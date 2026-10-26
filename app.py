import eventlet
eventlet.monkey_patch()

import os
import secrets
import json
import base64
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask.json.provider import DefaultJSONProvider
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from flask_socketio import SocketIO, join_room, emit
import pymysql.cursors
from cryptography.hazmat.primitives.asymmetric import ec
from pywebpush import webpush

class CustomJSONProvider(DefaultJSONProvider):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%d %H:%M:%S')
        return super().default(obj)

app = Flask(__name__)
app.json = CustomJSONProvider(app)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# إعدادات قاعدة البيانات (Hostinger)
DB_HOST = '193.203.168.175'
DB_NAME = 'u301100000_tracker'
DB_USER = 'u301100000_admin1'
DB_PASS = 'kaisi@0Ahmed'

VAPID_PRIVATE_KEY = None
VAPID_PUBLIC_KEY = None

def get_db_connection():
    conn = pymysql.connect(
        host=DB_HOST, 
        user=DB_USER, 
        password=DB_PASS, 
        database=DB_NAME,
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor, 
        autocommit=True,
        connect_timeout=10,
        ssl={"fake_flag_to_enable_tls": True},
        client_flag=pymysql.constants.CLIENT.SSL
    )
    try:
        with conn.cursor() as cursor: 
            cursor.execute("SET time_zone = '+03:00'")
    except: pass
    return conn

def log_action(cursor, user_id, action, entity, entity_id, details=None):
    details_json = json.dumps(details, ensure_ascii=False) if details else None
    cursor.execute(
        'INSERT INTO audit_logs (user_id, action, entity, entity_id, details_json) VALUES (%s, %s, %s, %s, %s)', 
        (user_id, action, entity, entity_id, details_json)
    )
    try:
        cursor.execute("SELECT name FROM users WHERE id = %s", (user_id,))
        user_name = cursor.fetchone()['name']
        action_text = f"قام {user_name} بـ {action}"
        if details:
            action_text += f" ({details})"
        socketio.emit('new_activity', {'title': 'نشاط جديد', 'description': action_text}, room='admins')
    except: pass

def init_db():
    global VAPID_PRIVATE_KEY, VAPID_PUBLIC_KEY
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            try: cursor.execute("ALTER TABLE tasks ADD COLUMN scheduled_start DATETIME")
            except: pass
            try: cursor.execute("ALTER TABLE tasks ADD COLUMN duration_hours FLOAT DEFAULT 2.0")
            except: pass
            
            cursor.execute('SELECT * FROM users WHERE role = "admin"')
            if not cursor.fetchone():
                cursor.execute('INSERT INTO users (name, phone, email, emp_id, password_hash, role) VALUES (%s, %s, %s, %s, %s, %s)', 
                               ('مدير النظام', '07000000000', 'admin@domain.com', 'A001', generate_password_hash('admin123'), 'admin'))
            
            cursor.execute('SELECT value FROM settings WHERE key_name="vapid_private"')
            vapid = cursor.fetchone()
            if vapid:
                VAPID_PRIVATE_KEY = vapid['value']
                cursor.execute('SELECT value FROM settings WHERE key_name="vapid_public"')
                VAPID_PUBLIC_KEY = cursor.fetchone()['value']
            else:
                private_key = ec.generate_private_key(ec.SECP256R1())
                priv_bytes = private_key.private_numbers().private_value.to_bytes(32, 'big')
                VAPID_PRIVATE_KEY = base64.urlsafe_b64encode(priv_bytes).decode('utf-8').rstrip('=')
                pub_numbers = private_key.public_key().public_numbers()
                pub_bytes = b'\x04' + pub_numbers.x.to_bytes(32, 'big') + pub_numbers.y.to_bytes(32, 'big')
                VAPID_PUBLIC_KEY = base64.urlsafe_b64encode(pub_bytes).decode('utf-8').rstrip('=')
                cursor.execute('INSERT INTO settings (key_name, value) VALUES (%s, %s)', ('vapid_private', VAPID_PRIVATE_KEY))
                cursor.execute('INSERT INTO settings (key_name, value) VALUES (%s, %s)', ('vapid_public', VAPID_PUBLIC_KEY))
        print("✅ Database initialized successfully.")
    except Exception as e:
        print(f"❌ Database INIT failed: {e}")
    finally:
        if conn: conn.close()

def is_inside_polygon(lat, lng, poly_coords):
    try:
        if len(poly_coords) == 1 and isinstance(poly_coords[0][0], list): poly_coords = poly_coords[0]
        n = len(poly_coords)
        inside = False
        p1lat, p1lng = float(poly_coords[0][0]), float(poly_coords[0][1])
        for i in range(n + 1):
            p2lat, p2lng = float(poly_coords[i % n][0]), float(poly_coords[i % n][1])
            if lng > min(p1lng, p2lng):
                if lng <= max(p1lng, p2lng):
                    if lat <= max(p1lat, p2lat):
                        if p1lng != p2lng: xints = (lng - p1lng) * (p2lat - p1lat) / (p2lng - p1lng) + p1lat
                        if p1lat == p2lat or lat <= xints: inside = not inside
            p1lat, p1lng = p2lat, p2lng
        return inside
    except: return True

@app.before_request
def require_auth():
    if request.method == 'OPTIONS' or request.path.startswith('/socket.io') or request.path.endswith('/login') or request.path.endswith('/vapid-public-key') or (request.path.endswith('/location') and request.method == 'POST') or ('/sync/' in request.path and request.method == 'POST'):
        return
    token = request.headers.get('Authorization')
    if not token: return jsonify({'error': 'Unauthorized'}), 401
    token = token.replace('Bearer ', '')
    
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute('SELECT * FROM users WHERE token = %s', (token,))
            user = cursor.fetchone()
            if not user: return jsonify({'error': 'Unauthorized'}), 401
            request.current_user = user
    except Exception as e: 
        return jsonify({'error': 'Database Error', 'message': str(e)}), 500
    finally:
        if conn: conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute('SELECT * FROM users WHERE phone = %s', (data.get('phone'),))
            user = cursor.fetchone()
            if user and check_password_hash(user['password_hash'], data.get('password')):
                token = secrets.token_hex(32)
                cursor.execute('UPDATE users SET token = %s WHERE id = %s', (token, user['id']))
                log_action(cursor, user['id'], 'login', 'users', user['id'], "تسجيل دخول للنظام")
                user['token'] = token
                user.pop('password_hash')
                return jsonify({'success': True, 'user': user})
        return jsonify({'error': 'Unauthorized'}), 401
    except Exception as e:
        return jsonify({'error': 'Database Error', 'message': str(e)}), 500
    finally:
        if conn: conn.close()

@app.route('/api/vapid-public-key', methods=['GET'])
def get_vapid_key(): 
    return jsonify({'public_key': VAPID_PUBLIC_KEY})

@app.route('/api/subscribe', methods=['POST'])
def subscribe():
    data = request.get_json()
    endpoint = data.get('endpoint'); keys = data.get('keys', {})
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor: 
            cursor.execute('''INSERT INTO push_subscriptions (user_id, endpoint, p256dh, auth) VALUES (%s, %s, %s, %s) ON DUPLICATE KEY UPDATE p256dh=%s, auth=%s''', 
                           (request.current_user['id'], endpoint, keys.get('p256dh'), keys.get('auth'), keys.get('p256dh'), keys.get('auth')))
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': 'Database Error', 'message': str(e)}), 500
    finally:
        if conn: conn.close()

@socketio.on('authenticate')
def handle_auth(data):
    token = data.get('token')
    if not token: return
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute('SELECT * FROM users WHERE token = %s', (token,))
            user = cursor.fetchone()
            if user:
                join_room(f"user_{user['id']}")
                if user['role'] == 'admin': join_room('admins')
                elif user['role'] == 'manager': join_room(f"manager_{user['team_id']}")
    except: pass
    finally:
        if conn: conn.close()

def process_incoming_location(user, lat, lng, recorded_at_db=None, is_offline=0):
    user_id = user['id']
    if not recorded_at_db:
        baghdad_now = datetime.utcnow() + timedelta(hours=3)
        recorded_at_db = baghdad_now.strftime('%Y-%m-%d %H:%M:%S')
    
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute('INSERT INTO location_logs (user_id, lat, lng, is_offline_sync, recorded_at) VALUES (%s, %s, %s, %s, %s)', (user_id, lat, lng, is_offline, recorded_at_db))
            if user['zone_id']:
                cursor.execute('SELECT name, coordinates_json FROM zones WHERE id = %s', (user['zone_id'],))
                zone = cursor.fetchone()
                if zone and zone['coordinates_json']:
                    coords = json.loads(zone['coordinates_json'])
                    if not is_inside_polygon(lat, lng, coords):
                        alert_msg = f"تنبيه: الموظف {user['name']} يتواجد خارج المنطقة الجغرافية المخصصة له ({zone['name']})."
                        socketio.emit('admin_notification', {'title': 'تجاوز النطاق الجغرافي', 'message': alert_msg}, room='admins')
    except: pass
    finally:
        if conn: conn.close()
    
    loc_data = { 'user_id': user_id, 'name': user['name'], 'profile_image': user.get('profile_image'), 'job_title': user['job_title'], 'zone_id': user['zone_id'], 'lat': lat, 'lng': lng, 'recorded_at': recorded_at_db }
    socketio.emit('new_location', loc_data, room='admins')
    if user['team_id']: socketio.emit('new_location', loc_data, room=f"manager_{user['team_id']}")

@socketio.on('send_location')
def handle_location(data):
    token = data.get('token')
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute('SELECT * FROM users WHERE token = %s', (token,))
            user = cursor.fetchone()
            if user and user['role'] == 'employee': 
                process_incoming_location(user, data.get('lat'), data.get('lng'))
    except: pass
    finally:
        if conn: conn.close()

@app.route('/api/location', methods=['POST'])
def api_fallback_location():
    data = request.get_json()
    token = request.headers.get('Authorization')
    if token: token = token.replace('Bearer ', '')
    else: token = data.get('token')
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute('SELECT * FROM users WHERE token = %s', (token,))
            user = cursor.fetchone()
            if user and user['role'] == 'employee':
                process_incoming_location(user, data.get('lat'), data.get('lng'))
                return jsonify({'success': True})
    except: pass
    finally:
        if conn: conn.close()
    return jsonify({'error': 'Unauthorized'}), 401

@app.route('/api/stats', methods=['GET'])
def get_stats():
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            if request.current_user['role'] == 'admin':
                cursor.execute("SELECT COUNT(*) as c FROM users WHERE role IN ('employee', 'manager') AND status = 'active'")
                emp_count = cursor.fetchone()['c']
                cursor.execute("SELECT COUNT(*) as c FROM tasks WHERE DATE(due_date) = CURDATE()")
                total_tasks_today = cursor.fetchone()['c']
                cursor.execute("SELECT COUNT(*) as c FROM tasks WHERE status = 'in_progress'")
                in_progress = cursor.fetchone()['c']
                cursor.execute("SELECT COUNT(*) as c FROM tasks WHERE status = 'completed' AND DATE(completed_at) = CURDATE()")
                completed_today = cursor.fetchone()['c']
                cursor.execute("SELECT COUNT(*) as c FROM tasks WHERE status NOT IN ('completed', 'cancelled') AND due_date < NOW()")
                overdue = cursor.fetchone()['c']
            else:
                cursor.execute("SELECT COUNT(*) as c FROM users WHERE team_id IN (SELECT id FROM teams WHERE manager_id = %s) AND status = 'active'", (request.current_user['id'],))
                emp_count = cursor.fetchone()['c']
                cursor.execute("SELECT COUNT(t.id) as c FROM tasks t JOIN users u ON t.assigned_to = u.id WHERE u.team_id IN (SELECT id FROM teams WHERE manager_id = %s) AND DATE(t.due_date) = CURDATE()", (request.current_user['id'],))
                total_tasks_today = cursor.fetchone()['c']
                cursor.execute("SELECT COUNT(t.id) as c FROM tasks t JOIN users u ON t.assigned_to = u.id WHERE t.status = 'in_progress' AND u.team_id IN (SELECT id FROM teams WHERE manager_id = %s)", (request.current_user['id'],))
                in_progress = cursor.fetchone()['c']
                cursor.execute("SELECT COUNT(t.id) as c FROM tasks t JOIN users u ON t.assigned_to = u.id WHERE t.status = 'completed' AND DATE(t.completed_at) = CURDATE() AND u.team_id IN (SELECT id FROM teams WHERE manager_id = %s)", (request.current_user['id'],))
                completed_today = cursor.fetchone()['c']
                cursor.execute("SELECT COUNT(t.id) as c FROM tasks t JOIN users u ON t.assigned_to = u.id WHERE t.status NOT IN ('completed', 'cancelled') AND t.due_date < NOW() AND u.team_id IN (SELECT id FROM teams WHERE manager_id = %s)", (request.current_user['id'],))
                overdue = cursor.fetchone()['c']
                
            productivity = round((completed_today / total_tasks_today) * 100) if total_tasks_today > 0 else 0
        return jsonify({'success': True, 'stats': {'active_employees': emp_count, 'total_tasks_today': total_tasks_today, 'in_progress': in_progress, 'overdue': overdue, 'completed_today': completed_today, 'productivity': productivity}})
    except Exception as e:
        return jsonify({'error': 'Database Error', 'message': str(e)}), 500
    finally:
        if conn: conn.close()

@app.route('/api/activity', methods=['GET'])
def get_activity_timeline():
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute('''SELECT a.*, u.name as user_name FROM audit_logs a LEFT JOIN users u ON a.user_id = u.id ORDER BY a.created_at DESC LIMIT 20''')
            activities = cursor.fetchall()
        return jsonify({'success': True, 'activities': activities})
    except Exception as e:
        return jsonify({'error': 'Database Error', 'message': str(e)}), 500
    finally:
        if conn: conn.close()

@app.route('/api/location/latest', methods=['GET'])
def get_latest_locations():
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            base_query = '''SELECT l.user_id, l.lat, l.lng, l.recorded_at, u.name, u.job_title, u.zone_id, u.profile_image FROM location_logs l JOIN users u ON l.user_id = u.id INNER JOIN (SELECT user_id, MAX(recorded_at) as max_date FROM location_logs GROUP BY user_id) grouped_l ON l.user_id = grouped_l.user_id AND l.recorded_at = grouped_l.max_date'''
            if request.current_user['role'] == 'admin': cursor.execute(base_query)
            else: cursor.execute(base_query + ' WHERE u.team_id IN (SELECT id FROM teams WHERE manager_id = %s)', (request.current_user['id'],))
            locations = cursor.fetchall()
        return jsonify({'success': True, 'locations': locations})
    except Exception as e:
        return jsonify({'error': 'Database Error', 'message': str(e)}), 500
    finally:
        if conn: conn.close()

@app.route('/api/tasks/all', methods=['GET'])
def get_all_tasks():
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            base_query = '''SELECT t.*, u.name as assignee_name, u.team_id, c.name as client_name, c.phone as client_phone FROM tasks t LEFT JOIN users u ON t.assigned_to = u.id LEFT JOIN clients c ON t.client_id = c.id'''
            if request.current_user['role'] == 'admin': cursor.execute(base_query + " ORDER BY t.due_date DESC")
            else: cursor.execute(base_query + " WHERE u.team_id IN (SELECT id FROM teams WHERE manager_id = %s) ORDER BY t.due_date DESC", (request.current_user['id'],))
            tasks = cursor.fetchall()
        return jsonify({'success': True, 'tasks': tasks})
    except Exception as e:
        return jsonify({'error': 'Database Error', 'message': str(e)}), 500
    finally:
        if conn: conn.close()

@app.route('/api/users/employees', methods=['GET'])
def get_employees():
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            if request.current_user['role'] == 'admin': 
                cursor.execute("SELECT u.id, u.name, u.phone, u.job_title, u.role, u.profile_image, u.team_id, u.zone_id, t.name as team_name FROM users u LEFT JOIN teams t ON u.team_id = t.id WHERE u.role IN ('employee', 'manager') AND u.status='active'")
            else: 
                cursor.execute("SELECT u.id, u.name, u.phone, u.job_title, u.role, u.profile_image, u.team_id, u.zone_id, t.name as team_name FROM users u LEFT JOIN teams t ON u.team_id = t.id WHERE u.team_id IN (SELECT id FROM teams WHERE manager_id = %s) AND u.status='active'", (request.current_user['id'],))
            employees = cursor.fetchall()
        return jsonify({'success': True, 'employees': employees})
    except Exception as e:
        return jsonify({'error': 'Database Error', 'message': str(e)}), 500
    finally:
        if conn: conn.close()

@app.route('/api/users', methods=['POST'])
def create_user():
    if request.current_user['role'] != 'admin': return jsonify({'error': 'Forbidden'}), 403
    data = request.get_json()
    hashed_password = generate_password_hash(data.get('password'))
    emp_id = f"E{int(datetime.utcnow().timestamp())}"
    team_id = int(data.get('team_id')) if data.get('team_id') else None
    
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute('INSERT INTO users (name, phone, password_hash, role, job_title, emp_id, team_id) VALUES (%s, %s, %s, %s, %s, %s, %s)', 
                           (data.get('name'), data.get('phone'), hashed_password, data.get('role', 'employee'), data.get('job_title', 'موظف'), emp_id, team_id))
            log_action(cursor, request.current_user['id'], 'create_user', 'users', cursor.lastrowid, f"إضافة مستخدم جديد: {data.get('name')}")
        return jsonify({'success': True})
    except pymysql.err.IntegrityError: 
        return jsonify({'error': 'Conflict', 'message': 'رقم الهاتف مسجل مسبقاً، يرجى اختيار رقم آخر'}), 409
    except Exception as e:
        return jsonify({'error': 'Database Error', 'message': str(e)}), 500
    finally:
        if conn: conn.close()

@app.route('/api/teams', methods=['GET', 'POST'])
def handle_teams():
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            if request.method == 'POST':
                if request.current_user['role'] != 'admin': return jsonify({'error': 'Forbidden'}), 403
                data = request.get_json()
                manager_id = data.get('manager_id') if data.get('manager_id') else None
                cursor.execute('INSERT INTO teams (name, manager_id) VALUES (%s, %s)', (data.get('name'), manager_id))
                team_id = cursor.lastrowid
                log_action(cursor, request.current_user['id'], 'create_team', 'teams', team_id, f"إنشاء فريق: {data.get('name')}")
                return jsonify({'success': True, 'id': team_id})
            else:
                cursor.execute('''SELECT t.*, u.name as manager_name, (SELECT COUNT(*) FROM users WHERE team_id = t.id) as members_count FROM teams t LEFT JOIN users u ON t.manager_id = u.id ORDER BY t.created_at DESC''')
                teams = cursor.fetchall()
                return jsonify({'success': True, 'teams': teams})
    except Exception as e:
        return jsonify({'error': 'Database Error', 'message': str(e)}), 500
    finally:
        if conn: conn.close()

@app.route('/api/work_orders', methods=['GET', 'POST'])
def handle_work_orders():
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            if request.method == 'POST':
                if request.current_user['role'] != 'admin': return jsonify({'error': 'Forbidden'}), 403
                data = request.get_json()
                cursor.execute('INSERT INTO work_orders (title, client_id, team_id) VALUES (%s, %s, %s)', (data.get('title'), data.get('client_id'), data.get('team_id')))
                wo_id = cursor.lastrowid
                log_action(cursor, request.current_user['id'], 'create_work_order', 'work_orders', wo_id, f"أمر عمل: {data.get('title')}")
                return jsonify({'success': True, 'id': wo_id})
            else:
                cursor.execute('''SELECT w.*, c.name as client_name, t.name as team_name, (SELECT COUNT(*) FROM tasks WHERE work_order_id = w.id) as total_tasks, (SELECT COUNT(*) FROM tasks WHERE work_order_id = w.id AND status = 'completed') as completed_tasks FROM work_orders w LEFT JOIN clients c ON w.client_id = c.id LEFT JOIN teams t ON w.team_id = t.id ORDER BY w.created_at DESC''')
                wos = cursor.fetchall()
                return jsonify({'success': True, 'work_orders': wos})
    except Exception as e:
        return jsonify({'error': 'Database Error', 'message': str(e)}), 500
    finally:
        if conn: conn.close()

@app.route('/api/tasks', methods=['POST'])
def create_task():
    data = request.get_json()
    checklist_json = json.dumps([{"title": item, "is_completed": False, "note": ""} for item in data.get('checklist', [])], ensure_ascii=False) if data.get('checklist') else None
    client_id = data.get('client_id'); lat = data.get('lat'); lng = data.get('lng')
    work_order_id = data.get('work_order_id'); form_id = data.get('form_id')
    scheduled_start = data.get('scheduled_start'); duration_hours = data.get('duration_hours', 2.0)
    
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            if client_id:
                cursor.execute('SELECT lat, lng FROM clients WHERE id = %s', (client_id,))
                client = cursor.fetchone()
                if client and not lat: lat = client['lat']; lng = client['lng']
                
            cursor.execute('''INSERT INTO tasks (title, assigned_to, created_by, lat, lng, scheduled_start, duration_hours, due_date, checklist, recurrence, client_id, work_order_id, form_id) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)''', (data['title'], data['assigned_to'], request.current_user['id'], lat, lng, scheduled_start, duration_hours, data['due_date'], checklist_json, data.get('recurrence', 'none'), client_id, work_order_id, form_id))
            task_id = cursor.lastrowid
            log_action(cursor, request.current_user['id'], 'create_task', 'tasks', task_id, f"إصدار مهمة: {data['title']}")
            msg_title = 'مهمة جديدة 📋'; msg_body = f"تم إسناد مهمة جديدة: {data['title']}"
            cursor.execute('INSERT INTO notifications (user_id, title, message) VALUES (%s, %s, %s)', (data['assigned_to'], msg_title, msg_body))
        
        socketio.emit('employee_notification', {'title': msg_title, 'message': msg_body}, room=f"user_{data['assigned_to']}")
        socketio.emit('task_updated', {}, room='admins')
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': 'Database Error', 'message': str(e)}), 500
    finally:
        if conn: conn.close()

@app.route('/api/clients', methods=['GET', 'POST'])
def handle_clients():
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            if request.method == 'POST':
                if request.current_user['role'] != 'admin': return jsonify({'error': 'Forbidden'}), 403
                data = request.get_json()
                cursor.execute('INSERT INTO clients (name, phone, address, lat, lng) VALUES (%s, %s, %s, %s, %s)', (data.get('name'), data.get('phone'), data.get('address'), data.get('lat'), data.get('lng')))
                log_action(cursor, request.current_user['id'], 'create_client', 'clients', cursor.lastrowid, f"عميل جديد: {data.get('name')}")
                return jsonify({'success': True})
            else:
                cursor.execute('SELECT * FROM clients ORDER BY created_at DESC')
                clients = cursor.fetchall()
                return jsonify({'success': True, 'clients': clients})
    except Exception as e:
        return jsonify({'error': 'Database Error', 'message': str(e)}), 500
    finally:
        if conn: conn.close()

@app.route('/api/forms', methods=['GET', 'POST'])
def handle_forms():
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            if request.method == 'POST':
                if request.current_user['role'] != 'admin': return jsonify({'error': 'Forbidden'}), 403
                data = request.get_json()
                cursor.execute('INSERT INTO forms (title, fields_json) VALUES (%s, %s)', (data.get('title'), json.dumps(data.get('fields'), ensure_ascii=False)))
                form_id = cursor.lastrowid
                log_action(cursor, request.current_user['id'], 'create_form', 'forms', form_id, f"نموذج جديد: {data.get('title')}")
                return jsonify({'success': True, 'id': form_id})
            else:
                cursor.execute('SELECT * FROM forms ORDER BY created_at DESC')
                forms = cursor.fetchall()
                return jsonify({'success': True, 'forms': forms})
    except Exception as e:
        return jsonify({'error': 'Database Error', 'message': str(e)}), 500
    finally:
        if conn: conn.close()

@app.route('/api/location/history/<int:user_id>', methods=['GET'])
def get_location_history(user_id):
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            baghdad_now = datetime.utcnow() + timedelta(hours=3)
            target_date = request.args.get('date', baghdad_now.strftime('%Y-%m-%d'))
            cursor.execute('SELECT lat, lng, recorded_at FROM location_logs WHERE user_id = %s AND DATE(recorded_at) = %s ORDER BY recorded_at ASC', (user_id, target_date))
            history = cursor.fetchall()
        return jsonify({'success': True, 'history': history})
    except Exception as e:
        return jsonify({'error': 'Database Error', 'message': str(e)}), 500
    finally:
        if conn: conn.close()

@app.route('/api/zones', methods=['GET', 'POST'])
def handle_zones():
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            if request.method == 'POST':
                data = request.get_json()
                cursor.execute('INSERT INTO zones (name, coordinates_json, color) VALUES (%s, %s, %s)', (data.get('name'), data.get('coordinates_json'), data.get('color', '#3b82f6')))
                log_action(cursor, request.current_user['id'], 'create_zone', 'zones', cursor.lastrowid)
                return jsonify({'success': True})
            else: 
                cursor.execute('SELECT * FROM zones')
                zones = cursor.fetchall()
                return jsonify({'success': True, 'zones': zones})
    except Exception as e:
        return jsonify({'error': 'Database Error', 'message': str(e)}), 500
    finally:
        if conn: conn.close()

try:
    init_db()
except Exception as e: print(f"❌ DB Initialization Error: {e}")

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)