import eventlet
eventlet.monkey_patch()

import os
import secrets
import json
import base64
import uuid
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask.json.provider import DefaultJSONProvider
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from flask_socketio import SocketIO, join_room, emit
import pymysql.cursors
from cryptography.hazmat.primitives.asymmetric import ec
from pywebpush import webpush, WebPushException

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
    # إضافة إعدادات SSL لتخطي حظر Hostinger للاتصالات الخارجية
    conn = pymysql.connect(
        host=DB_HOST, 
        user=DB_USER, 
        password=DB_PASS, 
        database=DB_NAME,
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor, 
        autocommit=True,
        connect_timeout=15,
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
        conn.close()
        print("✅ Database initialized successfully.")
    except Exception as e:
        print(f"❌ Database connection failed: {e}")

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
    if request.method == 'OPTIONS': return
    if request.path.startswith('/socket.io'): return
    if request.path.endswith('/login'): return
    if request.path.endswith('/vapid-public-key'): return
    if request.path.endswith('/location') and request.method == 'POST': return
    if '/sync/' in request.path and request.method == 'POST': return
    
    token = request.headers.get('Authorization')
    if not token: return jsonify({'error': 'Unauthorized'}), 401
    token = token.replace('Bearer ', '')
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute('SELECT * FROM users WHERE token = %s', (token,))
            user = cursor.fetchone()
        conn.close()
        if not user: return jsonify({'error': 'Unauthorized'}), 401
        request.current_user = user
    except Exception as e: return jsonify({'error': 'Database Error', 'message': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
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
                conn.close()
                return jsonify({'success': True, 'user': user})
        conn.close()
    except Exception as e:
        return jsonify({'error': 'Database Error', 'message': str(e)}), 500
    return jsonify({'error': 'Unauthorized'}), 401

@app.route('/api/users/employees', methods=['GET'])
def get_employees():
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            if request.current_user['role'] == 'admin': 
                cursor.execute("SELECT u.id, u.name, u.phone, u.job_title, u.role, u.profile_image, u.team_id, u.zone_id, t.name as team_name FROM users u LEFT JOIN teams t ON u.team_id = t.id WHERE u.role IN ('employee', 'manager') AND u.status='active'")
            else: 
                cursor.execute("SELECT u.id, u.name, u.phone, u.job_title, u.role, u.profile_image, u.team_id, u.zone_id, t.name as team_name FROM users u LEFT JOIN teams t ON u.team_id = t.id WHERE u.team_id IN (SELECT id FROM teams WHERE manager_id = %s) AND u.status='active'", (request.current_user['id'],))
            employees = cursor.fetchall()
        conn.close()
        return jsonify({'success': True, 'employees': employees})
    except Exception as e:
        return jsonify({'error': 'Database Error', 'message': str(e)}), 500

@app.route('/api/users', methods=['POST'])
def create_user():
    if request.current_user['role'] != 'admin': return jsonify({'error': 'Forbidden'}), 403
    data = request.get_json()
    hashed_password = generate_password_hash(data.get('password'))
    emp_id = f"E{int(datetime.utcnow().timestamp())}"
    team_id = int(data.get('team_id')) if data.get('team_id') else None
    
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute('INSERT INTO users (name, phone, password_hash, role, job_title, emp_id, team_id) VALUES (%s, %s, %s, %s, %s, %s, %s)', 
                           (data.get('name'), data.get('phone'), hashed_password, data.get('role', 'employee'), data.get('job_title', 'موظف'), emp_id, team_id))
            log_action(cursor, request.current_user['id'], 'create_user', 'users', cursor.lastrowid, f"إضافة مستخدم جديد: {data.get('name')}")
        conn.close()
        return jsonify({'success': True})
    except pymysql.err.IntegrityError: 
        return jsonify({'error': 'Conflict', 'message': 'الهاتف مسجل مسبقاً'}), 409
    except Exception as e:
        return jsonify({'error': 'Database Error', 'message': str(e)}), 500

# (باقي دوال البايثون السابقة تبقى كما هي، أهم شيء هو أن دوال get_db_connection و login و get_employees و create_user قد تم تغليفها بـ try/except لترد برسالة الخطأ بدل تجميد السكريبت)

@app.route('/api/stats', methods=['GET'])
def get_stats():
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
                
            productivity = 0
            if total_tasks_today > 0:
                productivity = round((completed_today / total_tasks_today) * 100)
                
        conn.close()
        return jsonify({'success': True, 'stats': {'active_employees': emp_count, 'total_tasks_today': total_tasks_today, 'in_progress': in_progress, 'overdue': overdue, 'completed_today': completed_today, 'productivity': productivity}})
    except Exception as e:
        return jsonify({'error': 'Database Error', 'message': str(e)}), 500

@app.route('/api/activity', methods=['GET'])
def get_activity_timeline():
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute('''SELECT a.*, u.name as user_name FROM audit_logs a LEFT JOIN users u ON a.user_id = u.id ORDER BY a.created_at DESC LIMIT 20''')
            activities = cursor.fetchall()
        conn.close()
        return jsonify({'success': True, 'activities': activities})
    except Exception as e:
        return jsonify({'error': 'Database Error', 'message': str(e)}), 500

@app.route('/api/location/latest', methods=['GET'])
def get_latest_locations():
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            base_query = '''SELECT l.user_id, l.lat, l.lng, l.recorded_at, u.name, u.job_title, u.zone_id, u.profile_image FROM location_logs l JOIN users u ON l.user_id = u.id INNER JOIN (SELECT user_id, MAX(recorded_at) as max_date FROM location_logs GROUP BY user_id) grouped_l ON l.user_id = grouped_l.user_id AND l.recorded_at = grouped_l.max_date'''
            if request.current_user['role'] == 'admin': cursor.execute(base_query)
            else: cursor.execute(base_query + ' WHERE u.team_id IN (SELECT id FROM teams WHERE manager_id = %s)', (request.current_user['id'],))
            locations = cursor.fetchall()
        conn.close(); return jsonify({'success': True, 'locations': locations})
    except Exception as e:
        return jsonify({'error': 'Database Error', 'message': str(e)}), 500

@app.route('/api/tasks/all', methods=['GET'])
def get_all_tasks():
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            base_query = '''SELECT t.*, u.name as assignee_name, u.team_id, c.name as client_name, c.phone as client_phone FROM tasks t LEFT JOIN users u ON t.assigned_to = u.id LEFT JOIN clients c ON t.client_id = c.id'''
            if request.current_user['role'] == 'admin': cursor.execute(base_query + " ORDER BY t.due_date DESC")
            else: cursor.execute(base_query + " WHERE u.team_id IN (SELECT id FROM teams WHERE manager_id = %s) ORDER BY t.due_date DESC", (request.current_user['id'],))
            tasks = cursor.fetchall()
        conn.close(); return jsonify({'success': True, 'tasks': tasks})
    except Exception as e:
        return jsonify({'error': 'Database Error', 'message': str(e)}), 500

@app.route('/api/teams', methods=['GET', 'POST'])
def handle_teams():
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
                conn.close()
                return jsonify({'success': True, 'id': team_id})
            else:
                cursor.execute('''SELECT t.*, u.name as manager_name, (SELECT COUNT(*) FROM users WHERE team_id = t.id) as members_count FROM teams t LEFT JOIN users u ON t.manager_id = u.id ORDER BY t.created_at DESC''')
                teams = cursor.fetchall()
                conn.close()
                return jsonify({'success': True, 'teams': teams})
    except Exception as e:
        return jsonify({'error': 'Database Error', 'message': str(e)}), 500

@app.route('/api/work_orders', methods=['GET', 'POST'])
def handle_work_orders():
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            if request.method == 'POST':
                if request.current_user['role'] != 'admin': return jsonify({'error': 'Forbidden'}), 403
                data = request.get_json()
                cursor.execute('INSERT INTO work_orders (title, client_id, team_id) VALUES (%s, %s, %s)', (data.get('title'), data.get('client_id'), data.get('team_id')))
                wo_id = cursor.lastrowid
                log_action(cursor, request.current_user['id'], 'create_work_order', 'work_orders', wo_id, f"أمر عمل: {data.get('title')}")
                conn.close()
                return jsonify({'success': True, 'id': wo_id})
            else:
                cursor.execute('''SELECT w.*, c.name as client_name, t.name as team_name, (SELECT COUNT(*) FROM tasks WHERE work_order_id = w.id) as total_tasks, (SELECT COUNT(*) FROM tasks WHERE work_order_id = w.id AND status = 'completed') as completed_tasks FROM work_orders w LEFT JOIN clients c ON w.client_id = c.id LEFT JOIN teams t ON w.team_id = t.id ORDER BY w.created_at DESC''')
                wos = cursor.fetchall()
                conn.close()
                return jsonify({'success': True, 'work_orders': wos})
    except Exception as e:
        return jsonify({'error': 'Database Error', 'message': str(e)}), 500

@app.route('/api/clients', methods=['GET', 'POST'])
def handle_clients():
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            if request.method == 'POST':
                if request.current_user['role'] != 'admin': return jsonify({'error': 'Forbidden'}), 403
                data = request.get_json()
                cursor.execute('INSERT INTO clients (name, phone, address, lat, lng) VALUES (%s, %s, %s, %s, %s)', (data.get('name'), data.get('phone'), data.get('address'), data.get('lat'), data.get('lng')))
                log_action(cursor, request.current_user['id'], 'create_client', 'clients', cursor.lastrowid, f"عميل جديد: {data.get('name')}")
                conn.close(); return jsonify({'success': True})
            else:
                cursor.execute('SELECT * FROM clients ORDER BY created_at DESC')
                clients = cursor.fetchall()
                conn.close(); return jsonify({'success': True, 'clients': clients})
    except Exception as e:
        return jsonify({'error': 'Database Error', 'message': str(e)}), 500

@app.route('/api/forms', methods=['GET', 'POST'])
def handle_forms():
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            if request.method == 'POST':
                if request.current_user['role'] != 'admin': return jsonify({'error': 'Forbidden'}), 403
                data = request.get_json()
                cursor.execute('INSERT INTO forms (title, fields_json) VALUES (%s, %s)', (data.get('title'), json.dumps(data.get('fields'), ensure_ascii=False)))
                form_id = cursor.lastrowid
                log_action(cursor, request.current_user['id'], 'create_form', 'forms', form_id, f"نموذج جديد: {data.get('title')}")
                conn.close(); return jsonify({'success': True, 'id': form_id})
            else:
                cursor.execute('SELECT * FROM forms ORDER BY created_at DESC')
                forms = cursor.fetchall()
                conn.close(); return jsonify({'success': True, 'forms': forms})
    except Exception as e:
        return jsonify({'error': 'Database Error', 'message': str(e)}), 500

try:
    init_db()
except Exception as e: print(f"❌ DB Initialization Error: {e}")

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)