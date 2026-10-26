import eventlet
eventlet.monkey_patch()

import os
import secrets
import json
import base64
import uuid
import math
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
    conn = pymysql.connect(
        host=DB_HOST, 
        user=DB_USER, 
        password=DB_PASS, 
        database=DB_NAME, 
        cursorclass=pymysql.cursors.DictCursor, 
        autocommit=True
    )
    try:
        with conn.cursor() as cursor: 
            cursor.execute("SET time_zone = '+03:00'")
    except: pass
    return conn

# دالة تسجيل النشاطات (Audit Logs)
def log_action(cursor, user_id, action, entity, entity_id, details=None):
    details_json = json.dumps(details, ensure_ascii=False) if details else None
    cursor.execute(
        'INSERT INTO audit_logs (user_id, action, entity, entity_id, details_json) VALUES (%s, %s, %s, %s, %s)', 
        (user_id, action, entity, entity_id, details_json)
    )
    # إرسال تحديث لحظي للوحة القيادة
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
    conn = get_db_connection()
    with conn.cursor() as cursor:
        # إضافة الأعمدة الجديدة إذا لم تكن موجودة مسبقاً (للخرائط ولوحة التوزيع)
        try: cursor.execute("ALTER TABLE tasks ADD COLUMN scheduled_start DATETIME")
        except: pass
        try: cursor.execute("ALTER TABLE tasks ADD COLUMN duration_hours FLOAT DEFAULT 2.0")
        except: pass
        
        # إنشاء مستخدم افتراضي إذا لم يكن موجوداً
        cursor.execute('SELECT * FROM users WHERE role = "admin"')
        if not cursor.fetchone():
            cursor.execute('INSERT INTO users (name, phone, email, emp_id, password_hash, role) VALUES (%s, %s, %s, %s, %s, %s)', 
                           ('مدير النظام', '07000000000', 'admin@domain.com', 'A001', generate_password_hash('admin123'), 'admin'))
        
        # إعدادات الـ Web Push
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
    except Exception as e: return jsonify({'error': 'Database Error'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
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
    return jsonify({'error': 'Unauthorized'}), 401

@app.route('/api/vapid-public-key', methods=['GET'])
def get_vapid_key(): return jsonify({'public_key': VAPID_PUBLIC_KEY})

@app.route('/api/subscribe', methods=['POST'])
def subscribe():
    data = request.get_json()
    endpoint = data.get('endpoint'); keys = data.get('keys', {})
    conn = get_db_connection()
    with conn.cursor() as cursor: 
        cursor.execute('''INSERT INTO push_subscriptions (user_id, endpoint, p256dh, auth) VALUES (%s, %s, %s, %s) ON DUPLICATE KEY UPDATE p256dh=%s, auth=%s''', 
                       (request.current_user['id'], endpoint, keys.get('p256dh'), keys.get('auth'), keys.get('p256dh'), keys.get('auth')))
    conn.close()
    return jsonify({'success': True})

@socketio.on('authenticate')
def handle_auth(data):
    token = data.get('token')
    if not token: return
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute('SELECT * FROM users WHERE token = %s', (token,))
        user = cursor.fetchone()
    conn.close()
    if user:
        join_room(f"user_{user['id']}")
        if user['role'] == 'admin': join_room('admins')
        elif user['role'] == 'manager': join_room(f"manager_{user['team_id']}")

def process_incoming_location(user, lat, lng, recorded_at_db=None, is_offline=0):
    user_id = user['id']
    if not recorded_at_db:
        baghdad_now = datetime.utcnow() + timedelta(hours=3)
        recorded_at_db = baghdad_now.strftime('%Y-%m-%d %H:%M:%S')
    
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
    conn.close()
    
    loc_data = { 'user_id': user_id, 'name': user['name'], 'profile_image': user.get('profile_image'), 'job_title': user['job_title'], 'zone_id': user['zone_id'], 'lat': lat, 'lng': lng, 'recorded_at': recorded_at_db }
    socketio.emit('new_location', loc_data, room='admins')
    if user['team_id']: socketio.emit('new_location', loc_data, room=f"manager_{user['team_id']}")

@socketio.on('send_location')
def handle_location(data):
    token = data.get('token')
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute('SELECT * FROM users WHERE token = %s', (token,))
        user = cursor.fetchone()
    conn.close()
    if user and user['role'] == 'employee': process_incoming_location(user, data.get('lat'), data.get('lng'))

@app.route('/api/location', methods=['POST'])
def api_fallback_location():
    data = request.get_json()
    token = request.headers.get('Authorization')
    if token: token = token.replace('Bearer ', '')
    else: token = data.get('token')
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute('SELECT * FROM users WHERE token = %s', (token,))
        user = cursor.fetchone()
    conn.close()
    if user and user['role'] == 'employee':
        process_incoming_location(user, data.get('lat'), data.get('lng'))
        return jsonify({'success': True})
    return jsonify({'error': 'Unauthorized'}), 401

# --- API الحضور والانصراف (Attendance) ---
@app.route('/api/attendance/checkin', methods=['POST'])
def checkin():
    data = request.get_json()
    baghdad_now = datetime.utcnow() + timedelta(hours=3)
    today = baghdad_now.strftime('%Y-%m-%d')
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute('SELECT id FROM attendance WHERE user_id = %s AND work_date = %s', (request.current_user['id'], today))
        if cursor.fetchone():
            conn.close(); return jsonify({'error': 'Conflict', 'message': 'تم تسجيل الحضور مسبقاً لهذا اليوم.'}), 409
        cursor.execute('INSERT INTO attendance (user_id, check_in_time, check_in_lat, check_in_lng, work_date) VALUES (%s, %s, %s, %s, %s)', (request.current_user['id'], baghdad_now, data.get('lat'), data.get('lng'), today))
        log_action(cursor, request.current_user['id'], 'check_in', 'attendance', None, "تسجيل حضور للميدان")
        msg_title = 'تسجيل حضور ⏰'; msg_body = f"الموظف {request.current_user['name']} بدأ يوم العمل."
        socketio.emit('admin_notification', {'title': msg_title, 'message': msg_body}, room='admins')
    conn.close(); return jsonify({'success': True})

@app.route('/api/attendance/checkout', methods=['POST'])
def checkout():
    data = request.get_json()
    baghdad_now = datetime.utcnow() + timedelta(hours=3)
    today = baghdad_now.strftime('%Y-%m-%d')
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute('UPDATE attendance SET check_out_time = %s, check_out_lat = %s, check_out_lng = %s WHERE user_id = %s AND work_date = %s', (baghdad_now, data.get('lat'), data.get('lng'), request.current_user['id'], today))
        log_action(cursor, request.current_user['id'], 'check_out', 'attendance', None, "تسجيل انصراف")
        msg_title = 'تسجيل انصراف 🛑'; msg_body = f"الموظف {request.current_user['name']} أنهى فترة عمله."
        socketio.emit('admin_notification', {'title': msg_title, 'message': msg_body}, room='admins')
    conn.close(); return jsonify({'success': True})

# --- API Dashboard Stats & KPIs ---
@app.route('/api/stats', methods=['GET'])
def get_stats():
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
            # Manager logic
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
    return jsonify({
        'success': True, 
        'stats': {
            'active_employees': emp_count, 
            'total_tasks_today': total_tasks_today, 
            'in_progress': in_progress, 
            'overdue': overdue, 
            'completed_today': completed_today,
            'productivity': productivity
        }
    })

@app.route('/api/activity', methods=['GET'])
def get_activity_timeline():
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute('''
            SELECT a.*, u.name as user_name 
            FROM audit_logs a 
            LEFT JOIN users u ON a.user_id = u.id 
            ORDER BY a.created_at DESC LIMIT 20
        ''')
        activities = cursor.fetchall()
    conn.close()
    return jsonify({'success': True, 'activities': activities})

# --- API Tasks ---
@app.route('/api/tasks', methods=['POST'])
def create_task():
    data = request.get_json()
    checklist_json = json.dumps([{"title": item, "is_completed": False, "note": ""} for item in data.get('checklist', [])], ensure_ascii=False) if data.get('checklist') else None
    client_id = data.get('client_id'); lat = data.get('lat'); lng = data.get('lng')
    work_order_id = data.get('work_order_id'); form_id = data.get('form_id')
    scheduled_start = data.get('scheduled_start')
    duration_hours = data.get('duration_hours', 2.0)
    
    conn = get_db_connection()
    with conn.cursor() as cursor:
        if client_id:
            cursor.execute('SELECT lat, lng FROM clients WHERE id = %s', (client_id,))
            client = cursor.fetchone()
            if client and not lat: lat = client['lat']; lng = client['lng']
            
        cursor.execute('''
            INSERT INTO tasks (title, assigned_to, created_by, lat, lng, scheduled_start, duration_hours, due_date, checklist, recurrence, client_id, work_order_id, form_id) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ''', (data['title'], data['assigned_to'], request.current_user['id'], lat, lng, scheduled_start, duration_hours, data['due_date'], checklist_json, data.get('recurrence', 'none'), client_id, work_order_id, form_id))
        task_id = cursor.lastrowid
        log_action(cursor, request.current_user['id'], 'create_task', 'tasks', task_id, f"إصدار مهمة جديدة: {data['title']}")
        
        msg_title = 'مهمة جديدة 📋'
        msg_body = f"تم إسناد مهمة جديدة إليك: {data['title']}"
        cursor.execute('INSERT INTO notifications (user_id, title, message) VALUES (%s, %s, %s)', (data['assigned_to'], msg_title, msg_body))
    conn.close()
    
    socketio.emit('employee_notification', {'title': msg_title, 'message': msg_body}, room=f"user_{data['assigned_to']}")
    socketio.emit('task_updated', {}, room='admins')
    return jsonify({'success': True})

@app.route('/api/tasks/all', methods=['GET'])
def get_all_tasks():
    conn = get_db_connection()
    with conn.cursor() as cursor:
        base_query = '''
            SELECT t.*, u.name as assignee_name, u.team_id, c.name as client_name, c.phone as client_phone 
            FROM tasks t 
            LEFT JOIN users u ON t.assigned_to = u.id 
            LEFT JOIN clients c ON t.client_id = c.id
        '''
        if request.current_user['role'] == 'admin': 
            cursor.execute(base_query + " ORDER BY t.due_date DESC")
        else: 
            cursor.execute(base_query + " WHERE u.team_id IN (SELECT id FROM teams WHERE manager_id = %s) ORDER BY t.due_date DESC", (request.current_user['id'],))
        tasks = cursor.fetchall()
    conn.close(); return jsonify({'success': True, 'tasks': tasks})

@app.route('/api/tasks/my', methods=['GET'])
def get_my_tasks():
    conn = get_db_connection()
    with conn.cursor() as cursor: 
        cursor.execute('''
            SELECT t.*, c.name as client_name, c.phone as client_phone, c.address as client_address 
            FROM tasks t LEFT JOIN clients c ON t.client_id = c.id 
            WHERE t.assigned_to = %s 
            ORDER BY t.due_date ASC
        ''', (request.current_user['id'],))
        tasks = cursor.fetchall()
    conn.close(); return jsonify({'success': True, 'tasks': tasks})

@app.route('/api/tasks/<int:task_id>/status', methods=['PUT'])
def update_task_status(task_id):
    data = request.get_json()
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute('SELECT * FROM tasks WHERE id = %s', (task_id,))
        task = cursor.fetchone()
        if not task: conn.close(); return jsonify({'error': 'Not found'}), 404
        
        existing_images = []
        if task['image_url']:
            try: existing_images = json.loads(task['image_url']) if isinstance(json.loads(task['image_url']), list) else [task['image_url']]
            except: existing_images = [task['image_url']]

        new_images = data.get('images', []) if isinstance(data.get('images'), list) else []
        all_images = existing_images + new_images
        final_image_json = json.dumps(all_images) if all_images else None

        existing_notes = task['notes'] if task['notes'] else ""
        new_note = data.get('notes', "")
        combined_notes = f"{existing_notes}\n[تحديث]: {new_note}".strip() if new_note and existing_notes else new_note or existing_notes

        new_status = data.get('status', task['status'])
        
        query = 'UPDATE tasks SET status = %s'
        params = [new_status]
        
        if new_status == 'completed' and task['status'] != 'completed':
            query += ', completed_at = NOW()'
            
        if combined_notes: query += ', notes = %s'; params.append(combined_notes)
        if final_image_json is not None: query += ', image_url = %s'; params.append(final_image_json)
        if data.get('checklist') is not None: query += ', checklist = %s'; params.append(data.get('checklist'))
        query += ' WHERE id = %s'; params.append(task_id)
        
        cursor.execute(query, params)
        
        log_action(cursor, request.current_user['id'], 'update_task_status', 'tasks', task_id, f"تحديث حالة المهمة إلى: {new_status}")
        
        action = "بدأ بتنفيذ" if new_status == 'in_progress' else "أكمل" if new_status == 'completed' else "أضاف تحديثاً على"
        cursor.execute('SELECT name FROM users WHERE id = %s', (task['assigned_to'],)); emp_name = cursor.fetchone()['name']
        msg_title = f'تحديث ميداني 📋'; msg_body = f"الموظف ({emp_name}) {action} مهمة: {task['title']}"
        cursor.execute('INSERT INTO notifications (user_id, title, message) VALUES (%s, %s, %s)', (task['created_by'], msg_title, msg_body))
        socketio.emit('admin_notification', {'title': msg_title, 'message': msg_body}, room=f"user_{task['created_by']}")
    conn.close()
    
    socketio.emit('task_updated', {}, room='admins')
    return jsonify({'success': True})

# --- Other Essential APIs ---
@app.route('/api/users/employees', methods=['GET'])
def get_employees():
    conn = get_db_connection()
    with conn.cursor() as cursor:
        if request.current_user['role'] == 'admin': 
            cursor.execute("SELECT u.id, u.name, u.phone, u.job_title, u.role, u.profile_image, u.team_id, u.zone_id, t.name as team_name FROM users u LEFT JOIN teams t ON u.team_id = t.id WHERE u.role IN ('employee', 'manager') AND u.status='active'")
        else: 
            cursor.execute("SELECT u.id, u.name, u.phone, u.job_title, u.role, u.profile_image, u.team_id, u.zone_id, t.name as team_name FROM users u LEFT JOIN teams t ON u.team_id = t.id WHERE u.team_id IN (SELECT id FROM teams WHERE manager_id = %s) AND u.status='active'", (request.current_user['id'],))
        employees = cursor.fetchall()
    conn.close(); return jsonify({'success': True, 'employees': employees})

@app.route('/api/location/latest', methods=['GET'])
def get_latest_locations():
    conn = get_db_connection()
    with conn.cursor() as cursor:
        base_query = '''
            SELECT l.user_id, l.lat, l.lng, l.recorded_at, u.name, u.job_title, u.zone_id, u.profile_image 
            FROM location_logs l 
            JOIN users u ON l.user_id = u.id 
            INNER JOIN (SELECT user_id, MAX(recorded_at) as max_date FROM location_logs GROUP BY user_id) grouped_l 
            ON l.user_id = grouped_l.user_id AND l.recorded_at = grouped_l.max_date
        '''
        if request.current_user['role'] == 'admin': cursor.execute(base_query)
        else: cursor.execute(base_query + ' WHERE u.team_id IN (SELECT id FROM teams WHERE manager_id = %s)', (request.current_user['id'],))
        locations = cursor.fetchall()
    conn.close(); return jsonify({'success': True, 'locations': locations})

@app.route('/api/forms', methods=['GET', 'POST'])
def handle_forms():
    conn = get_db_connection()
    with conn.cursor() as cursor:
        if request.method == 'POST':
            if request.current_user['role'] != 'admin': return jsonify({'error': 'Forbidden'}), 403
            data = request.get_json()
            cursor.execute('INSERT INTO forms (title, fields_json) VALUES (%s, %s)', (data.get('title'), json.dumps(data.get('fields'), ensure_ascii=False)))
            form_id = cursor.lastrowid
            log_action(cursor, request.current_user['id'], 'create_form', 'forms', form_id, f"إنشاء نموذج جديد: {data.get('title')}")
            conn.close(); return jsonify({'success': True, 'id': form_id})
        else:
            cursor.execute('SELECT * FROM forms ORDER BY created_at DESC')
            forms = cursor.fetchall()
            conn.close(); return jsonify({'success': True, 'forms': forms})

@app.route('/api/forms/submit', methods=['POST'])
def submit_form():
    data = request.get_json()
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute('INSERT INTO form_submissions (form_id, task_id, user_id, submission_data_json) VALUES (%s, %s, %s, %s)', (data.get('form_id'), data.get('task_id'), request.current_user['id'], json.dumps(data.get('submission_data'), ensure_ascii=False)))
        log_action(cursor, request.current_user['id'], 'submit_form', 'form_submissions', cursor.lastrowid, f"تقديم نموذج استبيان للمهمة #{data.get('task_id')}")
    conn.close(); return jsonify({'success': True})

@app.route('/api/sync/locations', methods=['POST'])
def sync_locations():
    data = request.get_json()
    token = request.headers.get('Authorization').replace('Bearer ', '')
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute('SELECT * FROM users WHERE token = %s', (token,))
        user = cursor.fetchone()
        if not user or user['role'] != 'employee': return jsonify({'error': 'Unauthorized'}), 401
        
        logs = data.get('logs', [])
        for log in logs: 
            cursor.execute('INSERT INTO location_logs (user_id, lat, lng, is_offline_sync, recorded_at) VALUES (%s, %s, %s, %s, %s)', (user['id'], log['lat'], log['lng'], 1, log['recorded_at']))
    conn.close()
    return jsonify({'success': True})

@app.route('/api/sync/tasks', methods=['POST'])
def sync_tasks():
    data = request.get_json()
    token = request.headers.get('Authorization').replace('Bearer ', '')
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute('SELECT * FROM users WHERE token = %s', (token,))
        user = cursor.fetchone()
        if not user or user['role'] != 'employee': return jsonify({'error': 'Unauthorized'}), 401
        
        updates = data.get('updates', [])
        for upd in updates:
            task_id = upd['taskId']
            cursor.execute('SELECT * FROM tasks WHERE id = %s AND assigned_to = %s', (task_id, user['id']))
            task = cursor.fetchone()
            if not task: continue
            
            existing_images = []
            if task['image_url']:
                try: existing_images = json.loads(task['image_url']) if isinstance(json.loads(task['image_url']), list) else [task['image_url']]
                except: existing_images = [task['image_url']]

            new_images = upd.get('images', []) if isinstance(upd.get('images'), list) else []
            all_images = existing_images + new_images
            final_image_json = json.dumps(all_images) if all_images else None

            existing_notes = task['notes'] if task['notes'] else ""
            new_note = upd.get('notes', "")
            combined_notes = f"{existing_notes}\n[مزامنة أوفلاين]: {new_note}".strip() if new_note and existing_notes else new_note or existing_notes

            new_status = upd.get('status', task['status'])
            query = 'UPDATE tasks SET status = %s'
            params = [new_status]
            if new_status == 'completed' and task['status'] != 'completed': query += ', completed_at = NOW()'
            if combined_notes: query += ', notes = %s'; params.append(combined_notes)
            if final_image_json is not None: query += ', image_url = %s'; params.append(final_image_json)
            if upd.get('checklist') is not None: query += ', checklist = %s'; params.append(upd.get('checklist'))
            query += ' WHERE id = %s'; params.append(task_id)
            
            cursor.execute(query, params)
            log_action(cursor, user['id'], 'sync_task', 'tasks', task_id, "مزامنة بيانات غير متصلة لمهمة")
            
            msg_title = f'مزامنة ميدانية 🔄'; msg_body = f"الموظف ({user['name']}) قام بمزامنة أعمال أوفلاين لمهمة: {task['title']}"
            cursor.execute('INSERT INTO notifications (user_id, title, message) VALUES (%s, %s, %s)', (task['created_by'], msg_title, msg_body))
            socketio.emit('admin_notification', {'title': msg_title, 'message': msg_body}, room=f"user_{task['created_by']}")
    conn.close()
    socketio.emit('task_updated', {}, room='admins')
    return jsonify({'success': True})

try:
    init_db()
except Exception as e: print(f"❌ DB Initialization Error: {e}")

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)