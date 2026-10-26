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
            return obj.strftime('%Y-%m-%d %I:%M %p')
        return super().default(obj)

app = Flask(__name__)
app.json = CustomJSONProvider(app)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

DB_HOST = '193.203.168.175'
DB_NAME = 'u301100000_tracker'
DB_USER = 'u301100000_admin1'
DB_PASS = 'kaisi@0Ahmed'

employee_tracking = {}
VAPID_PRIVATE_KEY = None
VAPID_PUBLIC_KEY = None

def get_db_connection():
    conn = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME, cursorclass=pymysql.cursors.DictCursor, autocommit=True)
    try:
        with conn.cursor() as cursor: cursor.execute("SET time_zone = '+03:00'")
    except: pass
    return conn

# دالة مساعدة لتسجيل حركات النظام (Audit Logs)
def log_action(cursor, user_id, action, entity, entity_id, details=None):
    details_json = json.dumps(details, ensure_ascii=False) if details else None
    cursor.execute('INSERT INTO audit_logs (user_id, action, entity, entity_id, details_json) VALUES (%s, %s, %s, %s, %s)', 
                   (user_id, action, entity, entity_id, details_json))

def init_db():
    global VAPID_PRIVATE_KEY, VAPID_PUBLIC_KEY
    conn = get_db_connection()
    with conn.cursor() as cursor:
        # الجداول الأساسية السابقة
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(255), phone VARCHAR(50) UNIQUE, email VARCHAR(255), emp_id VARCHAR(50), password_hash VARCHAR(255), role VARCHAR(50), job_title VARCHAR(100), zone_id INT, team_id INT, token VARCHAR(255))''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS tasks (id INT AUTO_INCREMENT PRIMARY KEY, title VARCHAR(255), assigned_to INT, created_by INT, lat FLOAT, lng FLOAT, due_date DATETIME, status VARCHAR(50) DEFAULT 'new', notes TEXT, image_url LONGTEXT, checklist TEXT, recurrence VARCHAR(50) DEFAULT 'none', client_id INT, work_order_id INT, form_id INT)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS notifications (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT NOT NULL, title VARCHAR(255) NOT NULL, message TEXT, is_read TINYINT(1) DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS teams (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(255), manager_id INT)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS zones (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(255), coordinates_json TEXT, color VARCHAR(50))''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS location_logs (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT, lat FLOAT, lng FLOAT, is_offline_sync TINYINT(1) DEFAULT 0, recorded_at DATETIME)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS settings (key_name VARCHAR(100) PRIMARY KEY, value TEXT)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS push_subscriptions (user_id INT, endpoint TEXT, p256dh TEXT, auth TEXT, UNIQUE(user_id, endpoint(255)))''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS clients (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(255), phone VARCHAR(50), address TEXT, lat FLOAT, lng FLOAT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS expenses (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT, amount DECIMAL(15,2) NOT NULL, currency VARCHAR(10) NOT NULL, category VARCHAR(100), description TEXT, receipt_url LONGTEXT, status VARCHAR(50) DEFAULT 'pending', created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        
        # جداول المرحلة المؤسسية الجديدة (Enterprise FSM)
        cursor.execute('''CREATE TABLE IF NOT EXISTS work_orders (id INT AUTO_INCREMENT PRIMARY KEY, title VARCHAR(255), client_id INT, team_id INT, status VARCHAR(50) DEFAULT 'open', created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS forms (id INT AUTO_INCREMENT PRIMARY KEY, title VARCHAR(255), fields_json LONGTEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS form_submissions (id INT AUTO_INCREMENT PRIMARY KEY, form_id INT, task_id INT, user_id INT, submission_data_json LONGTEXT, submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS audit_logs (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT, action VARCHAR(255), entity VARCHAR(100), entity_id INT, details_json TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS attendance (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT, check_in_time DATETIME, check_out_time DATETIME, check_in_lat FLOAT, check_in_lng FLOAT, check_out_lat FLOAT, check_out_lng FLOAT, work_date DATE)''')
        
        # تحديث الجداول القديمة
        try: cursor.execute("ALTER TABLE users ADD COLUMN profile_image TEXT")
        except: pass
        try: cursor.execute("ALTER TABLE tasks ADD COLUMN is_alerted TINYINT(1) DEFAULT 0")
        except: pass
        try: cursor.execute("ALTER TABLE tasks ADD COLUMN work_order_id INT")
        except: pass
        try: cursor.execute("ALTER TABLE tasks ADD COLUMN form_id INT")
        except: pass
        
        cursor.execute('SELECT * FROM users WHERE role = "admin"')
        if not cursor.fetchone():
            cursor.execute('INSERT INTO users (name, phone, email, emp_id, password_hash, role) VALUES (%s, %s, %s, %s, %s, %s)', ('مدير النظام', '07000000000', 'admin@domain.com', 'A001', generate_password_hash('admin123'), 'admin'))
        
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

def scheduled_task_alerts():
    while True:
        try:
            conn = get_db_connection()
            with conn.cursor() as cursor:
                cursor.execute("SELECT id, title, assigned_to FROM tasks WHERE status != 'completed' AND is_alerted = 0 AND due_date <= DATE_ADD(NOW(), INTERVAL 15 MINUTE) AND due_date >= NOW()")
                tasks = cursor.fetchall()
                for t in tasks:
                    msg = f"تذكير: موعد مهمة '{t['title']}' اقترب!"
                    cursor.execute("INSERT INTO notifications (user_id, title, message) VALUES (%s, %s, %s)", (t['assigned_to'], "موعد المهمة ⏰", msg))
                    cursor.execute("UPDATE tasks SET is_alerted = 1 WHERE id = %s", (t['id'],))
                    socketio.emit('employee_notification', {'title': "موعد المهمة ⏰", 'message': msg}, room=f"user_{t['assigned_to']}")
                    send_web_push(t['assigned_to'], "تذكير بالموعد", msg)
            conn.close()
        except: pass
        eventlet.sleep(60)

def send_web_push(user_id, title, message):
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute('SELECT * FROM push_subscriptions WHERE user_id = %s', (user_id,))
            subs = cursor.fetchall()
        conn.close()
        for sub in subs:
            try: webpush(subscription_info={"endpoint": sub['endpoint'], "keys": {"p256dh": sub['p256dh'], "auth": sub['auth']}}, data=json.dumps({"title": title, "message": message}), vapid_private_key=VAPID_PRIVATE_KEY, vapid_claims={"sub": "mailto:admin@kaisi.dev"})
            except: pass
    except: pass

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
            log_action(cursor, user['id'], 'login', 'users', user['id'])
            user['token'] = token; user.pop('password_hash')
            conn.close(); return jsonify({'success': True, 'user': user})
    conn.close(); return jsonify({'error': 'Unauthorized'}), 401

@app.route('/api/vapid-public-key', methods=['GET'])
def get_vapid_key(): return jsonify({'public_key': VAPID_PUBLIC_KEY})

@app.route('/api/subscribe', methods=['POST'])
def subscribe():
    data = request.get_json()
    endpoint = data.get('endpoint'); keys = data.get('keys', {})
    conn = get_db_connection()
    with conn.cursor() as cursor: cursor.execute('''INSERT INTO push_subscriptions (user_id, endpoint, p256dh, auth) VALUES (%s, %s, %s, %s) ON DUPLICATE KEY UPDATE p256dh=%s, auth=%s''', (request.current_user['id'], endpoint, keys.get('p256dh'), keys.get('auth'), keys.get('p256dh'), keys.get('auth')))
    conn.close(); return jsonify({'success': True})

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
        recorded_at_display = baghdad_now.strftime('%Y-%m-%d %I:%M %p')
    else: recorded_at_display = recorded_at_db
    
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute('INSERT INTO location_logs (user_id, lat, lng, is_offline_sync, recorded_at) VALUES (%s, %s, %s, %s, %s)', (user_id, lat, lng, is_offline, recorded_at_db))
        if user['zone_id']:
            cursor.execute('SELECT name, coordinates_json FROM zones WHERE id = %s', (user['zone_id'],))
            zone = cursor.fetchone()
            if zone and zone['coordinates_json']:
                coords = json.loads(zone['coordinates_json'])
                if not is_inside_polygon(lat, lng, coords):
                    alert_msg = f"⚠️ الموظف {user['name']} خرج من نطاق عمله ({zone['name']})!"
                    socketio.emit('idle_alert', {'user_id': user_id, 'message': alert_msg}, room='admins')
    conn.close()
    
    loc_data = { 'user_id': user_id, 'name': user['name'], 'profile_image': user.get('profile_image'), 'job_title': user['job_title'], 'zone_id': user['zone_id'], 'lat': lat, 'lng': lng, 'recorded_at': recorded_at_display }
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
        log_action(cursor, request.current_user['id'], 'check_in', 'attendance', None)
        msg_title = 'تسجيل حضور ⏰'; msg_body = f"الموظف {request.current_user['name']} سجل حضوره وبدأ العمل."
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
        log_action(cursor, request.current_user['id'], 'check_out', 'attendance', None)
        msg_title = 'تسجيل انصراف 🛑'; msg_body = f"الموظف {request.current_user['name']} أنهى فترة عمله."
        socketio.emit('admin_notification', {'title': msg_title, 'message': msg_body}, room='admins')
    conn.close(); return jsonify({'success': True})
# ----------------------------------------

# --- API أوامر العمل (Work Orders) ---
@app.route('/api/work_orders', methods=['GET', 'POST'])
def handle_work_orders():
    conn = get_db_connection()
    with conn.cursor() as cursor:
        if request.method == 'POST':
            if request.current_user['role'] != 'admin': return jsonify({'error': 'Forbidden'}), 403
            data = request.get_json()
            cursor.execute('INSERT INTO work_orders (title, client_id, team_id) VALUES (%s, %s, %s)', (data.get('title'), data.get('client_id'), data.get('team_id')))
            wo_id = cursor.lastrowid
            log_action(cursor, request.current_user['id'], 'create_work_order', 'work_orders', wo_id)
            conn.close(); return jsonify({'success': True, 'id': wo_id})
        else:
            cursor.execute('''
                SELECT w.*, c.name as client_name, t.name as team_name,
                (SELECT COUNT(*) FROM tasks WHERE work_order_id = w.id) as total_tasks,
                (SELECT COUNT(*) FROM tasks WHERE work_order_id = w.id AND status = 'completed') as completed_tasks
                FROM work_orders w 
                LEFT JOIN clients c ON w.client_id = c.id
                LEFT JOIN teams t ON w.team_id = t.id
                ORDER BY w.created_at DESC
            ''')
            wos = cursor.fetchall()
            conn.close(); return jsonify({'success': True, 'work_orders': wos})
# ----------------------------------------

# --- API باني النماذج الديناميكية (Forms Builder) ---
@app.route('/api/forms', methods=['GET', 'POST'])
def handle_forms():
    conn = get_db_connection()
    with conn.cursor() as cursor:
        if request.method == 'POST':
            if request.current_user['role'] != 'admin': return jsonify({'error': 'Forbidden'}), 403
            data = request.get_json()
            cursor.execute('INSERT INTO forms (title, fields_json) VALUES (%s, %s)', (data.get('title'), json.dumps(data.get('fields'), ensure_ascii=False)))
            form_id = cursor.lastrowid
            log_action(cursor, request.current_user['id'], 'create_form', 'forms', form_id)
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
        log_action(cursor, request.current_user['id'], 'submit_form', 'form_submissions', cursor.lastrowid, {'task_id': data.get('task_id')})
    conn.close(); return jsonify({'success': True})
# ----------------------------------------

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
        for log in logs: cursor.execute('INSERT INTO location_logs (user_id, lat, lng, is_offline_sync, recorded_at) VALUES (%s, %s, %s, %s, %s)', (user['id'], log['lat'], log['lng'], 1, log['recorded_at']))
    conn.close()
    socketio.emit('admin_notification', {'title': 'تحديث مسار متأخر', 'message': f'تمت مزامنة مسار أوفلاين للموظف {user["name"]}'}, room='admins')
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

            query = 'UPDATE tasks SET status = %s'; params = [upd.get('status', task['status'])]
            if combined_notes: query += ', notes = %s'; params.append(combined_notes)
            if final_image_json is not None: query += ', image_url = %s'; params.append(final_image_json)
            if upd.get('checklist') is not None: query += ', checklist = %s'; params.append(upd.get('checklist'))
            query += ' WHERE id = %s'; params.append(task_id)
            cursor.execute(query, params)
            log_action(cursor, user['id'], 'sync_task', 'tasks', task_id)
            
            action = "قام بمزامنة أعمال أوفلاين لمهمة"
            msg_title = f'مزامنة ميدانية 🔄'; msg_body = f"الموظف ({user['name']}) {action}: {task['title']}"
            cursor.execute('INSERT INTO notifications (user_id, title, message) VALUES (%s, %s, %s)', (task['created_by'], msg_title, msg_body))
            socketio.emit('admin_notification', {'title': msg_title, 'message': msg_body}, room=f"user_{task['created_by']}")
    conn.close()
    socketio.emit('task_updated', {}, room='admins')
    return jsonify({'success': True})

@app.route('/api/expenses', methods=['GET', 'POST'])
def handle_expenses():
    conn = get_db_connection()
    with conn.cursor() as cursor:
        if request.method == 'POST':
            if request.current_user['role'] != 'employee': return jsonify({'error': 'Forbidden'}), 403
            data = request.get_json()
            cursor.execute('INSERT INTO expenses (user_id, amount, currency, category, description, receipt_url) VALUES (%s, %s, %s, %s, %s, %s)', (request.current_user['id'], data['amount'], data['currency'], data['category'], data.get('description', ''), data.get('receipt_url')))
            msg_title = 'مطالبة مالية جديدة 💰'
            msg_body = f"الموظف {request.current_user['name']} قدم مطالبة بقيمة {data['amount']} {data['currency']}"
            cursor.execute('INSERT INTO notifications (user_id, title, message) VALUES ((SELECT id FROM users WHERE role="admin" LIMIT 1), %s, %s)', (msg_title, msg_body))
            socketio.emit('admin_notification', {'title': msg_title, 'message': msg_body}, room='admins')
            conn.close(); return jsonify({'success': True})
        else:
            cursor.execute("SELECT * FROM expenses WHERE user_id = %s ORDER BY created_at DESC", (request.current_user['id'],))
            expenses = cursor.fetchall()
            conn.close(); return jsonify({'success': True, 'expenses': expenses})

@app.route('/api/expenses/all', methods=['GET'])
def get_all_expenses():
    if request.current_user['role'] != 'admin': return jsonify({'error': 'Forbidden'}), 403
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute("SELECT e.*, u.name as emp_name FROM expenses e JOIN users u ON e.user_id = u.id ORDER BY e.created_at DESC")
        expenses = cursor.fetchall()
    conn.close(); return jsonify({'success': True, 'expenses': expenses})

@app.route('/api/expenses/<int:expense_id>/status', methods=['PUT'])
def update_expense_status(expense_id):
    if request.current_user['role'] != 'admin': return jsonify({'error': 'Forbidden'}), 403
    data = request.get_json()
    new_status = data.get('status')
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute('UPDATE expenses SET status = %s WHERE id = %s', (new_status, expense_id))
        cursor.execute('SELECT user_id, amount, currency FROM expenses WHERE id = %s', (expense_id,))
        exp = cursor.fetchone()
        log_action(cursor, request.current_user['id'], f'expense_{new_status}', 'expenses', expense_id)
        status_ar = "الموافقة على" if new_status == 'approved' else "رفض"
        msg_title = 'تحديث حالة المطالبة 💳'
        msg_body = f"تم {status_ar} مطالبتك بقيمة {exp['amount']} {exp['currency']}"
        cursor.execute('INSERT INTO notifications (user_id, title, message) VALUES (%s, %s, %s)', (exp['user_id'], msg_title, msg_body))
        socketio.emit('employee_notification', {'title': msg_title, 'message': msg_body}, room=f"user_{exp['user_id']}")
    conn.close(); return jsonify({'success': True})

@app.route('/api/clients', methods=['GET', 'POST'])
def handle_clients():
    conn = get_db_connection()
    with conn.cursor() as cursor:
        if request.method == 'POST':
            if request.current_user['role'] != 'admin': return jsonify({'error': 'Forbidden'}), 403
            data = request.get_json()
            cursor.execute('INSERT INTO clients (name, phone, address, lat, lng) VALUES (%s, %s, %s, %s, %s)', (data.get('name'), data.get('phone'), data.get('address'), data.get('lat'), data.get('lng')))
            log_action(cursor, request.current_user['id'], 'create_client', 'clients', cursor.lastrowid)
            conn.close(); return jsonify({'success': True})
        else:
            cursor.execute('SELECT * FROM clients ORDER BY created_at DESC'); clients = cursor.fetchall()
            conn.close(); return jsonify({'success': True, 'clients': clients})

@app.route('/api/clients/<int:client_id>/history', methods=['GET'])
def client_history(client_id):
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute("SELECT t.title, t.status, t.due_date, t.notes, u.name as emp_name FROM tasks t LEFT JOIN users u ON t.assigned_to = u.id WHERE t.client_id = %s ORDER BY t.due_date DESC", (client_id,))
        history = cursor.fetchall()
    conn.close(); return jsonify({'success': True, 'history': history})

@app.route('/api/profile/image', methods=['PUT'])
def update_profile_image():
    data = request.get_json(); conn = get_db_connection()
    with conn.cursor() as cursor: cursor.execute('UPDATE users SET profile_image = %s WHERE id = %s', (data.get('image_url'), request.current_user['id']))
    conn.close(); return jsonify({'success': True})

@app.route('/api/users/employees', methods=['GET'])
def get_employees():
    conn = get_db_connection()
    with conn.cursor() as cursor:
        if request.current_user['role'] == 'admin': cursor.execute("SELECT u.id, u.name, u.phone, u.job_title, u.role, u.profile_image, u.team_id, u.zone_id, t.name as team_name FROM users u LEFT JOIN teams t ON u.team_id = t.id WHERE u.role IN ('employee', 'manager')")
        else: cursor.execute("SELECT u.id, u.name, u.phone, u.job_title, u.role, u.profile_image, u.team_id, u.zone_id, t.name as team_name FROM users u LEFT JOIN teams t ON u.team_id = t.id WHERE u.team_id IN (SELECT id FROM teams WHERE manager_id = %s)", (request.current_user['id'],))
        employees = cursor.fetchall()
    conn.close(); return jsonify({'success': True, 'employees': employees})

@app.route('/api/users', methods=['POST'])
def create_user():
    if request.current_user['role'] != 'admin': return jsonify({'error': 'Forbidden'}), 403
    data = request.get_json()
    hashed_password = generate_password_hash(data.get('password'))
    emp_id = f"E{int(datetime.utcnow().timestamp())}"
    zone_id = int(data.get('zone_id')) if data.get('zone_id') else None
    team_id = int(data.get('team_id')) if data.get('team_id') else None
    conn = get_db_connection()
    with conn.cursor() as cursor:
        try: 
            cursor.execute('INSERT INTO users (name, phone, password_hash, role, job_title, emp_id, zone_id, team_id) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)', (data.get('name'), data.get('phone'), hashed_password, data.get('role', 'employee'), data.get('job_title', 'موظف'), emp_id, zone_id, team_id))
            log_action(cursor, request.current_user['id'], 'create_user', 'users', cursor.lastrowid)
        except pymysql.err.IntegrityError: conn.close(); return jsonify({'error': 'Conflict', 'message': 'الهاتف مسجل مسبقاً'}), 409
    conn.close(); return jsonify({'success': True})

@app.route('/api/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    if request.current_user['role'] != 'admin': return jsonify({'error': 'Forbidden'}), 403
    data = request.get_json()
    zone_id = int(data.get('zone_id')) if data.get('zone_id') else None
    team_id = int(data.get('team_id')) if data.get('team_id') else None
    conn = get_db_connection()
    with conn.cursor() as cursor:
        try:
            query = "UPDATE users SET name=%s, phone=%s, role=%s, job_title=%s, zone_id=%s, team_id=%s"
            params = [data.get('name'), data.get('phone'), data.get('role'), data.get('job_title'), zone_id, team_id]
            if data.get('password'): query += ", password_hash=%s"; params.append(generate_password_hash(data.get('password')))
            query += " WHERE id=%s"; params.append(user_id)
            cursor.execute(query, params)
            log_action(cursor, request.current_user['id'], 'update_user', 'users', user_id)
        except pymysql.err.IntegrityError: conn.close(); return jsonify({'error': 'Conflict', 'message': 'رقم الهاتف مستخدم لموظف آخر'}), 409
    conn.close(); return jsonify({'success': True})

@app.route('/api/stats', methods=['GET'])
def get_stats():
    conn = get_db_connection()
    with conn.cursor() as cursor:
        if request.current_user['role'] == 'admin':
            cursor.execute("SELECT COUNT(*) as c FROM users WHERE role = 'employee'"); emp_count = cursor.fetchone()['c']
            cursor.execute("SELECT COUNT(*) as c FROM tasks"); total_tasks = cursor.fetchone()['c']
            cursor.execute("SELECT COUNT(*) as c FROM tasks WHERE status = 'completed'"); completed_tasks = cursor.fetchone()['c']
        else:
            cursor.execute("SELECT COUNT(*) as c FROM users WHERE team_id IN (SELECT id FROM teams WHERE manager_id = %s)", (request.current_user['id'],)); emp_count = cursor.fetchone()['c']
            cursor.execute("SELECT COUNT(t.id) as c FROM tasks t JOIN users u ON t.assigned_to = u.id WHERE u.team_id IN (SELECT id FROM teams WHERE manager_id = %s)", (request.current_user['id'],)); total_tasks = cursor.fetchone()['c']
            cursor.execute("SELECT COUNT(t.id) as c FROM tasks t JOIN users u ON t.assigned_to = u.id WHERE t.status = 'completed' AND u.team_id IN (SELECT id FROM teams WHERE manager_id = %s)", (request.current_user['id'],)); completed_tasks = cursor.fetchone()['c']
    conn.close(); return jsonify({'success': True, 'stats': {'employees': emp_count, 'total_tasks': total_tasks, 'completed_tasks': completed_tasks, 'pending_tasks': total_tasks - completed_tasks}})

@app.route('/api/tasks/all', methods=['GET'])
def get_all_tasks():
    conn = get_db_connection()
    with conn.cursor() as cursor:
        base_query = "SELECT t.*, u.name as assignee_name, c.name as client_name, c.phone as client_phone FROM tasks t LEFT JOIN users u ON t.assigned_to = u.id LEFT JOIN clients c ON t.client_id = c.id"
        if request.current_user['role'] == 'admin': cursor.execute(base_query + " ORDER BY t.due_date DESC")
        else: cursor.execute(base_query + " WHERE u.team_id IN (SELECT id FROM teams WHERE manager_id = %s) ORDER BY t.due_date DESC", (request.current_user['id'],))
        tasks = cursor.fetchall()
    conn.close(); return jsonify({'success': True, 'tasks': tasks})

@app.route('/api/tasks', methods=['POST'])
def create_task():
    data = request.get_json()
    checklist_json = json.dumps([{"title": item, "is_completed": False, "note": ""} for item in data.get('checklist', [])], ensure_ascii=False) if data.get('checklist') else None
    client_id = data.get('client_id'); lat = data.get('lat'); lng = data.get('lng')
    work_order_id = data.get('work_order_id'); form_id = data.get('form_id')
    
    conn = get_db_connection()
    with conn.cursor() as cursor:
        if client_id:
            cursor.execute('SELECT lat, lng FROM clients WHERE id = %s', (client_id,))
            client = cursor.fetchone()
            if client and not lat: lat = client['lat']; lng = client['lng']
        cursor.execute('INSERT INTO tasks (title, assigned_to, created_by, lat, lng, due_date, checklist, recurrence, client_id, work_order_id, form_id) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)', (data['title'], data['assigned_to'], request.current_user['id'], lat, lng, data['due_date'], checklist_json, data.get('recurrence', 'none'), client_id, work_order_id, form_id))
        task_id = cursor.lastrowid
        log_action(cursor, request.current_user['id'], 'create_task', 'tasks', task_id)
        
        msg_title = 'مهمة جديدة 🚀'; msg_body = f"تم إسناد مهمة جديدة لك: {data['title']}"
        cursor.execute('INSERT INTO notifications (user_id, title, message) VALUES (%s, %s, %s)', (data['assigned_to'], msg_title, msg_body))
    conn.close()
    socketio.emit('employee_notification', {'title': msg_title, 'message': msg_body}, room=f"user_{data['assigned_to']}")
    socketio.emit('task_updated', {}, room='admins')
    send_web_push(data['assigned_to'], msg_title, msg_body)
    return jsonify({'success': True})

@app.route('/api/tasks/my', methods=['GET'])
def get_my_tasks():
    conn = get_db_connection()
    with conn.cursor() as cursor: cursor.execute('SELECT t.*, c.name as client_name, c.phone as client_phone, c.address as client_address FROM tasks t LEFT JOIN clients c ON t.client_id = c.id WHERE t.assigned_to = %s ORDER BY t.due_date ASC', (request.current_user['id'],)); tasks = cursor.fetchall()
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

        query = 'UPDATE tasks SET status = %s'; params = [data.get('status', task['status'])]
        if combined_notes: query += ', notes = %s'; params.append(combined_notes)
        if final_image_json is not None: query += ', image_url = %s'; params.append(final_image_json)
        if data.get('checklist') is not None: query += ', checklist = %s'; params.append(data.get('checklist'))
        query += ' WHERE id = %s'; params.append(task_id)
        cursor.execute(query, params)
        log_action(cursor, request.current_user['id'], 'update_task_status', 'tasks', task_id, {'new_status': data.get('status')})
        
        new_status = data.get('status', task['status'])
        action = "بدأ بتنفيذ" if new_status == 'in_progress' else "أكمل" if new_status == 'completed' else "أضاف تحديثاً على"
        cursor.execute('SELECT name FROM users WHERE id = %s', (task['assigned_to'],)); emp_name = cursor.fetchone()['name']
        msg_title = f'تحديث ميداني 📋'; msg_body = f"الموظف ({emp_name}) {action} مهمة: {task['title']}"
        cursor.execute('INSERT INTO notifications (user_id, title, message) VALUES (%s, %s, %s)', (task['created_by'], msg_title, msg_body))
        socketio.emit('admin_notification', {'title': msg_title, 'message': msg_body}, room=f"user_{task['created_by']}")
    conn.close()
    socketio.emit('task_updated', {}, room='admins')
    return jsonify({'success': True})

@app.route('/api/location/latest', methods=['GET'])
def get_latest_locations():
    conn = get_db_connection()
    with conn.cursor() as cursor:
        base_query = "SELECT l.user_id, l.lat, l.lng, l.recorded_at, u.name, u.job_title, u.zone_id, u.profile_image FROM location_logs l JOIN users u ON l.user_id = u.id INNER JOIN (SELECT user_id, MAX(recorded_at) as max_date FROM location_logs GROUP BY user_id) grouped_l ON l.user_id = grouped_l.user_id AND l.recorded_at = grouped_l.max_date"
        if request.current_user['role'] == 'admin': cursor.execute(base_query)
        else: cursor.execute(base_query + ' WHERE u.team_id IN (SELECT id FROM teams WHERE manager_id = %s)', (request.current_user['id'],))
        locations = cursor.fetchall()
    conn.close(); return jsonify({'success': True, 'locations': locations})

@app.route('/api/location/history/<int:user_id>', methods=['GET'])
def get_location_history(user_id):
    conn = get_db_connection()
    with conn.cursor() as cursor:
        baghdad_now = datetime.utcnow() + timedelta(hours=3)
        target_date = request.args.get('date', baghdad_now.strftime('%Y-%m-%d'))
        # ترتيب تصاعدي للزمن لضمان تشغيل المسار بشكل صحيح (Route Playback)
        cursor.execute('SELECT lat, lng, recorded_at FROM location_logs WHERE user_id = %s AND DATE(recorded_at) = %s ORDER BY recorded_at ASC', (user_id, target_date))
        history = cursor.fetchall()
    conn.close(); return jsonify({'success': True, 'history': history})

@app.route('/api/zones', methods=['GET', 'POST'])
def handle_zones():
    conn = get_db_connection()
    with conn.cursor() as cursor:
        if request.method == 'POST':
            data = request.get_json()
            cursor.execute('INSERT INTO zones (name, coordinates_json, color) VALUES (%s, %s, %s)', (data.get('name'), data.get('coordinates_json'), data.get('color', '#3b82f6')))
            log_action(cursor, request.current_user['id'], 'create_zone', 'zones', cursor.lastrowid)
            conn.close(); return jsonify({'success': True})
        else: 
            cursor.execute('SELECT * FROM zones')
            zones = cursor.fetchall()
            conn.close(); return jsonify({'success': True, 'zones': zones})

try:
    init_db()
    eventlet.spawn(scheduled_task_alerts)
except Exception as e: print(f"❌ Error: {e}")

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)