# app.py
import sqlite3
import os
import secrets
import json
import base64
import uuid
import math
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from flask_socketio import SocketIO, join_room, emit

app = Flask(__name__, static_folder='static')
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

DB_NAME = 'field_management.db'
UPLOAD_FOLDER = os.path.join('static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

employee_tracking = {}

def get_distance(lat1, lon1, lat2, lon2):
    R = 6371e3 
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)
    a = math.sin(delta_phi/2.0)**2 + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda/2.0)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    if not os.path.exists(DB_NAME):
        conn = get_db_connection()
        if os.path.exists('schema.sql'):
            with open('schema.sql', 'r', encoding='utf-8') as f: conn.executescript(f.read())
        cursor = conn.cursor()
        admin_pass = generate_password_hash('admin123')
        cursor.execute('INSERT INTO users (name, phone, email, emp_id, password_hash, role) VALUES (?, ?, ?, ?, ?, ?)', ('مدير النظام', '07000000000', 'admin@domain.com', 'A001', admin_pass, 'admin'))
        conn.commit(); conn.close()
    
    conn = get_db_connection()
    try: conn.execute("ALTER TABLE tasks ADD COLUMN image_url TEXT")
    except sqlite3.OperationalError: pass
    try: conn.execute("ALTER TABLE tasks ADD COLUMN checklist TEXT")
    except sqlite3.OperationalError: pass
    try: conn.execute("ALTER TABLE tasks ADD COLUMN recurrence TEXT DEFAULT 'none'")
    except sqlite3.OperationalError: pass
    conn.execute('CREATE TABLE IF NOT EXISTS notifications (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, title TEXT NOT NULL, message TEXT, is_read BOOLEAN DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)')
    conn.commit(); conn.close()

@app.before_request
def require_auth():
    if request.method == 'OPTIONS': return
    if request.endpoint == 'login' or request.endpoint == 'serve_static': return
    token = request.headers.get('Authorization')
    if not token: return jsonify({'error': 'Unauthorized'}), 401
    token = token.replace('Bearer ', '')
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE token = ?', (token,)).fetchone()
    conn.close()
    if not user: return jsonify({'error': 'Unauthorized'}), 401
    request.current_user = dict(user)

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE phone = ?', (data.get('phone'),)).fetchone()
    if user and check_password_hash(user['password_hash'], data.get('password')):
        token = secrets.token_hex(32)
        conn.execute('UPDATE users SET token = ? WHERE id = ?', (token, user['id']))
        conn.commit(); conn.close()
        user_data = dict(user); user_data.pop('password_hash'); user_data['token'] = token
        return jsonify({'success': True, 'user': user_data})
    conn.close()
    return jsonify({'error': 'Unauthorized'}), 401

@app.route('/static/uploads/<path:filename>')
def serve_static(filename): return send_from_directory(UPLOAD_FOLDER, filename)

@socketio.on('authenticate')
def handle_auth(data):
    token = data.get('token')
    if not token: return
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE token = ?', (token,)).fetchone()
    conn.close()
    if user:
        join_room(f"user_{user['id']}")
        if user['role'] == 'admin': join_room('admins')
        elif user['role'] == 'manager': join_room(f"manager_{user['team_id']}")

@socketio.on('send_location')
def handle_location(data):
    token = data.get('token')
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE token = ?', (token,)).fetchone()
    if not user or user['role'] != 'employee':
        conn.close(); return

    lat = data.get('lat'); lng = data.get('lng'); user_id = user['id']
    now = datetime.utcnow(); recorded_at_str = now.strftime('%Y-%m-%d %H:%M:%S')

    conn.execute('INSERT INTO location_logs (user_id, lat, lng, is_offline_sync, recorded_at) VALUES (?, ?, ?, ?, ?)', (user_id, lat, lng, False, recorded_at_str))
    loc_data = { 'user_id': user_id, 'name': user['name'], 'job_title': user['job_title'], 'zone_id': user['zone_id'], 'lat': lat, 'lng': lng, 'recorded_at': recorded_at_str }
    
    socketio.emit('new_location', loc_data, room='admins')
    if user['team_id']: socketio.emit('new_location', loc_data, room=f"manager_{user['team_id']}")

    if user_id in employee_tracking:
        prev = employee_tracking[user_id]
        distance = get_distance(prev['lat'], prev['lng'], lat, lng)
        if distance > 30: 
            employee_tracking[user_id] = {'lat': lat, 'lng': lng, 'last_moved': now, 'alert_sent': False}
        else:
            diff_minutes = (now - prev['last_moved']).total_seconds() / 60
            if diff_minutes > 30 and not prev.get('alert_sent'):
                alert_msg = f"الموظف {user['name']} متوقف في نفس المكان منذ أكثر من 30 دقيقة!"
                socketio.emit('idle_alert', {'user_id': user_id, 'message': alert_msg}, room='admins')
                employee_tracking[user_id]['alert_sent'] = True
    else:
        employee_tracking[user_id] = {'lat': lat, 'lng': lng, 'last_moved': now, 'alert_sent': False}

    conn.commit(); conn.close()

@app.route('/api/teams', methods=['GET', 'POST'])
def handle_teams():
    if request.current_user['role'] != 'admin': return jsonify({'error': 'Forbidden'}), 403
    conn = get_db_connection()
    if request.method == 'POST':
        data = request.get_json()
        conn.execute('INSERT INTO teams (name, manager_id) VALUES (?, ?)', (data.get('name'), data.get('manager_id')))
        conn.commit(); conn.close(); return jsonify({'success': True})
    else:
        teams = conn.execute('SELECT t.*, u.name as manager_name FROM teams t LEFT JOIN users u ON t.manager_id = u.id').fetchall()
        conn.close(); return jsonify({'success': True, 'teams': [dict(t) for t in teams]})

@app.route('/api/users', methods=['POST'])
def create_user():
    if request.current_user['role'] != 'admin': return jsonify({'error': 'Forbidden'}), 403
    data = request.get_json()
    hashed_password = generate_password_hash(data.get('password'))
    emp_id = f"E{int(datetime.now().timestamp())}"
    zone_id = int(data.get('zone_id')) if data.get('zone_id') else None
    team_id = int(data.get('team_id')) if data.get('team_id') else None
    conn = get_db_connection()
    try:
        conn.execute('INSERT INTO users (name, phone, password_hash, role, job_title, emp_id, zone_id, team_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', 
                    (data.get('name'), data.get('phone'), hashed_password, data.get('role', 'employee'), data.get('job_title', 'موظف'), emp_id, zone_id, team_id))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close(); return jsonify({'error': 'Conflict', 'message': 'رقم الهاتف مسجل مسبقاً'}), 409
    conn.close(); return jsonify({'success': True})

@app.route('/api/users/managers', methods=['GET'])
def get_managers():
    conn = get_db_connection()
    managers = conn.execute("SELECT id, name FROM users WHERE role = 'manager'").fetchall(); conn.close()
    return jsonify({'success': True, 'managers': [dict(m) for m in managers]})

@app.route('/api/users/employees', methods=['GET'])
def get_employees():
    conn = get_db_connection()
    if request.current_user['role'] == 'admin': users = conn.execute("SELECT u.id, u.name, u.phone, u.job_title, u.role, t.name as team_name FROM users u LEFT JOIN teams t ON u.team_id = t.id WHERE u.role IN ('employee', 'manager')").fetchall()
    else: users = conn.execute("SELECT u.id, u.name, u.phone, u.job_title, u.role, t.name as team_name FROM users u LEFT JOIN teams t ON u.team_id = t.id WHERE u.team_id IN (SELECT id FROM teams WHERE manager_id = ?)", (request.current_user['id'],)).fetchall()
    conn.close(); return jsonify({'success': True, 'employees': [dict(u) for u in users]})

@app.route('/api/stats', methods=['GET'])
def get_stats():
    conn = get_db_connection()
    if request.current_user['role'] == 'admin':
        emp_count = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'employee'").fetchone()[0]
        total_tasks = conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
        completed_tasks = conn.execute("SELECT COUNT(*) FROM tasks WHERE status = 'completed'").fetchone()[0]
    else:
        emp_count = conn.execute("SELECT COUNT(*) FROM users WHERE team_id IN (SELECT id FROM teams WHERE manager_id = ?)", (request.current_user['id'],)).fetchone()[0]
        total_tasks = conn.execute("SELECT COUNT(t.id) FROM tasks t JOIN users u ON t.assigned_to = u.id WHERE u.team_id IN (SELECT id FROM teams WHERE manager_id = ?)", (request.current_user['id'],)).fetchone()[0]
        completed_tasks = conn.execute("SELECT COUNT(t.id) FROM tasks t JOIN users u ON t.assigned_to = u.id WHERE t.status = 'completed' AND u.team_id IN (SELECT id FROM teams WHERE manager_id = ?)", (request.current_user['id'],)).fetchone()[0]
    conn.close()
    return jsonify({'success': True, 'stats': {'employees': emp_count, 'total_tasks': total_tasks, 'completed_tasks': completed_tasks, 'pending_tasks': total_tasks - completed_tasks}})

@app.route('/api/tasks/all', methods=['GET'])
def get_all_tasks():
    conn = get_db_connection()
    if request.current_user['role'] == 'admin': tasks = conn.execute("SELECT tasks.*, users.name as assignee_name FROM tasks LEFT JOIN users ON tasks.assigned_to = users.id ORDER BY tasks.due_date DESC").fetchall()
    else: tasks = conn.execute("SELECT tasks.*, users.name as assignee_name FROM tasks LEFT JOIN users ON tasks.assigned_to = users.id WHERE users.team_id IN (SELECT id FROM teams WHERE manager_id = ?) ORDER BY tasks.due_date DESC", (request.current_user['id'],)).fetchall()
    conn.close(); return jsonify({'success': True, 'tasks': [dict(row) for row in tasks]})

@app.route('/api/tasks', methods=['POST'])
def create_task():
    data = request.get_json()
    checklist_json = json.dumps([{"title": item, "is_completed": False} for item in data.get('checklist', [])], ensure_ascii=False) if data.get('checklist') else None
    conn = get_db_connection()
    conn.execute('INSERT INTO tasks (title, assigned_to, created_by, lat, lng, due_date, checklist, recurrence) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', 
                 (data['title'], data['assigned_to'], request.current_user['id'], data['lat'], data['lng'], data['due_date'], checklist_json, data.get('recurrence', 'none')))
    
    msg_title = 'مهمة جديدة 🚀'
    msg_body = f"تم إسناد مهمة جديدة لك: {data['title']}"
    conn.execute('INSERT INTO notifications (user_id, title, message) VALUES (?, ?, ?)', (data['assigned_to'], msg_title, msg_body))
    conn.commit(); conn.close()
    
    socketio.emit('employee_notification', {'title': msg_title, 'message': msg_body}, room=f"user_{data['assigned_to']}")
    socketio.emit('task_updated', {}, room='admins')
    return jsonify({'success': True})

@app.route('/api/tasks/my', methods=['GET'])
def get_my_tasks():
    conn = get_db_connection()
    tasks = conn.execute('SELECT * FROM tasks WHERE assigned_to = ? ORDER BY due_date ASC', (request.current_user['id'],)).fetchall(); conn.close()
    return jsonify({'success': True, 'tasks': [dict(row) for row in tasks]})

@app.route('/api/tasks/<int:task_id>/status', methods=['PUT'])
def update_task_status(task_id):
    data = request.get_json()
    conn = get_db_connection()
    task = conn.execute('SELECT * FROM tasks WHERE id = ?', (task_id,)).fetchone()
    if not task: conn.close(); return jsonify({'error': 'Not found'}), 404
    
    # معالجة الصور المتعددة وتخزينها كمصفوفة JSON
    existing_images = []
    if task['image_url']:
        try:
            parsed = json.loads(task['image_url'])
            existing_images = parsed if isinstance(parsed, list) else [task['image_url']]
        except: existing_images = [task['image_url']]

    new_images = []
    if data.get('images') and isinstance(data.get('images'), list):
        for img_b64 in data.get('images'):
            if ',' in img_b64:
                try:
                    img_data = base64.b64decode(img_b64.split(',')[1])
                    filename = f"task_{task_id}_{uuid.uuid4().hex[:8]}.jpg"
                    with open(os.path.join(UPLOAD_FOLDER, filename), 'wb') as f: f.write(img_data)
                    new_images.append(f"/static/uploads/{filename}")
                except Exception: pass
    
    all_images = existing_images + new_images
    final_image_json = json.dumps(all_images) if all_images else None

    query = 'UPDATE tasks SET status = ?'; params = [data.get('status', task['status'])]
    if data.get('notes') is not None: query += ', notes = ?'; params.append(data.get('notes'))
    if final_image_json is not None: query += ', image_url = ?'; params.append(final_image_json)
    if data.get('checklist') is not None: query += ', checklist = ?'; params.append(data.get('checklist'))
    query += ' WHERE id = ?'; params.append(task_id)
    
    conn.execute(query, params)
    
    # تنبيه الإدارة بأي تغيير يجريه الموظف (بدء، إكمال، أو تحديث خطوة)
    new_status = data.get('status')
    if (new_status and new_status != task['status']) or data.get('checklist'):
        emp_name = conn.execute('SELECT name FROM users WHERE id = ?', (task['assigned_to'],)).fetchone()['name']
        action = "بدأ بتنفيذ" if new_status == 'in_progress' else "أكمل" if new_status == 'completed' else "قام بتحديث"
        msg_title = f'تحديث في المهمة 📋'
        msg_body = f"الموظف ({emp_name}) {action} مهمة: {task['title']}"
        conn.execute('INSERT INTO notifications (user_id, title, message) VALUES (?, ?, ?)', (task['created_by'], msg_title, msg_body))
        socketio.emit('admin_notification', {'title': msg_title, 'message': msg_body}, room=f"user_{task['created_by']}")

    conn.commit(); conn.close()
    socketio.emit('task_updated', {}, room='admins')
    return jsonify({'success': True})

@app.route('/api/notifications', methods=['GET'])
def get_notifications():
    conn = get_db_connection()
    notifs = conn.execute('SELECT * FROM notifications WHERE user_id = ? AND is_read = 0 ORDER BY created_at DESC', (request.current_user['id'],)).fetchall()
    if notifs:
        ids = [str(n['id']) for n in notifs]
        conn.execute(f"UPDATE notifications SET is_read = 1 WHERE id IN ({','.join(ids)})")
        conn.commit()
    conn.close(); return jsonify({'success': True, 'notifications': [dict(n) for n in notifs]})

@app.route('/api/location', methods=['POST'])
def sync_location_fallback():
    data = request.get_json()
    conn = get_db_connection()
    conn.execute('INSERT INTO location_logs (user_id, lat, lng, is_offline_sync, recorded_at) VALUES (?, ?, ?, ?, ?)', 
                 (request.current_user['id'], data.get('lat'), data.get('lng'), True, data.get('recorded_at', datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'))))
    conn.commit(); conn.close(); return jsonify({'success': True})

@app.route('/api/location/latest', methods=['GET'])
def get_latest_locations():
    conn = get_db_connection()
    base_query = "SELECT l.user_id, l.lat, l.lng, l.recorded_at, u.name, u.job_title, u.zone_id FROM location_logs l JOIN users u ON l.user_id = u.id INNER JOIN (SELECT user_id, MAX(recorded_at) as max_date FROM location_logs GROUP BY user_id) grouped_l ON l.user_id = grouped_l.user_id AND l.recorded_at = grouped_l.max_date"
    if request.current_user['role'] == 'admin': locations = conn.execute(base_query).fetchall()
    else: locations = conn.execute(base_query + ' WHERE u.team_id IN (SELECT id FROM teams WHERE manager_id = ?)', (request.current_user['id'],)).fetchall()
    conn.close(); return jsonify({'success': True, 'locations': [dict(loc) for loc in locations]})

@app.route('/api/location/history/<int:user_id>', methods=['GET'])
def get_location_history(user_id):
    conn = get_db_connection()
    locations = conn.execute('SELECT lat, lng, recorded_at FROM location_logs WHERE user_id = ? AND date(recorded_at) = ? ORDER BY recorded_at ASC', (user_id, request.args.get('date'))).fetchall()
    conn.close(); return jsonify({'success': True, 'history': [dict(loc) for loc in locations]})

@app.route('/api/reports', methods=['GET'])
def get_reports():
    conn = get_db_connection()
    base_query = "SELECT u.name as emp_name, u.job_title, t_team.name as team_name, COUNT(t.id) as total_tasks, SUM(CASE WHEN t.status = 'completed' THEN 1 ELSE 0 END) as completed_tasks, SUM(CASE WHEN t.status = 'delayed' THEN 1 ELSE 0 END) as delayed_tasks, SUM(CASE WHEN t.status = 'in_progress' THEN 1 ELSE 0 END) as in_progress_tasks FROM users u LEFT JOIN tasks t ON u.id = t.assigned_to LEFT JOIN teams t_team ON u.team_id = t_team.id WHERE u.role = 'employee'"
    if request.current_user['role'] == 'admin': reports = conn.execute(base_query + ' GROUP BY u.id').fetchall()
    else: reports = conn.execute(base_query + ' AND u.team_id IN (SELECT id FROM teams WHERE manager_id = ?) GROUP BY u.id', (request.current_user['id'],)).fetchall()
    conn.close()
    clean_reports = []
    for r in reports:
        d = dict(r)
        for key in ['total_tasks', 'completed_tasks', 'delayed_tasks', 'in_progress_tasks']: d[key] = d[key] or 0
        clean_reports.append(d)
    return jsonify({'success': True, 'reports': clean_reports})

@app.route('/api/zones', methods=['GET', 'POST'])
def handle_zones():
    conn = get_db_connection()
    if request.method == 'POST':
        data = request.get_json()
        conn.execute('INSERT INTO zones (name, coordinates_json, color) VALUES (?, ?, ?)', (data.get('name'), data.get('coordinates_json'), data.get('color', '#3b82f6')))
        conn.commit(); conn.close(); return jsonify({'success': True})
    else: 
        zones = conn.execute('SELECT * FROM zones').fetchall()
        conn.close(); return jsonify({'success': True, 'zones': [dict(z) for z in zones]})

if __name__ == '__main__':
    init_db()
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)