from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import ssl
import socket
import secrets
import os
from functools import wraps
import dns.resolver
from datetime import datetime, timezone
from cryptography import x509

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
DATABASE = os.getenv('DATABASE_PATH', 'credmonitor.db')
app.config['DATABASE'] = DATABASE


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            salt TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_name TEXT NOT NULL,
            target_type TEXT DEFAULT 'dns',
            target_value TEXT,
            sort_order INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')



    conn.commit()
    conn.close()


def check_cert_expiry(domain, target_type='dns', target_value=None):
    """检查SSL证书过期时间"""
    try:
        # 确定连接地址
        address = domain

        if target_type == 'ip':
            address = target_value if target_value else domain
        elif target_type == 'cname':
            if target_value:
                address = target_value
            else:
                # 解析CNAME
                answers = dns.resolver.resolve(domain, 'CNAME')
                if answers:
                    address = str(answers[0].target).rstrip('.')

        # 创建socket连接
        sock = socket.create_connection((address, 443), timeout=10)
        context = ssl._create_unverified_context()

        # 使用SSL包装socket
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            cert_der = ssock.getpeercert(binary_form=True)
            if not cert_der:
                raise ValueError('未获取到证书')

            # 使用cryptography库解析证书
            cert = x509.load_der_x509_certificate(cert_der)

            # 获取当前时间和证书有效期
            current_time = datetime.now(timezone.utc)

            # 兼容不同版本的cryptography库
            if hasattr(cert, 'not_valid_after_utc'):
                expiry_date = cert.not_valid_after_utc
                start_date = cert.not_valid_before_utc
            else:
                expiry_date = cert.not_valid_after.replace(tzinfo=timezone.utc)
                start_date = cert.not_valid_before.replace(tzinfo=timezone.utc)

            # 检查证书是否有效
            if not (start_date < current_time < expiry_date):
                if current_time > expiry_date:
                    status = 'expired'
                else:
                    status = 'invalid'
            else:
                # 计算剩余天数
                days_remaining = (expiry_date - current_time).days

                if days_remaining < 0:
                    status = 'expired'
                elif days_remaining < 7:
                    status = 'critical'
                elif days_remaining < 30:
                    status = 'warning'
                else:
                    status = 'valid'

            # 解析证书主域名 (Subject CN)
            subject_cn = None
            subject_o = None
            subject_ou = None
            try:
                for attr in cert.subject:
                    if attr.oid._name == 'commonName':
                        subject_cn = attr.value
                    elif attr.oid._name == 'organizationName':
                        subject_o = attr.value
                    elif attr.oid._name == 'organizationalUnitName':
                        subject_ou = attr.value
            except:
                pass

            # 解析签发机构信息 (Issuer CN, O, OU)
            issuer_cn = None
            issuer_o = None
            issuer_ou = None
            try:
                for attr in cert.issuer:
                    if attr.oid._name == 'commonName':
                        issuer_cn = attr.value
                    elif attr.oid._name == 'organizationName':
                        issuer_o = attr.value
                    elif attr.oid._name == 'organizationalUnitName':
                        issuer_ou = attr.value
            except:
                pass

        return {
            'success': True,
            'expiry_date': expiry_date.replace(tzinfo=None),  # 转换为naive datetime
            'start_date': start_date.replace(tzinfo=None),  # 证书发放时间
            'subject_cn': subject_cn,  # 证书主域名 (CN)
            'subject_o': subject_o,    # 证书组织 (O)
            'subject_ou': subject_ou,  # 证书组织单位 (OU)
            'issuer_cn': issuer_cn,    # 签发机构CN
            'issuer_o': issuer_o,      # 签发机构O
            'issuer_ou': issuer_ou,    # 签发机构OU
            'days_remaining': days_remaining if 'days_remaining' in locals() else 0,
            'status': status
        }

    except Exception as e:
        import traceback
        return {
            'success': False,
            'error': str(e),
            'status': 'error',
            'traceback': traceback.format_exc() if app.debug else None
        }


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if not session.get('is_admin', False):
            return jsonify({'success': False, 'error': '权限不足，需要管理员权限'}), 403
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
@login_required
def index():
    return render_template('index.html',
                          is_admin=session.get('is_admin', False),
                          username=session.get('username', ''))



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password + user['salt']):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = bool(user['is_admin'])
            return redirect(url_for('index'))
        else:
            flash('用户名或密码错误', 'error')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('请填写完整信息', 'error')
            return render_template('register.html')

        conn = get_db()
        cursor = conn.cursor()

        # 检查是否已有用户
        cursor.execute('SELECT COUNT(*) FROM users')
        user_count = cursor.fetchone()[0]

        # 如果已有用户，普通注册已关闭
        if user_count > 0:
            conn.close()
            flash('注册功能已关闭，请联系管理员添加账号', 'error')
            return render_template('register.html')

        # 首个用户自动成为管理员，并使用加盐hash
        salt = secrets.token_hex(16)
        password_hash = generate_password_hash(password + salt)

        try:
            cursor.execute(
                'INSERT INTO users (username, password, salt, is_admin) VALUES (?, ?, ?, 1)',
                (username, password_hash, salt)
            )
            conn.commit()
            flash('管理员账号注册成功，请登录', 'success')
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('用户名已存在', 'error')
        conn.close()

    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/api/users', methods=['POST'])
@login_required
@admin_required
def add_user():
    """管理员添加新用户"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    is_admin = data.get('is_admin', False)

    if not username or not password:
        return jsonify({'success': False, 'error': '用户名和密码不能为空'}), 400

    conn = get_db()
    cursor = conn.cursor()

    salt = secrets.token_hex(16)
    password_hash = generate_password_hash(password + salt)

    try:
        cursor.execute(
            'INSERT INTO users (username, password, salt, is_admin) VALUES (?, ?, ?, ?)',
            (username, password_hash, salt, 1 if is_admin else 0)
        )
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': f'用户 {username} 添加成功'})
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'success': False, 'error': '用户名已存在'}), 400


@app.route('/api/domains', methods=['GET'])
@login_required
def get_domains():
    # 所有用户共享域名列表
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM domains ORDER BY sort_order ASC, created_at DESC
    ''')
    domains = cursor.fetchall()
    conn.close()

    result = []

    for domain in domains:
        # 实时检查证书
        check_result = check_cert_expiry(domain['domain_name'], domain['target_type'], domain['target_value'])

        if check_result['success']:
            expiry_date = check_result['expiry_date']
            start_date = check_result['start_date']
            subject_cn = check_result.get('subject_cn')
            subject_o = check_result.get('subject_o')
            subject_ou = check_result.get('subject_ou')
            issuer_cn = check_result.get('issuer_cn')
            issuer_o = check_result.get('issuer_o')
            issuer_ou = check_result.get('issuer_ou')
            days_remaining = check_result['days_remaining']

            # 根据证书的实际有效期计算剩余比例
            total_valid_days = (expiry_date - start_date).days if expiry_date and start_date else 365
            if total_valid_days > 0:
                percentage = max(0, min(100, (days_remaining / total_valid_days) * 100))
            else:
                percentage = 0

            status = check_result['status']
        else:
            expiry_date = None
            start_date = None
            subject_cn = None
            subject_o = None
            subject_ou = None
            issuer_cn = None
            issuer_o = None
            issuer_ou = None
            days_remaining = None
            percentage = 0
            status = check_result['status']

        result.append({
            'id': domain['id'],
            'domain_name': domain['domain_name'],
            'target_type': domain['target_type'],
            'target_value': domain['target_value'],
            'expiry_date': expiry_date,
            'start_date': start_date,
            'subject_cn': subject_cn,
            'subject_o': subject_o,
            'subject_ou': subject_ou,
            'issuer_cn': issuer_cn,
            'issuer_o': issuer_o,
            'issuer_ou': issuer_ou,
            'days_remaining': days_remaining,
            'percentage': percentage,
            'status': status,
            'created_at': domain['created_at']
        })

    return jsonify(result)


@app.route('/api/domains', methods=['POST'])
@login_required
@admin_required
def add_domain():
    data = request.json
    domain_name = data.get('domain_name')
    target_type = data.get('target_type', 'dns')
    target_value = data.get('target_value', '')

    if not domain_name:
        return jsonify({'success': False, 'error': '域名不能为空'}), 400

    domain_name_clean = domain_name.strip().lower()

    conn = get_db()
    cursor = conn.cursor()

    # 检查是否已存在完全相同的配置（域名 + target_type + target_value）
    target_value_clean = target_value.strip() if target_value else ''
    cursor.execute('''
        SELECT id FROM domains
        WHERE LOWER(TRIM(domain_name)) = ?
        AND target_type = ?
        AND (target_value = ? OR (target_value IS NULL AND ? = ''))
    ''', (domain_name_clean, target_type, target_value_clean, target_value_clean))
    existing = cursor.fetchone()

    if existing:
        conn.close()
        return jsonify({'success': False, 'error': f'该域名配置已存在'}), 400

    # 获取当前最大的 sort_order
    cursor.execute('SELECT MAX(sort_order) FROM domains')
    max_order = cursor.fetchone()[0] or 0
    new_order = max_order + 1

    cursor.execute(
        'INSERT INTO domains (domain_name, target_type, target_value, sort_order) VALUES (?, ?, ?, ?)',
        (domain_name.strip(), target_type, target_value.strip() if target_value else None, new_order)
    )
    domain_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return jsonify({'success': True, 'domain_id': domain_id})


@app.route('/api/domains/reorder', methods=['POST'])
@login_required
@admin_required
def reorder_domains():
    """更新域名排序顺序（仅管理员）"""
    try:
        data = request.json
        order_list = data.get('order', [])

        print(f'[DEBUG] 收到排序请求: {order_list}')

        if not isinstance(order_list, list):
            return jsonify({'success': False, 'error': '无效的排序数据'}), 400

        conn = get_db()
        cursor = conn.cursor()

        for index, domain_id in enumerate(order_list):
            cursor.execute('UPDATE domains SET sort_order = ? WHERE id = ?',
                         (index, domain_id))
            print(f'[DEBUG] 更新域名 {domain_id} 的排序为 {index}')

        conn.commit()

        # 验证更新结果
        cursor.execute('SELECT id, domain_name, sort_order FROM domains ORDER BY sort_order ASC')
        result = cursor.fetchall()
        print(f'[DEBUG] 更新后的排序: {[(r[0], r[1], r[2]) for r in result]}')

        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        print(f'[ERROR] 排序失败: {e}')
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/domains/<int:domain_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_domain(domain_id):
    """删除域名（仅管理员）"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('DELETE FROM domains WHERE id = ?', (domain_id,))
    conn.commit()
    conn.close()

    return jsonify({'success': True})


@app.route('/api/domains/check-all', methods=['POST'])
@login_required
def check_all_domains():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM domains')
    domains = cursor.fetchall()
    conn.close()

    results = []
    for domain in domains:
        check_result = check_cert_expiry(domain['domain_name'], domain['target_type'], domain['target_value'])

        results.append({
            'domain_id': domain['id'],
            'domain_name': domain['domain_name'],
            'status': check_result.get('status', 'error'),
            'success': check_result['success']
        })

    return jsonify({'success': True, 'results': results})


if __name__ == '__main__':
    init_db()
    host = os.getenv('HOST', '0.0.0.0')
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('DEBUG', 'False').lower() == 'true'
    app.run(host=host, port=port, debug=debug)