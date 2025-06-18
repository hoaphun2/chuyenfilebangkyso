import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
import base64
from werkzeug.utils import secure_filename
import hashlib
import uuid
import json
from functools import wraps
import secrets # Để tạo mã bảo mật ngẫu nhiên

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SECRET_KEY'] = 'mot_chuoi_bi_mat_rat_bao_mat_cua_ban_va_dac_biet_ngau_nhien' # RẤT QUAN TRỌNG: Thay đổi chuỗi này bằng một chuỗi ngẫu nhiên mạnh
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Giới hạn file tải lên 16MB

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# --- Quản lý Khóa RSA ---
PRIVATE_KEY_FILE = 'server_private_key.pem'
PUBLIC_KEY_FILE = 'server_public_key.pem'

def generate_keys():
    if not os.path.exists(PRIVATE_KEY_FILE) or not os.path.exists(PUBLIC_KEY_FILE):
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        with open(PRIVATE_KEY_FILE, 'wb') as f:
            f.write(private_key)
        with open(PUBLIC_KEY_FILE, 'wb') as f:
            f.write(public_key)
        print("Đã tạo cặp khóa RSA mới.")
    else:
        print("Cặp khóa RSA đã tồn tại.")

def load_private_key():
    try:
        with open(PRIVATE_KEY_FILE, 'rb') as f:
            return RSA.import_key(f.read())
    except FileNotFoundError:
        print(f"Lỗi: Không tìm thấy file khóa riêng tư tại '{PRIVATE_KEY_FILE}'. Vui lòng chạy lại app để tạo khóa.")
        exit(1)

def load_public_key():
    try:
        with open(PUBLIC_KEY_FILE, 'rb') as f:
            return RSA.import_key(f.read())
    except FileNotFoundError:
        print(f"Lỗi: Không tìm thấy file khóa công khai tại '{PUBLIC_KEY_FILE}'.")
        return None

generate_keys()
private_key = load_private_key()
public_key = load_public_key()

# --- Quản lý người dùng đơn giản (lưu trong file JSON, sử dụng SHA256) ---
USERS_FILE = 'users_flask.json'

def hash_password_sha256(password):
    """Băm mật khẩu sử dụng SHA256, giống như trong server.py của bạn."""
    return hashlib.sha256(password.encode()).hexdigest()

def generate_security_code():
    """Tạo một mã bảo mật ngẫu nhiên (ví dụ: 16 ký tự hex)."""
    return secrets.token_hex(8) # Tạo chuỗi 16 ký tự hex (8 bytes)

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, indent=4)

users_db = load_users()

# --- Chức năng Ký số và Xác minh ---
def sign_file(filepath):
    with open(filepath, 'rb') as f:
        file_hash = SHA256.new(f.read())
    signer = pkcs1_15.new(private_key)
    signature = signer.sign(file_hash)
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(filepath, signature_b64):
    with open(filepath, 'rb') as f:
        file_hash = SHA256.new(f.read())
    try:
        verifier = pkcs1_15.new(public_key)
        verifier.verify(file_hash, base64.b64decode(signature_b64))
        return True
    except (ValueError, TypeError):
        return False

# --- Decorator để yêu cầu đăng nhập ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Vui lòng đăng nhập để truy cập trang này.', 'warning')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# --- Routes của Flask ---
@app.route('/')
def index():
    if 'username' not in session:
        return render_template('index.html', logged_in=False)

    files_info = []
    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
        if filename.endswith('.signature'):
            continue

        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        signature_filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename + '.signature')

        has_signature = False
        if os.path.exists(signature_filepath):
            with open(signature_filepath, 'r') as f:
                signature_b64 = f.read()
            has_signature = verify_signature(filepath, signature_b64)

        files_info.append({
            'name': filename,
            'has_signature': has_signature
        })

    files_info.sort(key=lambda x: x['name'].lower())

    # Lấy danh sách người dùng (ngoại trừ người dùng hiện tại) để hiển thị trong mục "Người nhận"
    recipients = []
    for user_name, user_data in users_db.items():
        if user_name != session['username']: # Không cho phép gửi cho chính mình
            recipients.append({'username': user_name, 'security_code': user_data.get('security_code', 'N/A')})
    recipients.sort(key=lambda x: x['username'].lower())

    sample_received_files = [
        {'name': 'Data_B.txt', 'sender': 'Nguyễn Văn B', 'hash': '18af1370b4d03477cf45...', 'signature': 'b\'x8fj\\ny\\fXfbm\\xbaB#pg^e\\x96\\xd4P&Z\\x8b\'...'},
        {'name': 'Report_C.pdf', 'sender': 'Trần Thị C', 'hash': 'abcde1234567890abcde...', 'signature': 'xyz123abc456def789ghi...'},
    ]
    sample_sent_files = [
        {'name': 'MyDoc.docx', 'receiver': 'Đinh Quang D', 'hash': 'def1237890abcdef1234...', 'signature': 'pqr789mno123uvw456xyz...'},
        {'name': 'Image.jpg', 'receiver': 'Lê Thị E', 'hash': '456fghjkl09876543210...', 'signature': '123asdfghjklmnbvcxzq...'},
    ]

    return render_template('index.html',
                           logged_in=True,
                           username=session['username'],
                           files=files_info,
                           recipients=recipients, # Truyền danh sách người nhận vào template
                           security_code=users_db[session['username']].get('security_code', 'Không có'), # Hiển thị mã bảo mật của người dùng hiện tại
                           received_files=sample_received_files,
                           sent_files=sample_sent_files)

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']

    if not username or not password:
        flash('Tên người dùng và mật khẩu không được để trống.', 'error')
        return redirect(url_for('index', from_auth='register_error'))

    if username in users_db:
        flash('Tên người dùng đã tồn tại. Vui lòng chọn tên khác.', 'error')
        return redirect(url_for('index', from_auth='register_error'))

    hashed_password = hash_password_sha256(password)
    security_code = generate_security_code() # Tạo mã bảo mật
    users_db[username] = {
        'password': hashed_password,
        'security_code': security_code
    }
    save_users(users_db)
    flash('Đăng ký thành công! Bạn có thể đăng nhập ngay bây giờ.', 'success')
    return redirect(url_for('index'))

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    if not username or not password:
        flash('Vui lòng nhập tên người dùng và mật khẩu.', 'error')
        return redirect(url_for('index', from_auth='login_error'))

    hashed_input_password = hash_password_sha256(password)
    if username not in users_db or users_db[username]['password'] != hashed_input_password:
        flash('Tên người dùng hoặc mật khẩu không đúng.', 'error')
        return redirect(url_for('index', from_auth='login_error'))

    session['username'] = username
    flash(f'Chào mừng, {username}!', 'success')
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Bạn đã đăng xuất.', 'info')
    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('Không có file nào được chọn để tải lên.', 'error')
        return redirect(request.url)

    file = request.files['file']

    if file.filename == '':
        flash('Chưa chọn file nào.', 'warning')
        return redirect(request.url)

    if file:
        original_filename = secure_filename(file.filename)
        file_extension = original_filename.rsplit('.', 1)[1] if '.' in original_filename else ''
        unique_filename = f"{uuid.uuid4().hex}.{file_extension}" if file_extension else uuid.uuid4().hex

        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(filepath)

        signature = sign_file(filepath)
        signature_filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename + '.signature')
        with open(signature_filepath, 'w') as f:
            f.write(signature)

        flash(f'File "{original_filename}" đã được tải lên và ký số thành công với tên mới: "{unique_filename}"!', 'success')
        return redirect(url_for('index'))

    flash('Có lỗi xảy ra khi tải lên file.', 'error')
    return redirect(url_for('index'))

@app.route('/download/<filename>')
@login_required
def download_file(filename):
    filename = secure_filename(filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    signature_filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename + '.signature')

    if not os.path.exists(filepath):
        flash(f'File "{filename}" không tồn tại.', 'error')
        return redirect(url_for('index'))

    signature_valid = False
    if os.path.exists(signature_filepath):
        with open(signature_filepath, 'r') as f:
            signature_b64 = f.read()
        signature_valid = verify_signature(filepath, signature_b64)

    if signature_valid:
        flash(f'File "{filename}" đã được tải xuống. Chữ ký số HỢP LỆ.', 'success')
    else:
        flash(f'File "{filename}" đã được tải xuống. Chữ ký số KHÔNG HỢP LỆ hoặc không tồn tại. File có thể đã bị thay đổi!', 'error')

    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/get_public_key')
def get_public_key():
    return send_from_directory('.', PUBLIC_KEY_FILE, as_attachment=True)

@app.route('/delete/<filename>', methods=['POST'])
@login_required
def delete_file(filename):
    filename = secure_filename(filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    signature_filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename + '.signature')

    if os.path.exists(filepath):
        try:
            os.remove(filepath)
            if os.path.exists(signature_filepath):
                os.remove(signature_filepath)
            flash(f'File "{filename}" và chữ ký đã được xóa thành công.', 'success')
        except OSError as e:
            flash(f'Lỗi khi xóa file "{filename}": {e}', 'error')
    else:
        flash(f'File "{filename}" không tồn tại.', 'warning')
    return redirect(url_for('index'))

@app.errorhandler(413)
def too_large(e):
    flash("Kích thước file quá lớn. Vui lòng tải lên file nhỏ hơn 16MB.", "error")
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)