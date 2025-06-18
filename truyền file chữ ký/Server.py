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
import secrets
from datetime import datetime

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SECRET_KEY'] = 'mot_chuoi_bi_mat_rat_bao_mat_cua_ban_va_dac_biet_ngau_nhien' # Thay đổi chuỗi này thành một chuỗi ngẫu nhiên mạnh
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 # Giới hạn kích thước file 16MB

# Tạo thư mục uploads nếu chưa tồn tại
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# --- Quản lý Khóa RSA ---
PRIVATE_KEY_FILE = 'server_private_key.pem'
PUBLIC_KEY_FILE = 'server_public_key.pem'

def generate_keys():
    """Tạo cặp khóa RSA nếu chúng chưa tồn tại."""
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
    """Tải khóa riêng tư của server."""
    try:
        with open(PRIVATE_KEY_FILE, 'rb') as f:
            return RSA.import_key(f.read())
    except FileNotFoundError:
        print(f"Lỗi: Không tìm thấy file khóa riêng tư tại '{PRIVATE_KEY_FILE}'. Vui lòng chạy lại app để tạo khóa.")
        exit(1)

def load_public_key():
    """Tải khóa công khai của server."""
    try:
        with open(PUBLIC_KEY_FILE, 'rb') as f:
            return RSA.import_key(f.read())
    except FileNotFoundError:
        print(f"Lỗi: Không tìm thấy file khóa công khai tại '{PUBLIC_KEY_FILE}'.")
        return None

# Gọi hàm để đảm bảo khóa được tạo khi khởi động server
generate_keys()
private_key = load_private_key()
public_key = load_public_key()

# --- Quản lý người dùng và Metadata file (lưu trong file JSON) ---
USERS_FILE = 'users_flask.json'
FILES_METADATA_FILE = 'files_metadata.json'
SENT_FILES_HISTORY_FILE = 'sent_files_history.json'

def hash_password_sha256(password):
    """Băm mật khẩu bằng SHA256."""
    return hashlib.sha256(password.encode()).hexdigest()

def generate_user_security_code():
    """Tạo mã bảo mật cá nhân ngẫu nhiên cho người dùng mới."""
    return secrets.token_hex(8) # Tạo một chuỗi hex ngẫu nhiên độ dài 8 byte (16 ký tự)

def load_users():
    """Tải dữ liệu người dùng từ file JSON."""
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_users(users):
    """Lưu dữ liệu người dùng vào file JSON."""
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, indent=4, ensure_ascii=False) # ensure_ascii=False để hỗ trợ tiếng Việt

users_db = load_users()

def load_files_metadata():
    """Tải metadata file từ file JSON."""
    if os.path.exists(FILES_METADATA_FILE):
        with open(FILES_METADATA_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_files_metadata(metadata):
    """Lưu metadata file vào file JSON."""
    with open(FILES_METADATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=4, ensure_ascii=False)

files_metadata_db = load_files_metadata()

def load_sent_files_history():
    """Tải lịch sử gửi file từ file JSON."""
    if os.path.exists(SENT_FILES_HISTORY_FILE):
        with open(SENT_FILES_HISTORY_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return [] # Trả về list vì mỗi lần gửi là một entry

def save_sent_files_history(history):
    """Lưu lịch sử gửi file vào file JSON."""
    with open(SENT_FILES_HISTORY_FILE, 'w', encoding='utf-8') as f:
        json.dump(history, f, indent=4, ensure_ascii=False)

sent_files_history_db = load_sent_files_history()

# --- Chức năng Ký số và Xác minh ---
def sign_file(filepath):
    """Ký số một file bằng khóa riêng tư của server."""
    with open(filepath, 'rb') as f:
        file_hash = SHA256.new(f.read())
    signer = pkcs1_15.new(private_key)
    signature = signer.sign(file_hash)
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(filepath, signature_b64):
    """Xác minh chữ ký số của một file bằng khóa công khai của server."""
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
    """Decorator kiểm tra xem người dùng đã đăng nhập chưa."""
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
    """Render trang chính của ứng dụng."""
    if 'username' not in session:
        return render_template('index.html', logged_in=False)

    current_username = session['username']

    # Lấy thông tin file đã upload bởi người dùng hiện tại
    uploaded_files_info = []
    for unique_filename, metadata in files_metadata_db.items():
        if metadata['uploader'] == current_username:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            signature_filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename + '.signature')

            has_signature = False
            if os.path.exists(filepath) and os.path.exists(signature_filepath):
                try:
                    with open(signature_filepath, 'r') as f:
                        signature_b64 = f.read()
                    has_signature = verify_signature(filepath, signature_b64)
                except Exception as e:
                    print(f"Lỗi khi xác minh chữ ký cho {unique_filename}: {e}")
                    has_signature = False # Đảm bảo trạng thái là false nếu có lỗi
            else:
                # Nếu file hoặc chữ ký không tồn tại, coi như không có chữ ký hợp lệ
                has_signature = False


            uploaded_files_info.append({
                'unique_name': unique_filename,
                'original_name': metadata.get('original_name', unique_filename),
                'has_signature': has_signature,
                'file_security_code': metadata.get('file_security_code', 'N/A')
            })

    uploaded_files_info.sort(key=lambda x: x['original_name'].lower())

    # Lấy danh sách người dùng (ngoại trừ người dùng hiện tại)
    recipients = []
    for user_name, user_data in users_db.items():
        if user_name != current_username:
            recipients.append({'username': user_name, 'security_code': user_data.get('security_code', 'N/A')})
    recipients.sort(key=lambda x: x['username'].lower())

    # Lịch sử file nhận được
    received_files_display = []
    for entry in sent_files_history_db:
        if entry['receiver'] == current_username:
            original_file_metadata = files_metadata_db.get(entry['unique_filename'])
            original_name = original_file_metadata.get('original_name', entry['unique_filename']) if original_file_metadata else "Tệp không tồn tại"
            
            received_files_display.append({
                'id': entry['id'],
                'original_name': original_name,
                'sender': entry['sender'],
                'sent_date': datetime.fromisoformat(entry['sent_date']).strftime('%H:%M %d/%m/%Y'),
                'status': entry['status'],
                'unique_filename': entry['unique_filename']
            })
    received_files_display.sort(key=lambda x: x['sent_date'], reverse=True)


    # Lịch sử file đã gửi
    sent_files_display = []
    for entry in sent_files_history_db:
        if entry['sender'] == current_username:
            original_file_metadata = files_metadata_db.get(entry['unique_filename'])
            original_name = original_file_metadata.get('original_name', entry['unique_filename']) if original_file_metadata else "Tệp không tồn tại"

            sent_files_display.append({
                'id': entry['id'],
                'original_name': original_name,
                'receiver': entry['receiver'],
                'sent_date': datetime.fromisoformat(entry['sent_date']).strftime('%H:%M %d/%m/%Y'),
                'sent_security_code': entry['sent_security_code'],
                'status': entry['status']
            })
    sent_files_display.sort(key=lambda x: x['sent_date'], reverse=True)


    return render_template('index.html',
                           logged_in=True,
                           username=current_username,
                           uploaded_files=uploaded_files_info,
                           recipients=recipients,
                           user_security_code=users_db[current_username].get('security_code', 'Không có'),
                           received_files=received_files_display,
                           sent_files=sent_files_display)

@app.route('/register', methods=['POST'])
def register():
    """Xử lý yêu cầu đăng ký người dùng mới."""
    username = request.form['username'].strip()
    password = request.form['password'].strip()

    if not username or not password:
        flash('Tên người dùng và mật khẩu không được để trống.', 'error')
        return redirect(url_for('index', from_auth='register_error'))

    if username in users_db:
        flash('Tên người dùng đã tồn tại. Vui lòng chọn tên khác.', 'error')
        return redirect(url_for('index', from_auth='register_error'))

    hashed_password = hash_password_sha256(password)
    user_security_code = generate_user_security_code()
    users_db[username] = {
        'password': hashed_password,
        'security_code': user_security_code
    }
    save_users(users_db)
    flash('Đăng ký thành công! Bạn có thể đăng nhập ngay bây giờ.', 'success')
    return redirect(url_for('index'))

@app.route('/login', methods=['POST'])
def login():
    """Xử lý yêu cầu đăng nhập người dùng."""
    username = request.form['username'].strip()
    password = request.form['password'].strip()

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
    """Xử lý yêu cầu đăng xuất người dùng."""
    session.pop('username', None)
    flash('Bạn đã đăng xuất.', 'info')
    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    """Xử lý tải file lên server."""
    if 'file' not in request.files:
        flash('Không có file nào được chọn để tải lên.', 'error')
        return redirect(request.url)

    file = request.files['file']
    file_security_code = request.form.get('file_security_code', '').strip()

    if file.filename == '':
        flash('Chưa chọn file nào.', 'warning')
        return redirect(request.url)

    if not file_security_code:
        flash('Vui lòng nhập mã bảo mật cho tệp.', 'error')
        return redirect(request.url)
    
    if not file_security_code.isalnum() or len(file_security_code) < 4:
        flash('Mã bảo mật tệp phải là chữ hoặc số và có ít nhất 4 ký tự.', 'error')
        return redirect(request.url)

    if file:
        original_filename = secure_filename(file.filename)
        # Tạo tên file duy nhất để tránh trùng lặp
        file_extension = original_filename.rsplit('.', 1)[1] if '.' in original_filename else ''
        unique_filename = f"{uuid.uuid4().hex}.{file_extension}" if file_extension else uuid.uuid4().hex

        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(filepath)

        # Ký số file sau khi lưu
        signature = sign_file(filepath)
        signature_filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename + '.signature')
        with open(signature_filepath, 'w') as f:
            f.write(signature)

        # Lưu metadata file vào DB
        files_metadata_db[unique_filename] = {
            'original_name': original_filename,
            'uploader': session['username'],
            'upload_time': datetime.now().isoformat(),
            'file_security_code': file_security_code
        }
        save_files_metadata(files_metadata_db)

        flash(f'File "{original_filename}" đã được tải lên và ký số thành công! Mã bảo mật của file: **{file_security_code}**', 'success')
        return redirect(url_for('index'))

    flash('Có lỗi xảy ra khi tải lên file.', 'error')
    return redirect(url_for('index'))

@app.route('/download/<unique_filename>', methods=['POST'])
@login_required
def download_file(unique_filename):
    """Xử lý tải file tự upload của người dùng, yêu cầu mã bảo mật."""
    file_metadata = files_metadata_db.get(unique_filename)
    if not file_metadata:
        flash('File không tồn tại.', 'error')
        return redirect(url_for('index'))

    # Chỉ người tải lên mới có thể tải xuống file của họ qua route này
    if file_metadata['uploader'] != session['username']:
        flash('Bạn không có quyền tải xuống file này.', 'error')
        return redirect(url_for('index'))

    submitted_code = request.form.get('security_code', '').strip()
    required_code = file_metadata.get('file_security_code')

    if not submitted_code or submitted_code != required_code:
        flash('Mã bảo mật không đúng. Vui lòng thử lại.', 'error')
        return redirect(url_for('index'))
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    signature_filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename + '.signature')

    signature_valid = False
    if os.path.exists(filepath) and os.path.exists(signature_filepath):
        with open(signature_filepath, 'r') as f:
            signature_b64 = f.read()
        signature_valid = verify_signature(filepath, signature_b64)

    if signature_valid:
        flash(f'File "{file_metadata["original_name"]}" đã được tải xuống. Chữ ký số HỢP LỆ.', 'success')
    else:
        flash(f'File "{file_metadata["original_name"]}" đã được tải xuống. Chữ ký số KHÔNG HỢP LỆ hoặc không tồn tại. File có thể đã bị thay đổi!', 'error')

    return send_from_directory(app.config['UPLOAD_FOLDER'], unique_filename, as_attachment=True, download_name=file_metadata['original_name'])

@app.route('/send_file', methods=['POST'])
@login_required
def send_file_to_other():
    """Xử lý gửi file cho người dùng khác với mã bảo mật riêng."""
    selected_unique_filename = request.form.get('file_to_send')
    recipient_username = request.form.get('recipient')
    sent_security_code = request.form.get('sent_security_code', '').strip()

    if not selected_unique_filename or not recipient_username or not sent_security_code:
        flash('Vui lòng chọn file, người nhận và nhập mã bảo mật để gửi.', 'error')
        return redirect(url_for('index'))

    if not sent_security_code.isalnum() or len(sent_security_code) < 4:
        flash('Mã bảo mật gửi phải là chữ hoặc số và có ít nhất 4 ký tự.', 'error')
        return redirect(url_for('index'))


    file_metadata = files_metadata_db.get(selected_unique_filename)
    if not file_metadata or file_metadata['uploader'] != session['username']:
        flash('File bạn muốn gửi không tồn tại hoặc không thuộc quyền sở hữu của bạn.', 'error')
        return redirect(url_for('index'))

    if recipient_username not in users_db:
        flash('Người nhận không tồn tại.', 'error')
        return redirect(url_for('index'))
    
    if recipient_username == session['username']:
        flash('Bạn không thể tự gửi file cho chính mình.', 'warning')
        return redirect(url_for('index'))

    new_sent_entry = {
        'id': str(uuid.uuid4()), # ID duy nhất cho giao dịch gửi này
        'unique_filename': selected_unique_filename,
        'sender': session['username'],
        'receiver': recipient_username,
        'sent_date': datetime.now().isoformat(),
        'sent_security_code': sent_security_code,
        'status': 'pending'
    }
    sent_files_history_db.append(new_sent_entry)
    save_sent_files_history(sent_files_history_db)

    flash(f'Đã gửi file "{file_metadata["original_name"]}" tới {recipient_username} với mã bảo mật: **{sent_security_code}**', 'success')
    return redirect(url_for('index'))


@app.route('/download_sent_file/<sent_id>', methods=['GET', 'POST'])
@login_required
def download_sent_file(sent_id):
    """Xử lý tải file được gửi từ người khác, yêu cầu mã bảo mật của giao dịch gửi."""
    sent_entry = next((entry for entry in sent_files_history_db if entry['id'] == sent_id), None)

    if not sent_entry:
        flash('Giao dịch gửi file không tồn tại.', 'error')
        return redirect(url_for('index'))

    if sent_entry['receiver'] != session['username']:
        flash('Bạn không có quyền tải xuống file này.', 'error')
        return redirect(url_for('index'))

    file_metadata = files_metadata_db.get(sent_entry['unique_filename'])
    if not file_metadata:
        flash(f'File gốc của giao dịch này không tồn tại trên hệ thống. (ID: {sent_id})', 'error')
        sent_entry['status'] = 'file_not_found'
        save_sent_files_history(sent_files_history_db)
        return redirect(url_for('index'))

    if request.method == 'POST':
        submitted_code = request.form.get('security_code', '').strip()
        required_code = sent_entry.get('sent_security_code')

        if not submitted_code or submitted_code != required_code:
            flash('Mã bảo mật không đúng. Vui lòng thử lại.', 'error')
            return redirect(url_for('index'))

        filepath = os.path.join(app.config['UPLOAD_FOLDER'], sent_entry['unique_filename'])
        signature_filepath = os.path.join(app.config['UPLOAD_FOLDER'], sent_entry['unique_filename'] + '.signature')

        signature_valid = False
        if os.path.exists(filepath) and os.path.exists(signature_filepath):
            try:
                with open(signature_filepath, 'r') as f:
                    signature_b64 = f.read()
                signature_valid = verify_signature(filepath, signature_b64)
            except Exception as e:
                print(f"Lỗi khi xác minh chữ ký cho {sent_entry['unique_filename']}: {e}")
                signature_valid = False
        else:
            signature_valid = False

        # Cập nhật trạng thái của giao dịch gửi là đã nhận
        sent_entry['status'] = 'received'
        save_sent_files_history(sent_files_history_db)

        if signature_valid:
            flash(f'File "{file_metadata["original_name"]}" đã được tải xuống. Chữ ký số HỢP LỆ.', 'success')
        else:
            flash(f'File "{file_metadata["original_name"]}" đã được tải xuống. Chữ ký số KHÔNG HỢP LỆ hoặc không tồn tại. File có thể đã bị thay đổi!', 'error')

        return send_from_directory(app.config['UPLOAD_FOLDER'], sent_entry['unique_filename'], as_attachment=True, download_name=file_metadata['original_name'])
    else:
        # GET request: chỉ hiển thị trang chủ với thông báo nhập mã
        flash(f'Vui lòng nhập mã bảo mật để tải xuống file "{file_metadata["original_name"]}" từ {sent_entry["sender"]}.', 'info')
        return redirect(url_for('index'))

@app.route('/delete/<unique_filename>', methods=['POST'])
@login_required
def delete_file(unique_filename):
    """Xử lý xóa file đã tải lên."""
    file_metadata = files_metadata_db.get(unique_filename)
    if not file_metadata or file_metadata['uploader'] != session['username']:
        flash('Bạn không có quyền xóa file này hoặc file không tồn tại.', 'error')
        return redirect(url_for('index'))

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    signature_filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename + '.signature')

    if os.path.exists(filepath):
        try:
            os.remove(filepath)
            if os.path.exists(signature_filepath):
                os.remove(signature_filepath)
            
            # Xóa metadata khỏi DB
            del files_metadata_db[unique_filename]
            save_files_metadata(files_metadata_db)

            # Cập nhật trạng thái các giao dịch gửi liên quan đến file này
            for entry in sent_files_history_db:
                if entry['unique_filename'] == unique_filename:
                    entry['status'] = 'sender_deleted'
            save_sent_files_history(sent_files_history_db)

            flash(f'File "{file_metadata["original_name"]}" và chữ ký đã được xóa thành công.', 'success')
        except OSError as e:
            flash(f'Lỗi khi xóa file "{file_metadata["original_name"]}": {e}', 'error')
    else:
        flash(f'File "{file_metadata["original_name"]}" không tồn tại trên hệ thống.', 'warning')
    return redirect(url_for('index'))

@app.route('/get_public_key')
def get_public_key():
    """Cho phép người dùng tải xuống khóa công khai của server."""
    return send_from_directory(os.getcwd(), PUBLIC_KEY_FILE, as_attachment=True)

@app.errorhandler(413)
def too_large(e):
    """Xử lý lỗi khi file tải lên quá lớn."""
    flash("Kích thước file quá lớn. Vui lòng tải lên file nhỏ hơn 16MB.", "error")
    return redirect(url_for('index'))

if __name__ == '__main__':
    # Đảm bảo các file JSON dữ liệu tồn tại khi khởi động app
    if not os.path.exists(FILES_METADATA_FILE):
        with open(FILES_METADATA_FILE, 'w', encoding='utf-8') as f:
            json.dump({}, f)
    if not os.path.exists(SENT_FILES_HISTORY_FILE):
        with open(SENT_FILES_HISTORY_FILE, 'w', encoding='utf-8') as f:
            json.dump([], f)
    if not os.path.exists(USERS_FILE):
         with open(USERS_FILE, 'w', encoding='utf-8') as f:
            json.dump({}, f)
            
    app.run(debug=True, host='0.0.0.0') # host='0.0.0.0' để truy cập từ mạng nội bộ