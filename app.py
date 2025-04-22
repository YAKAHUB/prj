from flask import Flask, request, send_file, render_template, redirect, url_for, flash, session, send_from_directory, jsonify
import os
import logging
import sqlite3
import secrets
import re
import tempfile
import time
import smtplib
import ssl
import traceback
from email.message import EmailMessage
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from converter import convert_file_input

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(32)
UPLOAD_FOLDER = 'Uploads'
OUTPUT_FOLDER = 'outputs'
DATABASE = 'users.db'

# Logging setup
log_file = '/var/www/flask-app/app.log' if os.path.exists('/var/www/flask-app') else os.path.join(
    os.path.dirname(__file__), 'app.log')
logging.basicConfig(
    level=logging.DEBUG,
    filename=log_file,
    format='%(asctime)s %(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)
logger.debug("Starting Flask app")

# Ensure directories
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# Supported conversions
SUPPORTED_CONVERSIONS = {
    'ttf': ['ttf', 'otf', 'woff', 'woff2'],
    'otf': ['ttf', 'otf', 'woff', 'woff2'],
    'woff': ['ttf', 'otf', 'woff', 'woff2'],
    'woff2': ['ttf', 'otf', 'woff', 'woff2'],
    'png': ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'webp', 'pdf'],
    'jpg': ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'webp', 'pdf'],
    'jpeg': ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'webp', 'pdf'],
    'gif': ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'webp', 'pdf'],
    'bmp': ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'webp', 'pdf'],
    'tiff': ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'webp', 'pdf'],
    'webp': ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'webp', 'pdf'],
    'pdf': ['png', 'jpg', 'jpeg', 'docx', 'txt'],
    'docx': ['docx', 'pdf', 'txt'],
    'txt': ['pdf', 'docx', 'md'],
    'odt': ['docx', 'txt'],
    'md': ['pdf', 'txt'],
    'mp3': ['mp3', 'wav', 'ogg', 'flac', 'aac', 'm4a'],
    'wav': ['mp3', 'wav', 'ogg', 'flac', 'aac', 'm4a'],
    'ogg': ['mp3', 'wav', 'ogg', 'flac', 'aac', 'm4a'],
    'flac': ['mp3', 'wav', 'ogg', 'flac', 'aac', 'm4a'],
    'aac': ['mp3', 'wav', 'ogg', 'flac', 'aac', 'm4a'],
    'm4a': ['mp3', 'wav', 'ogg', 'flac', 'aac', 'm4a'],
    'mp4': ['mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'webm'],
    'avi': ['mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'webm'],
    'mkv': ['mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'webm'],
    'mov': ['mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'webm'],
    'wmv': ['mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'webm'],
    'flv': ['mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'webm'],
    'webm': ['mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'webm'],
    'zip': ['zip', 'tar', 'gz', '7z'],
    'tar': ['zip', 'tar', 'gz', '7z'],
    'gz': ['zip', 'tar', 'gz', '7z'],
    '7z': ['zip', 'tar', 'gz', '7z'],
    'csv': ['csv', 'xls', 'xlsx', 'json', 'txt'],
    'xls': ['csv', 'xls', 'xlsx', 'json', 'txt'],
    'xlsx': ['csv', 'xls', 'xlsx', 'json', 'txt'],
    'json': ['csv', 'txt'],
    'xml': ['json', 'txt'],
}

# Database initialization
def init_db():
    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
            if not cursor.fetchone():
                conn.execute('''
                    CREATE TABLE users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL,
                        is_admin INTEGER DEFAULT 0,
                        is_verified INTEGER DEFAULT 1,
                        credits INTEGER DEFAULT 10
                    )
                ''')
                hashed_password = generate_password_hash('admin')
                conn.execute(
                    'INSERT INTO users (username, email, password, is_admin, is_verified, credits) VALUES (?, ?, ?, ?, ?, ?)',
                    ('admin', 'admin@noemail.com', hashed_password, 1, 1, 10))
                logger.debug("Created admin user")

            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='settings'")
            if not cursor.fetchone():
                conn.execute('''
                    CREATE TABLE settings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        mb_per_credit REAL DEFAULT 1.0,
                        usd_per_credit REAL DEFAULT 0.01
                    )
                ''')
                conn.execute('INSERT INTO settings (mb_per_credit, usd_per_credit) VALUES (?, ?)', (1.0, 0.01))
                logger.debug("Created settings table")

            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='otps'")
            if not cursor.fetchone():
                conn.execute('''
                    CREATE TABLE otps (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        otp_hash TEXT NOT NULL,
                        expires_at TIMESTAMP NOT NULL,
                        FOREIGN KEY (user_id) REFERENCES users(id)
                    )
                ''')
                logger.debug("Created otps table")
            conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Database init failed: {e}")
        raise

# Conversion rates
def get_conversion_rates():
    try:
        with sqlite3.connect(DATABASE) as conn:
            settings = conn.execute('SELECT mb_per_credit, usd_per_credit FROM settings WHERE id = 1').fetchone()
            return settings if settings else (1.0, 0.01)
    except sqlite3.Error as e:
        logger.error(f"Error fetching rates: {e}")
        return (1.0, 0.01)

# Check if user is admin
def get_user_is_admin(user_id):
    try:
        with sqlite3.connect(DATABASE) as conn:
            result = conn.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,)).fetchone()
            return bool(result[0]) if result else False
    except sqlite3.Error as e:
        logger.error(f"Error checking admin: {e}")
        return False

# Get user credits
def get_user_credits():
    if 'user_id' not in session:
        return None
    try:
        with sqlite3.connect(DATABASE) as conn:
            result = conn.execute('SELECT credits FROM users WHERE id = ?', (session['user_id'],)).fetchone()
            return result[0] if result else 0
    except sqlite3.Error as e:
        logger.error(f"Error fetching credits: {e}")
        return 0

app.jinja_env.globals.update(get_user_is_admin=get_user_is_admin, get_user_credits=get_user_credits)

# Login required decorator
def login_required(f):
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

# Admin required decorator
def admin_required(f):
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in.')
            return redirect(url_for('login'))
        if not get_user_is_admin(session['user_id']):
            flash('Admin access required.')
            return redirect(url_for('upload_file'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(app.static_folder, 'favicon.ico')

@app.route('/get_credits')
@login_required
def get_credits():
    credits = get_user_credits()
    return jsonify({'credits': credits})

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        if not username or not email or not password:
            flash('All fields are required.')
            return redirect(url_for('register'))

        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            flash('Invalid email address.')
            return redirect(url_for('register'))

        try:
            with sqlite3.connect(DATABASE) as conn:
                existing_email = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
                existing_username = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
                if existing_email:
                    flash('Email is already in use.')
                    return redirect(url_for('register'))
                if existing_username:
                    flash('Username already exists.')
                    return redirect(url_for('register'))
        except sqlite3.Error as e:
            logger.error(f"Registration check error: {e}")
            flash('Registration failed.')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        try:
            with sqlite3.connect(DATABASE) as conn:
                conn.execute(
                    'INSERT INTO users (username, email, password, is_verified, credits) VALUES (?, ?, ?, ?, ?)',
                    (username, email, hashed_password, 1, 10))
                conn.commit()
            logger.debug(f"User registered: {username}, {email}")
        except sqlite3.Error as e:
            logger.error(f"Register error: {e}")
            flash('Registration failed.')
            return redirect(url_for('register'))

        email_sender = 'fconvertz@gmail.com'
        email_password = os.getenv('EMAIL_PASSWORD', 'amddpfhiwyrmvdjb')
        email_receiver = email
        subject = 'Welcome to FileConvertz'
        body = f"""
Hello {username},

Your account has been successfully created. You can now log in and start converting files.

Best,
FileConvertz Team
"""
        em = EmailMessage()
        em['From'] = email_sender
        em['To'] = email_receiver
        em['Subject'] = subject
        em.set_content(body)

        context = ssl.create_default_context()
        try:
            logger.debug(f"Attempting to send email to {email}")
            with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
                smtp.login(email_sender, email_password)
                smtp.sendmail(email_sender, email_receiver, em.as_string())
            logger.debug(f"Sent email to {email}")
            flash('Registration successful! A welcome email has been sent.')
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"Email authentication failed: {str(e)}\n{traceback.format_exc()}")
            flash(f'Registration successful, but email sending failed: Authentication error - {str(e)}')
        except smtplib.SMTPException as e:
            logger.error(f"SMTP error: {str(e)}\n{traceback.format_exc()}")
            flash(f'Registration successful, but email sending failed: SMTP error - {str(e)}')
        except Exception as e:
            logger.error(f"Unexpected email error: {str(e)}\n{traceback.format_exc()}")
            flash(f'Registration successful, but email sending failed: Unexpected error - {str(e)}')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/recover_password', methods=['GET', 'POST'])
def recover_password():
    if request.method == 'POST':
        email = request.form['email']
        if not email:
            flash('Email is required.')
            return redirect(url_for('recover_password'))
        try:
            with sqlite3.connect(DATABASE) as conn:
                user = conn.execute('SELECT id, username FROM users WHERE email = ?', (email,)).fetchone()
                if not user:
                    flash('Invalid email.')
                    return redirect(url_for('recover_password'))
                user_id, username = user
                otp = str(secrets.randbelow(1000000)).zfill(6)  # 6-digit OTP
                otp_hash = generate_password_hash(otp)
                expires_at = datetime.utcnow() + timedelta(minutes=15)
                conn.execute('DELETE FROM otps WHERE user_id = ?', (user_id,))
                conn.execute(
                    'INSERT INTO otps (user_id, otp_hash, expires_at) VALUES (?, ?, ?)',
                    (user_id, otp_hash, expires_at)
                )
                conn.commit()
                logger.debug(f"Generated OTP for user_id: {user_id}")
                email_sender = 'fconvertz@gmail.com'
                email_password = os.getenv('EMAIL_PASSWORD', 'amddpfhiwyrmvdjb')
                email_receiver = email
                subject = 'Your FileConvertz One-Time Password'
                body = f"""
Hello {username},

You requested a one-time password (OTP) to reset your FileConvertz account password. Use the OTP below to proceed:

{otp}

This OTP will expire in 15 minutes. If you did not request this, ignore this email.

Best,
FileConvertz Team
"""
                em = EmailMessage()
                em['From'] = email_sender
                em['To'] = email_receiver
                em['Subject'] = subject
                em.set_content(body)
                context = ssl.create_default_context()
                try:
                    logger.debug(f"Attempting to send OTP email to {email}")
                    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
                        smtp.login(email_sender, email_password)
                        smtp.sendmail(email_sender, email_receiver, em.as_string())
                    logger.debug(f"Sent OTP email to {email}")
                    flash('A one-time password has been sent to your email.')
                    return redirect(url_for('verify_otp'))
                except smtplib.SMTPAuthenticationError as e:
                    logger.error(f"Email authentication failed: {str(e)}\n{traceback.format_exc()}")
                    flash(f'OTP could not be sent: Authentication error - {str(e)}')
                except smtplib.SMTPException as e:
                    logger.error(f"SMTP error: {str(e)}\n{traceback.format_exc()}")
                    flash(f'OTP could not be sent: SMTP error - {str(e)}')
                except smtplib.SMTPRecipientsRefused as e:
                    logger.error(f"Recipient refused: {str(e)}\n{traceback.format_exc()}")
                    flash(f'OTP could not be sent: Recipient refused - {str(e)}')
                except Exception as e:
                    logger.error(f"Unexpected email error: {str(e)}\n{traceback.format_exc()}")
                    flash(f'OTP could not be sent: Unexpected error - {str(e)}')
                return redirect(url_for('recover_password'))
        except sqlite3.Error as e:
            logger.error(f"Recovery error: {e}")
            flash('Error processing recovery request.')
            return redirect(url_for('recover_password'))
    return render_template('recover_password.html', is_logged_in='user_id' in session)

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        otp = request.form['otp']
        email = request.form['email']  # Email from hidden input
        if not otp or not email:
            flash('OTP and email are required.')
            return redirect(url_for('verify_otp'))
        try:
            with sqlite3.connect(DATABASE) as conn:
                user = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
                if not user:
                    flash('Invalid email.')
                    return redirect(url_for('verify_otp'))
                user_id = user[0]
                otp_record = conn.execute(
                    'SELECT user_id, otp_hash, expires_at FROM otps WHERE user_id = ?',
                    (user_id,)
                ).fetchone()
                if not otp_record:
                    flash('Invalid or expired OTP.')
                    return redirect(url_for('verify_otp'))
                otp_user_id, otp_hash, expires_at = otp_record
                expires_at = datetime.strptime(expires_at, '%Y-%m-%d %H:%M:%S.%f')
                if datetime.utcnow() > expires_at:
                    flash('OTP has expired.')
                    conn.execute('DELETE FROM otps WHERE user_id = ?', (user_id,))
                    conn.commit()
                    return redirect(url_for('verify_otp'))
                if check_password_hash(otp_hash, otp):
                    session['user_id'] = user_id
                    session['otp_verified'] = True
                    conn.execute('DELETE FROM otps WHERE user_id = ?', (user_id,))
                    conn.commit()
                    logger.debug(f"OTP verified for user_id: {user_id}")
                    flash('OTP verified. Please set a new password.')
                    return redirect(url_for('change_password'))
                else:
                    flash('Invalid OTP.')
        except sqlite3.Error as e:
            logger.error(f"OTP verification error: {e}")
            flash('Error verifying OTP.')
        return redirect(url_for('verify_otp'))
    return render_template('verify_otp.html')

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if not session.get('otp_verified') and not session.get('otp_login'):
        flash('Please verify OTP to change your password.')
        return redirect(url_for('recover_password'))
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if not password or not confirm_password:
            flash('Both password fields are required.')
            return redirect(url_for('change_password'))
        if password != confirm_password:
            flash('Passwords do not match.')
            return redirect(url_for('change_password'))
        try:
            with sqlite3.connect(DATABASE) as conn:
                hashed_password = generate_password_hash(password)
                conn.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_password, session['user_id']))
                conn.commit()
            logger.debug(f"Password changed for user_id: {session['user_id']}")
            session.pop('otp_verified', None)
            session.pop('otp_login', None)
            flash('Your password has been updated. Please log in.')
            return redirect(url_for('login'))
        except sqlite3.Error as e:
            logger.error(f"Password change error: {e}")
            flash('Error updating password.')
            return redirect(url_for('change_password'))
    return render_template('change_password.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form['username']
        password = request.form['password']
        if not identifier or not password:
            flash('Username/email and password are required.')
            return redirect(url_for('login'))
        try:
            with sqlite3.connect(DATABASE) as conn:
                user = conn.execute(
                    'SELECT id, password, is_admin FROM users WHERE username = ? OR email = ?',
                    (identifier, identifier)
                ).fetchone()
            if not user:
                flash('Username or email not found.')
                return redirect(url_for('login'))
            user_id, hashed_password, is_admin = user
            if check_password_hash(hashed_password, password):
                session['user_id'] = user_id
                session.pop('otp_verified', None)
                session.pop('otp_login', None)
                logger.debug(f"User logged in: {identifier}")
                flash('Logged in!')
                return redirect(url_for('admin_dashboard') if is_admin else url_for('upload_file'))
            else:
                flash('Invalid password.')
        except sqlite3.Error as e:
            logger.error(f"Login error: {e}")
            flash('Login failed.')
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('otp_verified', None)
    session.pop('otp_login', None)
    flash('Logged out.')
    return redirect(url_for('login'))

@app.route('/account')
@login_required
def account():
    try:
        with sqlite3.connect(DATABASE) as conn:
            user = conn.execute('SELECT username, email, credits FROM users WHERE id = ?',
                                (session['user_id'],)).fetchone()
        if user:
            if session.get('otp_verified') or session.get('otp_login'):
                flash('Please change your password before continuing.')
                return redirect(url_for('change_password'))
            return render_template('account.html', username=user[0], email=user[1] or 'No email', credits=user[2])
        flash('User not found.')
        return redirect(url_for('login'))
    except sqlite3.Error as e:
        logger.error(f"Account error: {e}")
        flash('Error fetching account.')
        return redirect(url_for('upload_file'))

@app.route('/', methods=['GET', 'POST'])
@login_required
def upload_file():
    if session.get('otp_verified') or session.get('otp_login'):
        flash('Please change your password before uploading files.')
        return redirect(url_for('change_password'))
    if request.method == 'POST':
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        if 'file' not in request.files:
            logger.error("No file uploaded")
            flash('No file uploaded.')
            if is_ajax:
                return jsonify({'success': False, 'message': 'No file uploaded.'}), 400
            return redirect(url_for('upload_file'))
        file = request.files['file']
        if file.filename == '':
            logger.error("No file selected")
            flash('No file selected.')
            if is_ajax:
                return jsonify({'success': False, 'message': 'No file selected.'}), 400
            return redirect(url_for('upload_file'))
        file.seek(0, os.SEEK_END)
        file_size_mb = file.tell() / (1024 * 1024)
        file.seek(0)
        if file_size_mb > 100:
            flash('File too large (max 100 MB).')
            if is_ajax:
                return jsonify({'success': False, 'message': 'File too large (max 100 MB).'}),
            return redirect(url_for('upload_file'))
        input_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        output_format = request.form.get('output_format', '').lower()
        if not output_format or input_ext not in SUPPORTED_CONVERSIONS or output_format not in SUPPORTED_CONVERSIONS.get(
                input_ext, []):
            flash('Unsupported conversion.')
            if is_ajax:
                return jsonify({'success': False, 'message': 'Unsupported conversion.'}), 400
            return redirect(url_for('upload_file'))
        mb_per_credit, _ = get_conversion_rates()
        required_credits = max(1, int(file_size_mb / mb_per_credit))
        try:
            with sqlite3.connect(DATABASE) as conn:
                user_credits = conn.execute('SELECT credits FROM users WHERE id = ?',
                                            (session['user_id'],)).fetchone()
                if not user_credits:
                    flash('User not found.')
                    if is_ajax:
                        return jsonify({'success': False, 'message': 'User not found.'}), 400
                    return redirect(url_for('upload_file'))
                user_credits = user_credits[0]
                if user_credits < required_credits:
                    flash(f'Not enough credits. Need: {required_credits}, Have: {user_credits}')
                    if is_ajax:
                        return jsonify({'success': False, 'message': f'Not enough credits. Need: {required_credits}, Have: {user_credits}'}), 400
                    return redirect(url_for('upload_file'))
        except sqlite3.Error as e:
            logger.error(f"Credit check error: {e}")
            flash('Error checking credits.')
            if is_ajax:
                return jsonify({'success': False, 'message': 'Error checking credits.'}), 500
            return redirect(url_for('upload_file'))
        safe_filename = ''.join(c for c in file.filename if c.isalnum() or c in ('.', '_', '-'))
        input_fd, input_path = tempfile.mkstemp(suffix=f'.{input_ext}', dir=UPLOAD_FOLDER)
        base_filename = os.path.splitext(safe_filename)[0]
        output_path = os.path.join(OUTPUT_FOLDER, f"{base_filename}.{output_format}")
        try:
            with os.fdopen(input_fd, 'wb') as f:
                file.save(f)
            logger.debug(f"Saved input file: {input_path}")
            logger.debug(f"Starting conversion: {input_path} to {output_path} ({input_ext} -> {output_format})")
            success = convert_file_input(input_path, output_path, input_ext, output_format)
            if not success:
                logger.error(f"Conversion failed for {input_path} to {output_path}")
                flash('Conversion failed.')
                if is_ajax:
                    return jsonify({'success': False, 'message': 'Conversion failed.'}), 500
                return redirect(url_for('upload_file'))
            actual_output_path = output_path
            if input_ext == 'pdf' and output_format in ['png', 'jpg', 'jpeg']:
                zip_path = os.path.join(OUTPUT_FOLDER, f"{base_filename}.zip")
                if os.path.exists(zip_path):
                    actual_output_path = zip_path
                    logger.debug(f"Multi-page PDF detected, serving ZIP: {actual_output_path}")
                elif not os.path.exists(actual_output_path):
                    logger.error(f"Output file not found at {actual_output_path} or {zip_path}")
                    flash('Conversion succeeded but output file is missing.')
                    if is_ajax:
                        return jsonify({'success': False, 'message': 'Conversion succeeded but output file is missing.'}), 500
                    return redirect(url_for('upload_file'))
            try:
                with sqlite3.connect(DATABASE) as conn:
                    conn.execute('UPDATE users SET credits = credits - ? WHERE id = ?',
                                 (required_credits, session['user_id']))
                    conn.commit()
                logger.debug(f"Deducted {required_credits} credits for user {session['user_id']}")
                if is_ajax:
                    with open(actual_output_path, 'rb') as f:
                        file_data = f.read()
                    import base64
                    file_b64 = base64.b64encode(file_data).decode('utf-8')
                    return jsonify({
                        'success': True,
                        'file_name': os.path.basename(actual_output_path),
                        'file_data': file_b64,
                        'credits': get_user_credits()
                    })
                response = send_file(actual_output_path, as_attachment=True,
                                     download_name=os.path.basename(actual_output_path))
                return response
            except sqlite3.Error as e:
                logger.error(f"Credit deduction error: {e}")
                flash(f'Conversion succeeded but failed to update credits: {str(e)}')
                if is_ajax:
                    return jsonify({'success': False, 'message': f'Conversion succeeded but failed to update credits: {str(e)}'}), 500
                return redirect(url_for('upload_file'))
        except Exception as e:
            logger.error(f"Conversion error: {str(e)}")
            flash(f'Error during conversion: {str(e)}')
            if is_ajax:
                return jsonify({'success': False, 'message': f'Error during conversion: {str(e)}'}), 500
            return redirect(url_for('upload_file'))
        finally:
            for _ in range(3):
                try:
                    if os.path.exists(input_path):
                        os.remove(input_path)
                        logger.debug(f"Cleaned up input file: {input_path}")
                    if os.path.exists(output_path) and output_path != actual_output_path:
                        os.remove(output_path)
                        logger.debug(f"Cleaned up output file: {output_path}")
                    if actual_output_path != output_path and os.path.exists(actual_output_path):
                        os.remove(actual_output_path)
                        logger.debug(f"Cleaned up actual output file: {actual_output_path}")
                    break
                except PermissionError as e:
                    logger.warning(f"PermissionError during cleanup, retrying: {e}")
                    time.sleep(1)
                except Exception as e:
                    logger.error(f"Cleanup error: {e}")
                    break
    return render_template('index.html', output_options=SUPPORTED_CONVERSIONS)

@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin_dashboard():
    if request.method == 'POST':
        action = request.form.get('action')
        try:
            with sqlite3.connect(DATABASE) as conn:
                if action == 'update_admin':
                    new_username = request.form.get('new_username', '').strip()
                    new_password = request.form.get('new_password', '').strip()
                    if not new_username or not new_password:
                        flash('Both username and password are required.')
                        return redirect(url_for('admin_dashboard'))
                    existing_username = conn.execute('SELECT id FROM users WHERE username = ? AND id != ?',
                                                     (new_username, session['user_id'])).fetchone()
                    if existing_username:
                        flash('Username already exists.')
                        return redirect(url_for('admin_dashboard'))
                    hashed_password = generate_password_hash(new_password)
                    conn.execute('UPDATE users SET username = ?, password = ? WHERE id = ?',
                                 (new_username, hashed_password, session['user_id']))
                    conn.commit()
                    logger.debug(f"Admin updated: username={new_username}")
                    flash('Admin credentials updated.')
                elif action == 'remove_user':
                    user_id = request.form['user_id']
                    conn.execute('DELETE FROM users WHERE id = ? AND is_admin = 0', (user_id,))
                    conn.commit()
                    logger.debug(f"User removed: {user_id}")
                    flash('User removed.')
                elif action == 'update_credits':
                    user_id = request.form['user_id']
                    credits = request.form['credits']
                    try:
                        credits = int(credits)
                        if credits < 0:
                            flash('Credits cannot be negative.')
                            return redirect(url_for('admin_dashboard'))
                        conn.execute('UPDATE users SET credits = ? WHERE id = ? AND is_admin = 0',
                                     (credits, user_id))
                        conn.commit()
                        logger.debug(f"Credits updated for user {user_id}: {credits}")
                        flash('Credits updated.')
                    except ValueError:
                        flash('Credits must be a valid number.')
                elif action == 'update_rates':
                    mb_per_credit = request.form['mb_per_credit']
                    usd_per_credit = request.form['usd_per_credit']
                    try:
                        mb_per_credit = float(mb_per_credit)
                        usd_per_credit = float(usd_per_credit)
                        if mb_per_credit <= 0 or usd_per_credit <= 0:
                            flash('Rates must be positive.')
                            return redirect(url_for('admin_dashboard'))
                        conn.execute('UPDATE settings SET mb_per_credit = ?, usd_per_credit = ? WHERE id = 1',
                                     (mb_per_credit, usd_per_credit))
                        conn.commit()
                        logger.debug(f"Rates updated: mb_per_credit={mb_per_credit}, usd_per_credit={usd_per_credit}")
                        flash('Rates updated.')
                    except ValueError:
                        flash('Rates must be valid numbers.')
                elif action == 'search_users':
                    search_query = request.form['search_query'].strip()
                    users = conn.execute(
                        'SELECT id, username, credits FROM users WHERE is_admin = 0 AND username LIKE ?',
                        (f'%{search_query}%',)).fetchall()
                    mb_per_credit, usd_per_credit = get_conversion_rates()
                    return render_template('admin.html', users=users, search_query=search_query,
                                           mb_per_credit=mb_per_credit, usd_per_credit=usd_per_credit)
        except sqlite3.Error as e:
            logger.error(f"Admin action error: {e}")
            flash(f'Action failed: {str(e)}')
    try:
        with sqlite3.connect(DATABASE) as conn:
            users = conn.execute('SELECT id, username, credits FROM users WHERE is_admin = 0').fetchall()
        mb_per_credit, usd_per_credit = get_conversion_rates()
    except sqlite3.Error as e:
        logger.error(f"Admin fetch error: {e}")
        users = []
        mb_per_credit, usd_per_credit = 1.0, 0.01
    return render_template('admin.html', users=users, search_query='',
                           mb_per_credit=mb_per_credit, usd_per_credit=usd_per_credit)

with app.app_context():
    init_db()

if __name__ == '__main__':
    app.run(debug=True)