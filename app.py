from flask import Flask, render_template, request, redirect, url_for, session, after_this_request
from flask_mail import Mail, Message
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
import random

# Initialize the Flask application
app = Flask(__name__)
app.secret_key = 'your_super_secret_key_here'  # Change this to a random, secure key

# Add the serializer for password reset tokens
s = URLSafeTimedSerializer(app.secret_key)

# Configure Flask-Mail
# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'victorfemi9145@gmail.com'
app.config['MAIL_PASSWORD'] = 'vccpbgvwhihvrdzj'  # No spaces!
app.config['MAIL_DEFAULT_SENDER'] = 'victorfemi9145@gmail.com'
mail = Mail(app)

# --- Global Handlers ---
@app.before_request
def check_cache():
    """Adds no-cache headers to protected routes."""
    protected_routes = ['dashboard', 'admin_dashboard']
    if request.endpoint in protected_routes:
        @after_this_request
        def add_no_cache_headers(response):
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
            return response

# --- Database Functions ---
def get_db_connection():
    """Establishes a connection to the SQLite database."""
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Creates the necessary tables in the database."""
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            matric_no TEXT UNIQUE NOT NULL,
            fullname TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            has_voted INTEGER DEFAULT 0,
            is_admin INTEGER DEFAULT 0,
            confirmation_code TEXT,
            is_verified INTEGER DEFAULT 0
        );
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS candidates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fullname TEXT NOT NULL,
            position TEXT NOT NULL,
            vote_count INTEGER DEFAULT 0
        );
    ''')
    conn.commit()
    conn.close()

def create_initial_admin():
    """Creates a default admin user if one doesn't exist."""
    conn = get_db_connection()
    admin_matric = "admin"
    admin_password = "password123"
    admin_email = "admin@school.edu"
    hashed_password = generate_password_hash(admin_password)

    existing_admin = conn.execute("SELECT * FROM users WHERE matric_no = ? AND is_admin = 1", (admin_matric,)).fetchone()
    if not existing_admin:
        conn.execute("INSERT INTO users (matric_no, fullname, email, password, is_admin, is_verified) VALUES (?, ?, ?, ?, 1, 1)",
                     (admin_matric, "Admin User", admin_email, hashed_password))
        conn.commit()
        print("Admin user created with matric_no 'admin' and password 'password123'")
    conn.close()

# --- Routes (Endpoints) ---

@app.route('/')
def home():
    """Renders the student login page."""
    return render_template('login.html')

@app.route('/register', methods=('GET', 'POST'))
def register():
    """Handles student registration and email verification."""
    if request.method == 'POST':
        matric_no = request.form['matric_no']
        fullname = request.form['fullname']
        email = request.form['email']
        password = request.form['password']

        # 1. Email Domain Validation
        required_domain = '@bouesti.edu.ng'
        if not email.endswith(required_domain):
            error = "Invalid school email. Please use your official university email."
            return render_template('register.html', error=error)

        hashed_password = generate_password_hash(password)
        confirmation_code = str(random.randint(100000, 999999))
        
        conn = get_db_connection()
        try:
            conn.execute("INSERT INTO users (matric_no, fullname, email, password, confirmation_code) VALUES (?, ?, ?, ?, ?)",
                         (matric_no, fullname, email, hashed_password, confirmation_code))
            conn.commit()

            # 2. Send Confirmation Email
            msg = Message("Secure Voting System - Account Verification", recipients=[email])
            msg.body = f"Hello {fullname},\n\nYour confirmation code is: {confirmation_code}\n\nUse this code to verify your account and complete your registration."
            mail.send(msg)

            # Redirect to a page where the user can enter the code
            return redirect(url_for('verify_email', email=email))

        except sqlite3.IntegrityError:
            error = "Matric number or email already registered. Please login or use a different email."
            return render_template('register.html', error=error)
        finally:
            conn.close()

    return render_template('register.html')

@app.route('/login', methods=('POST',))
def login():
    """Handles student login."""
    matric_no = request.form['matric_no']
    password = request.form['password']
    
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE matric_no = ?", (matric_no,)).fetchone()
    conn.close()
    
    if user and check_password_hash(user['password'], password) and user['is_verified'] == 1:
        session['matric_no'] = user['matric_no']
        return redirect(url_for('dashboard'))
    elif user and user['is_verified'] == 0:
        error = "Please verify your email address to log in."
        return render_template('login.html', error=error)
    else:
        error = "Invalid Matric Number or Password."
        return render_template('login.html', error=error)

@app.route('/verify_email', methods=('GET', 'POST'))
def verify_email():
    """Verifies the user's email with a confirmation code."""
    if request.method == 'POST':
        email = request.form['email']
        code_entered = request.form['code']
        
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE email = ? AND is_verified = 0", (email,)).fetchone()

        if user and user['confirmation_code'] == code_entered:
            conn.execute("UPDATE users SET is_verified = 1 WHERE email = ?", (email,))
            conn.commit()
            conn.close()
            return redirect(url_for('home'))
        else:
            error = "Invalid code or email. Please try again."
            conn.close()
            return render_template('verify_email.html', email=email, error=error)
    
    email = request.args.get('email')
    if not email:
        return redirect(url_for('home'))
        
    return render_template('verify_email.html', email=email)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """Handles password reset request by sending a reset link to the user's email."""
    if request.method == 'POST':
        identifier = request.form['identifier']
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE matric_no = ? OR email = ?", (identifier, identifier)).fetchone()
        conn.close()

        if user and user['is_verified'] == 1:
            try:
                token = s.dumps(user['email'], salt='password-reset-salt')
                reset_link = url_for('reset_password', token=token, _external=True)

                msg = Message('Password Reset Request', recipients=[user['email']])
                msg.body = f"Hello {user['fullname']},\n\n" \
                           f"We received a request to reset your password. Click the link below to set a new password:\n" \
                           f"{reset_link}\n\n" \
                           f"If you did not request a password reset, you can safely ignore this email.\n\n" \
                           f"The link is valid for a short time only."
                mail.send(msg)

                success_message = "A password reset link has been sent to your email address."
                return render_template('forgot_password.html', success=success_message)

            except Exception as e:
                error = "An error occurred while sending the email. Please try again later."
                return render_template('forgot_password.html', error=error)
        else:
            error = "User not found or email not verified."
            return render_template('forgot_password.html', error=error)

    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Handles the password reset form submission."""
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        return render_template('reset_password.html', error="The password reset link is invalid or has expired.")

    if request.method == 'POST':
        new_password = request.form['new_password']
        hashed_password = generate_password_hash(new_password)
        
        conn = get_db_connection()
        conn.execute("UPDATE users SET password = ? WHERE email = ?", (hashed_password, email))
        conn.commit()
        conn.close()

        return redirect(url_for('home', success="Your password has been reset. You can now log in."))
    
    return render_template('reset_password.html', token=token)

@app.route('/logout')
def logout():
    """Logs the student out by clearing the session."""
    session.pop('matric_no', None)
    return redirect(url_for('home'))

@app.route('/dashboard')
def dashboard():
    """The main dashboard page for logged-in students."""
    if 'matric_no' in session:
        conn = get_db_connection()
        user = conn.execute("SELECT fullname, matric_no, has_voted FROM users WHERE matric_no = ?", (session['matric_no'],)).fetchone()
        candidates = conn.execute("SELECT id, fullname, position FROM candidates").fetchall()
        conn.close()

        if user:
            return render_template('dashboard.html',
                                   user_fullname=user['fullname'],
                                   user_matric_no=user['matric_no'],
                                   user_has_voted=user['has_voted'],
                                   candidates=candidates)
    
    return redirect(url_for('home'))

@app.route('/confirm_vote', methods=('POST',))
def confirm_vote():
    """Renders a confirmation page before casting the vote."""
    if 'matric_no' not in session:
        return redirect(url_for('home'))

    candidate_id = request.form['candidate_id']
    conn = get_db_connection()
    user = conn.execute("SELECT has_voted FROM users WHERE matric_no = ?", (session['matric_no'],)).fetchone()
    
    if user['has_voted'] == 1:
        conn.close()
        return redirect(url_for('dashboard'))

    candidate = conn.execute("SELECT id, fullname, position FROM candidates WHERE id = ?", (candidate_id,)).fetchone()
    conn.close()

    if not candidate:
        return "Candidate not found.", 404

    return render_template('confirm_vote.html', candidate=candidate)

@app.route('/vote', methods=('POST',))
def vote():
    """Handles the final vote submission."""
    if 'matric_no' not in session:
        return redirect(url_for('home'))

    conn = get_db_connection()
    user = conn.execute("SELECT has_voted FROM users WHERE matric_no = ?", (session['matric_no'],)).fetchone()
    
    if user['has_voted'] == 1:
        conn.close()
        return redirect(url_for('dashboard'))

    candidate_id = request.form['candidate_id']
    
    conn.execute("UPDATE candidates SET vote_count = vote_count + 1 WHERE id = ?", (candidate_id,))
    conn.execute("UPDATE users SET has_voted = 1 WHERE matric_no = ?", (session['matric_no'],))
    
    conn.commit()
    conn.close()

    return redirect(url_for('vote_success'))

@app.route('/vote_success')
def vote_success():
    """Displays a success message after a vote is cast."""
    if 'matric_no' not in session:
        return redirect(url_for('home'))
        
    return render_template('vote_success.html')

@app.route('/results')
def show_results():
    """Displays the voting results."""
    conn = get_db_connection()
    candidates = conn.execute("SELECT fullname, position, vote_count FROM candidates ORDER BY vote_count DESC, fullname").fetchall()
    conn.close()

    return render_template('results.html', candidates=candidates)

# --- Admin Routes ---
@app.route('/admin/login', methods=('GET', 'POST'))
def admin_login():
    """Handles admin login."""
    if request.method == 'POST':
        matric_no = request.form['matric_no']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE matric_no = ? AND is_admin = 1", (matric_no,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['admin_logged_in'] = True
            session['admin_matric'] = user['matric_no']
            return redirect(url_for('admin_dashboard'))
        else:
            error = "Invalid credentials."
            return render_template('admin/login.html', error=error)
    
    return render_template('admin/login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    """The admin dashboard page."""
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    candidates = conn.execute("SELECT * FROM candidates ORDER BY position, fullname").fetchall()
    total_voters = conn.execute("SELECT COUNT(id) FROM users").fetchone()[0]
    total_votes_cast = conn.execute("SELECT COUNT(id) FROM users WHERE has_voted = 1").fetchone()[0]
    
    if total_voters > 0:
        vote_percentage = (total_votes_cast / total_voters) * 100
    else:
        vote_percentage = 0
    
    conn.close()

    return render_template('admin/dashboard.html',
                           candidates=candidates,
                           total_votes_cast=total_votes_cast,
                           total_voters=total_voters,
                           vote_percentage=vote_percentage)

@app.route('/admin/add_candidate', methods=('POST',))
def add_candidate():
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))

    fullname = request.form['fullname']
    position = request.form['position']

    conn = get_db_connection()
    conn.execute("INSERT INTO candidates (fullname, position) VALUES (?, ?)", (fullname, position))
    conn.commit()
    conn.close()

    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_candidate/<int:id>', methods=('POST',))
def delete_candidate(id):
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    conn.execute("DELETE FROM candidates WHERE id = ?", (id,))
    conn.commit()
    conn.close()

    return redirect(url_for('admin_dashboard'))

@app.route('/admin/logout')
def admin_logout():
    """Logs the admin out."""
    session.pop('admin_logged_in', None)
    session.pop('admin_matric', None)
    return redirect(url_for('admin_login'))

@app.route('/admin/reset_votes', methods=['POST'])
def reset_votes():
    """Resets all vote counts to zero."""
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    conn.execute("UPDATE candidates SET vote_count = 0")
    conn.commit()
    conn.close()

    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reset_voters', methods=['POST'])
def reset_voters():
    """Resets the voting status for all users."""
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    conn.execute("UPDATE users SET has_voted = 0")
    conn.commit()
    conn.close()

    return redirect(url_for('admin_dashboard'))

# --- Main Entry Point ---
if __name__ == '__main__':
    with app.app_context():
        init_db()
        create_initial_admin()
    app.run(debug=True, port=5001)