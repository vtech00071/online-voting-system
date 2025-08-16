from flask import Flask, render_template, request, redirect, url_for, session, after_this_request
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize the Flask application
app = Flask(__name__)
app.secret_key = 'your_super_secret_key_here'  # Change this to a random, secure key

# --- Global Handlers ---
@app.before_request
def check_cache():
    """Adds no-cache headers to protected routes."""
    # List of routes that should not be cached
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
    conn.row_factory = sqlite3.Row  # Allows accessing columns by name
    return conn

def init_db():
    """Creates the necessary tables in the database."""
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            matric_no TEXT UNIQUE NOT NULL,
            fullname TEXT NOT NULL,
            password TEXT NOT NULL,
            has_voted INTEGER DEFAULT 0,
            is_admin INTEGER DEFAULT 0
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
    admin_password = "password123"  # <--- CHANGE THIS FOR PRODUCTION!
    hashed_password = generate_password_hash(admin_password)

    existing_admin = conn.execute("SELECT * FROM users WHERE matric_no = ? AND is_admin = 1", (admin_matric,)).fetchone()
    if not existing_admin:
        conn.execute("INSERT INTO users (matric_no, fullname, password, is_admin) VALUES (?, ?, ?, 1)",
                     (admin_matric, "Admin User", hashed_password))
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
    """Handles student registration."""
    if request.method == 'POST':
        matric_no = request.form['matric_no']
        fullname = request.form['fullname']
        password = request.form['password']

        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        try:
            conn.execute("INSERT INTO users (matric_no, fullname, password) VALUES (?, ?, ?)",
                         (matric_no, fullname, hashed_password))
            conn.commit()
            return redirect(url_for('home'))
        except sqlite3.IntegrityError:
            error = "Matric number already registered. Please login."
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
    
    if user and check_password_hash(user['password'], password):
        session['matric_no'] = user['matric_no']
        return redirect(url_for('dashboard'))
    else:
        error = "Invalid Matric Number or Password."
        return render_template('login.html', error=error)

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




# all admin code start from here 

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



# with this route we will add add_candidate

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


# with this route we will delete delete_candidate

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




# this route will allow us to cast votes 


@app.route('/vote', methods=('POST',))
def vote():
    """Handles the final vote submission and redirects to a success page."""
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

    # The new line to redirect to the vote success page
    return redirect(url_for('vote_success'))
# confirm your vote 

@app.route('/confirm_vote', methods=('POST',))
def confirm_vote():
    if 'matric_no' not in session:
        return redirect(url_for('home'))

    # Get the selected candidate's ID from the form submission
    candidate_id = request.form['candidate_id']

    conn = get_db_connection()
    user = conn.execute("SELECT has_voted FROM users WHERE matric_no = ?", (session['matric_no'],)).fetchone()

    # Check if the user has already voted
    if user['has_voted'] == 1:
        conn.close()
        return redirect(url_for('dashboard'))

    # Get the candidate's details for display on the confirmation page
    candidate = conn.execute("SELECT id, fullname, position FROM candidates WHERE id = ?", (candidate_id,)).fetchone()
    conn.close()

    if not candidate:
        # Handle case where the candidate ID is invalid
        return "Candidate not found.", 404

    # Store the candidate_id in the session so it can be used on the next page
    session['candidate_id_to_confirm'] = candidate['id']

    return render_template('confirm_vote.html', candidate=candidate)



# this route is for result


@app.route('/results')
def show_results():
    """Displays the voting results."""
    conn = get_db_connection()
    candidates = conn.execute("SELECT fullname, position, vote_count FROM candidates ORDER BY vote_count DESC, fullname").fetchall()
    conn.close()

    return render_template('results.html', candidates=candidates)



# this route will reset vote

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


# this route will reset voters

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



# this route is for sucessful voters

@app.route('/vote_success')
def vote_success():
    """Displays a success message after a vote is cast."""
    if 'matric_no' not in session:
        return redirect(url_for('home'))
        
    return render_template('vote_success.html')


# --- Main Entry Point ---
# app.py



if __name__ == '__main__':
    with app.app_context():
        init_db()
        create_initial_admin()
    app.run(debug=True, port=5001)