from flask import Flask, request, render_template, redirect, url_for, session, flash
from supabase import create_client, Client
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import re
import logging
import uuid

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    logger.error("Supabase credentials not found. Check .env file.")
    raise ValueError("Supabase credentials not found. Check .env file.")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
logger.info("Supabase client initialized successfully")

app = Flask(__name__, static_folder='assets', template_folder='templates')
app.secret_key = os.getenv("FLASK_SECRET_KEY", str(uuid.uuid4()))

# Validation functions
def is_valid_email(email):
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(regex, email)

def is_valid_username(username):
    return len(username) >= 3 and username.isalnum()

def is_valid_password(password):
    return len(password) >= 8

def is_valid_sign_up_as(sign_up_as):
    return sign_up_as in ['merchant', 'loan_borrower', 'nbfc_admin']

@app.route('/')
def home():
    return redirect(url_for('signin'))  # ✅ Fixed: use function name, not file name

@app.route('/sign-up', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        sign_up_as = request.form.get('signup_as')

        # Validation
        if not all([username, email, password, sign_up_as]):
            flash("All fields are required.", "error")
            return render_template('sign-up.html')

        if not is_valid_email(email):
            flash("Invalid email format.", "error")
            return render_template('sign-up.html')

        if not is_valid_username(username):
            flash("Username must be at least 3 characters and alphanumeric.", "error")
            return render_template('sign-up.html')

        if not is_valid_password(password):
            flash("Password must be at least 8 characters.", "error")
            return render_template('sign-up.html')

        if not is_valid_sign_up_as(sign_up_as):
            flash("Invalid role selected.", "error")
            return render_template('sign-up.html')

        try:
            # Check if username or email already exists
            if supabase.table('users').select('username').eq('username', username).execute().data:
                flash("Username already taken.", "error")
                return render_template('sign-up.html')

            if supabase.table('users').select('email').eq('email', email).execute().data:
                flash("Email already registered.", "error")
                return render_template('sign-up.html')

            # Create user
            hashed_password = generate_password_hash(password)
            user_data = {
                'id': str(uuid.uuid4()),
                'username': username,
                'email': email,
                'password': hashed_password,
                'sign_up_as': sign_up_as,
                'created_at': datetime.utcnow().isoformat()
            }

            response = supabase.table('users').insert(user_data).execute()
            if response.data:
                session['user_id'] = user_data['id']
                session['username'] = username
                session['sign_in_as'] = sign_up_as
                flash("Sign-up successful!", "info")
                return redirect(url_for('dashboard'))
            else:
                flash("Database error: could not insert user.", "error")

        except Exception as e:
            logger.error(f"Sign-up error: {str(e)}")
            flash(f"Sign-up failed: {str(e)}", "error")

    return render_template('sign-up.html')

@app.route('/sign-in', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        sign_in_as = request.form.get('signin_as')

        if not all([email, password, sign_in_as]):
            flash("All fields are required.", "error")
            return render_template('sign-in.html')

        if not is_valid_email(email):
            flash("Invalid email format.", "error")
            return render_template('sign-in.html')

        if not is_valid_sign_up_as(sign_in_as):
            flash("Invalid role selected.", "error")
            return render_template('sign-in.html')

        try:
            user = supabase.table('users').select('*').eq('email', email).execute()
            if not user.data:
                flash("Invalid credentials.", "error")
                return render_template('sign-in.html')

            user_data = user.data[0]
            if check_password_hash(user_data['password'], password) and user_data['sign_up_as'] == sign_in_as:
                session['user_id'] = user_data['id']
                session['username'] = user_data['username']
                session['sign_in_as'] = sign_in_as
                flash("Signed in successfully!", "info")
                return redirect(url_for('dashboard'))
            else:
                flash("Incorrect password or role.", "error")

        except Exception as e:
            logger.error(f"Sign-in error: {str(e)}")
            flash(f"Sign-in failed: {str(e)}", "error")

    return render_template('sign-in.html')

@app.route('/')
def dashboard():
    if 'user_id' not in session:
        flash("Please sign in to continue.", "error")
        return redirect(url_for('signin'))

    return render_template('dashboard.html', username=session['username'], role=session['sign_in_as'])

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('signin'))

@app.route('/debug/users')
def debug_users():
    try:
        users = supabase.table('users').select('*').execute()
        return render_template('debug.html', users=users.data)
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
