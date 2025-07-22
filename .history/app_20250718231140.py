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

supabase_url = os.getenv("SUPABASE_URL")
supabase_key = os.getenv("SUPABASE_KEY")

if not supabase_url or not supabase_key:
    logger.error("Supabase credentials not found. Check .env file.")
    raise ValueError("Supabase credentials not found. Check .env file.")

supabase: Client = create_client(supabase_url, supabase_key)
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
    return redirect(url_for('signin'))

@app.route('/sign-up', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        sign_up_as = request.form.get('signup_as')

        # Validate inputs
        if not all([username, email, password, sign_up_as]):
            flash("All fields are required.", "error")
            logger.warning("Signup failed: Missing required fields")
            return render_template('signup.html')
        if not is_valid_email(email):
            flash("Invalid email format.", "error")
            logger.warning(f"Signup failed: Invalid email format - {email}")
            return render_template('signup.html')
        if not is_valid_username(username):
            flash("Username must be at least 3 characters and alphanumeric.", "error")
            logger.warning(f"Signup failed: Invalid username - {username}")
            return render_template('signup.html')
        if not is_valid_password(password):
            flash("Password must be at least 8 characters.", "error")
            logger.warning("Signup failed: Password too short")
            return render_template('signup.html')
        if not is_valid_sign_up_as(sign_up_as):
            flash("Invalid role selected.", "error")
            logger.warning(f"Signup failed: Invalid role - {sign_up_as}")
            return render_template('signup.html')

        try:
            # Check for existing username or email
            existing_user = supabase.table('users').select('username').eq('username', username).execute()
            if existing_user.data:
                flash("Username already taken.", "error")
                logger.warning(f"Signup failed: Username {username} already taken")
                return render_template('signup.html')

            existing_email = supabase.table('users').select('email').eq('email', email).execute()
            if existing_email.data:
                flash("Email already registered.", "error")
                logger.warning(f"Signup failed: Email {email} already registered")
                return render_template('signup.html')

            # Hash password and insert user into users table
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
                logger.info(f"User {username} successfully saved.")
            else:
                logger.error(f"Insert failed: {response}")
    flash("Could not save user to DB.", "error")
    return render_template('signup.html')
            if response.data:
                logger.info(f"User {username} (email: {email}, role: {sign_up_as}) successfully saved to database")
                session['user_id'] = user_data['id']
                session['username'] = username
                session['sign_in_as'] = sign_up_as
                flash("Sign-up successful! Welcome to your dashboard.", "info")
                return redirect(url_for('dashboard'))
            else:
                logger.error("Failed to insert user into users table")
                flash("Profile creation failed. Check database configuration.", "error")
                return render_template('signup.html')

        except Exception as e:
            logger.error(f"Signup error: {str(e)}")
            flash(f"Sign-up failed: {str(e)}", "error")
            return render_template('signup.html')

    return render_template('signup.html')

@app.route('/sign-in', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        sign_in_as = request.form.get('signin_as')

        # Validate inputs
        if not all([email, password, sign_in_as]):
            flash("Email, password, and role are required.", "error")
            logger.warning("Signin failed: Missing required fields")
            return render_template('signin.html')
        if not is_valid_email(email):
            flash("Invalid email format.", "error")
            logger.warning(f"Signin failed: Invalid email format - {email}")
            return render_template('signin.html')
        if not is_valid_sign_up_as(sign_in_as):
            flash("Invalid role selected.", "error")
            logger.warning(f"Signin failed: Invalid role - {sign_in_as}")
            return render_template('signin.html')

        try:
            # Check user in users table
            user = supabase.table('users').select('*').eq('email', email).execute()
            if not user.data:
                flash("Invalid email or password.", "error")
                logger.warning(f"Signin failed: Email {email} not found")
                return render_template('signin.html')

            user_data = user.data[0]
            if check_password_hash(user_data['password'], password) and user_data['sign_up_as'] == sign_in_as:
                session['user_id'] = user_data['id']
                session['username'] = user_data['username']
                session['sign_in_as'] = sign_in_as
                logger.info(f"User {user_data['username']} (email: {email}, role: {sign_in_as}) signed in successfully")
                flash("Sign-in successful! Welcome back.", "info")
                return redirect(url_for('dashboard'))
            else:
                flash("Invalid email, password, or role.", "error")
                logger.warning(f"Signin failed: Invalid credentials or role for email {email}")
                return render_template('signin.html')

        except Exception as e:
            logger.error(f"Signin error: {str(e)}")
            flash(f"Sign-in failed: {str(e)}", "error")
            return render_template('signin.html')

    return render_template('signin.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Please sign in to access the dashboard.", "error")
        logger.warning("Unauthorized dashboard access attempt")
        return redirect(url_for('signin'))
    logger.info(f"User {session['username']} accessed dashboard")
    return render_template('dashboard.html', username=session['username'], role=session['sign_in_as'])

@app.route('/logout')
def logout():
    username = session.get('username', 'unknown')
    session.clear()
    logger.info(f"User {username} logged out")
    flash("Logged out successfully.", "info")
    return redirect(url_for('signin'))

@app.route('/debug/users')
def debug_users():
    try:
        users = supabase.table('users').select('*').execute()
        logger.info("Debug: Fetched all users from database")
        return render_template('debug.html', users=users.data)
    except Exception as e:
        logger.error(f"Debug error: {str(e)}")
        return f"Debug error: {str(e)}"

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)