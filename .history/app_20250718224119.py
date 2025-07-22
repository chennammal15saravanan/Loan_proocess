from flask import Flask, request, render_template, redirect, url_for, session, flash
from supabase import create_client, Client
from dotenv import load_dotenv
import os
import re
import logging

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
app.secret_key = os.getenv("FLASK_SECRET_KEY", "your-secret-key")

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
            # Check for existing username or email
            existing_user = supabase.table('users').select('username').eq('username', username).execute()
            if existing_user.data:
                flash("Username already taken.", "error")
                return render_template('sign-up.html')

            existing_email = supabase.table('users').select('email').eq('email', email).execute()
            if existing_email.data:
                flash("Email already registered.", "error")
                return render_template('sign-up.html')

            # Sign up with Supabase Auth
            auth_response = supabase.auth.sign_up({
                "email": email,
                "password": password,
                "options": {
                    "data": {
                        "username": username,
                        "sign_up_as": sign_up_as
                    }
                }
            })

            user = auth_response.user
            session_info = auth_response.session

            if not user or not session_info:
                flash("Sign-up failed. Please try again.", "error")
                return render_template('sign-up.html')

            # Set session
            supabase.auth.set_session(session_info.access_token, session_info.refresh_token)

            # Insert user details into users table
            profile_response = supabase.table('users').insert({
                "id": user.id,
                "username": username,
                "email": email,
                "sign_up_as": sign_up_as
            }).execute()

            if not profile_response.data:
                flash("Profile creation failed. Check database configuration.", "error")
                return render_template('sign-up.html')

            session['user_id'] = user.id
            session['username'] = username
            session['sign_in_as'] = sign_up_as
            flash("Sign-up successful! Confirmation email sent.", "info")
            return redirect(url_for('dashboard'))

        except Exception as e:
            logger.error(f"Signup error: {str(e)}")
            flash("Sign-up failed. Please try again.", "error")
            return render_template('sign-up.html')

    return render_template('sign-up.html')

@app.route('/sign-in', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        sign_in_as = request.form.get('signin_as')

        # Validate inputs
        if not all([email, password, sign_in_as]):
            flash("Email, password, and role are required.", "error")
            return render_template('sign-in.html')
        if not is_valid_email(email):
            flash("Invalid email format.", "error")
            return render_template('sign-in.html')
        if not is_valid_sign_up_as(sign_in_as):
            flash("Invalid role selected.", "error")
            return render_template('sign-in.html')

        try:
            # Sign in with Supabase Auth
            auth_response = supabase.auth.sign_in_with_password({
                "email": email,
                "password": password
            })

            user = auth_response.user
            session_info = auth_response.session

            if not user or not session_info:
                flash("Invalid email or password.", "error")
                return render_template('sign-in.html')

            # Verify sign_in_as matches stored role
            profile = supabase.table('users').select('*').eq('id', user.id).execute()
            if not profile.data:
                flash("User profile not found.", "error")
                return render_template('sign-in.html')

            if profile.data[0]['sign_up_as'] != sign_in_as:
                flash("Invalid role selected.", "error")
                return render_template('sign-in.html')

            supabase.auth.set_session(session_info.access_token, session_info.refresh_token)
            session['user_id'] = user.id
            session['username'] = profile.data[0]['username']
            session['sign_in_as'] = sign_in_as
            return redirect(url_for('dashboard'))

        except Exception as e:
            logger.error(f"Signin error: {str(e)}")
            flash("Sign-in failed. Please try again.", "error")
            return render_template('sign-in.html')

    return render_template('sign-in.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Please sign in to access the dashboard.", "error")
        return redirect(url_for('signin'))
    return render_template('dashboard.html', username=session['username'], role=session['sign_in_as'])

@app.route('/logout')
def logout():
    session.clear()
    supabase.auth.sign_out()
    flash("Logged out successfully.", "info")
    return redirect(url_for('signin'))

@app.route('/debug/users')
def debug_users():
    try:
        service_client = create_client(supabase_url, os.getenv("SUPABASE_SERVICE_ROLE_KEY"))
        users = service_client.table('users').select('*').execute()
        return render_template('debug.html', users=users.data)
    except Exception as e:
        logger.error(f"Debug error: {str(e)}")
        return f"Debug error: {str(e)}"

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)