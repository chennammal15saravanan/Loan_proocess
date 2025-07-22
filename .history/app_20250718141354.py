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

@app.route('/')
def home():
    return render_template('sign-in.html')

@app.route('/sign-up.html')
def signup_html():
    return render_template('sign-up.html')


@app.route('/sign-up', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        signup_as = request.form['signup_as']

        # Step 1: Create user in Supabase Auth
        auth_response = supabase.auth.sign_up({
            'email': email,
            'password': password
        })

        user = auth_response.get('user')
        logger.info("Signup auth response: %s", auth_response)

        if not user or not user.get('id'):
            flash("Signup successful. Please confirm your email before logging in.", "info")
            return render_template('confirmation.html')

        # Step 2: Insert into profiles table (password is required in your schema)
        profile_data = {
            'id': user['id'],
            'username': username,
            'email': email,
            'password': password,     # ⚠️ Stored as plain text – not secure
            'signup_as': signup_as
        }

        profile_response = supabase.table('profiles').insert(profile_data).execute()
        logger.info("Profile insert response: %s", profile_response)

        if profile_response.get('status_code') != 201:
            flash("Failed to save profile details. Please try again.", "error")
            return render_template('sign-up.html')

        flash("Signup successful. Please log in.", "success")
        return redirect(url_for('signin'))

    return render_template('sign-up.html')


@app.route('/sign-in', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash("Email and password are required.", "error")
            logger.error("Missing email or password")
            return render_template('sign-in.html')

        if not is_valid_email(email):
            flash("Invalid email format.", "error")
            logger.error("Invalid email format: %s", email)
            return render_template('sign-in.html')

        try:
            logger.info("Attempting sign-in for email: %s", email)
            auth_response = supabase.auth.sign_in_with_password({
                "email": email,
                "password": password
            })

            user = auth_response.get("user")
            session_info = auth_response.session

            if not user or not session_info:
                flash("Invalid email or password.", "error")
                logger.error("Invalid email or password for: %s", email)
                return render_template('sign-in.html')

            logger.info("Setting session for user: %s", user.id)
            supabase.auth.set_session(session_info.access_token, session_info.refresh_token)

            profile = supabase.table('profiles').select('*').eq('id', user.id).execute()
            if not profile.data:
                flash("User profile not found.", "error")
                logger.error("Profile not found for user ID: %s", user.id)
                return render_template('sign-in.html')

            session['user_id'] = user.id
            session['email'] = user.email
            session['username'] = profile.data[0]['username']
            logger.info("Sign-in successful for: %s", email)
            flash("Sign-in successful!", "info")
            return redirect(url_for('dashboard'))

        except Exception as e:
            flash("Signin failed. Please try again.", "error")
            logger.error("Signin error: %s", str(e))
            return render_template('sign-in.html')

    # Handle email confirmation redirect
    if request.args.get('access_token') and request.args.get('refresh_token'):
        try:
            logger.info("Processing email confirmation redirect")
            supabase.auth.set_session(request.args.get('access_token'), request.args.get('refresh_token'))
            user = supabase.auth.get_user().user
            if user:
                profile = supabase.table('profiles').select('username').eq('id', user.id).execute()
                if profile.data:
                    session['user_id'] = user.id
                    session['email'] = user.email
                    session['username'] = profile.data[0]['username']
                    logger.info("Email confirmed for user: %s", user.email)
                    flash("Email confirmed! You are now signed in.", "info")
                    return redirect(url_for('dashboard'))
                else:
                    flash("User profile not found.", "error")
                    logger.error("Profile not found for confirmed user: %s", user.id)
            else:
                flash("Invalid confirmation link.", "error")
                logger.error("Invalid confirmation link")
        except Exception as e:
            flash("Failed to process confirmation.", "error")
            logger.error("Confirmation error: %s", str(e))

    return render_template('sign-in.html')

@app.route('/logout')
def logout():
    session.clear()
    supabase.auth.sign_out()
    return redirect(url_for('home'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Please sign in.", "error")
        return redirect(url_for('signin'))
    return render_template('dashboard.html', username=session.get('username'))

@app.route('/debug/profiles')
def debug_profiles():
    try:
        service_client = create_client(supabase_url, os.getenv("SUPABASE_SERVICE_ROLE_KEY"))
        profiles = service_client.table('profiles').select('*').execute()
        return render_template('debug.html', profiles=profiles.data)
    except Exception as e:
        return f"Debug error: {str(e)}"

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)