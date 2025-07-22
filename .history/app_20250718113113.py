from flask import Flask, request, render_template, redirect, url_for, session, flash
from supabase import create_client, Client
from dotenv import load_dotenv
import os
import re
import logging
import bcrypt

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

# Email and username validation
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
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        signup_as = request.form.get('signup_as')

        logger.info(f"Attempting sign-up with email: {email}, username: {username}, signup_as: {signup_as}")

        # Validate inputs
        if not email or not username or not password or not signup_as:
            return render_template('sign-up.html', error="All fields are required.")
        if not is_valid_email(email):
            return render_template('sign-up.html', error="Invalid email format.")
        if not is_valid_username(username):
            return render_template('sign-up.html', error="Username must be at least 3 characters, alphanumeric.")
        if not is_valid_password(password):
            return render_template('sign-up.html', error="Password must be at least 8 characters.")

        try:
            # Check if username or email already exists
            existing_user = supabase.table('profiles').select('username').eq('username', username).execute()
            if existing_user.data:
                return render_template('sign-up.html', error="Username already taken.")

            existing_email = supabase.table('profiles').select('email').eq('email', email).execute()
            if existing_email.data:
                return render_template('sign-up.html', error="Email already registered.")

            # Signup with Supabase, triggering email confirmation
            auth_response = supabase.auth.sign_up({
                "email": email,
                "password": password,
                "options": {
                    "data": {
                        "username": username,
                        "signup_as": signup_as
                    },
                    "email_redirect_to": url_for('confirm_email', _external=True)  # Custom redirect URL
                }
            })

            logger.info(f"Sign-up response: user={auth_response.user}, session={auth_response.session}")

            user = auth_response.user
            if not user:
                return render_template('sign-up.html', error="Signup failed. No user returned.")

            # Insert profile to DB with email_confirmed as False
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            profile_response = supabase.table('profiles').insert({
                "id": user.id,
                "username": username,
                "email": email,
                "password": hashed_password,
                "signup_as": signup_as,
                "email_confirmed": False
            }).execute()

            if not profile_response.data:
                return render_template('sign-up.html', error="Profile insert failed. Check RLS or schema.")

            flash("A confirmation email has been sent to your email address. Please check your inbox and spam folder.", "info")
            return render_template('sign-up.html', signup_success=True)

        except Exception as e:
            logger.error(f"Signup error: {str(e)}")
            return render_template('sign-up.html', error=f"Signup failed: {str(e)}")

    return render_template('sign-up.html')

@app.route('/confirm', methods=['GET'])
def confirm_email():
    token = request.args.get('token')
    email = request.args.get('email')
    logger.info(f"Confirming email with token: {token}, email: {email}")

    if not token or not email:
        flash("Invalid or missing confirmation token/email.", "error")
        return redirect(url_for('signup'))

    try:
        # Verify the confirmation token
        response = supabase.auth.verify_otp({
            "email": email,
            "token": token,
            "type": "signup"
        })

        user = response.user
        session_info = response.session

        if user and session_info:
            # Update profile to mark email as confirmed
            supabase.table('profiles').update({
                "email_confirmed": True
            }).eq('id', user.id).execute()

            # Set session
            supabase.auth.set_session(session_info.access_token, session_info.refresh_token)
            session['user_id'] = user.id
            session['email'] = user.email

            flash("Email confirmed successfully! You can now sign in.", "success")
            return redirect(url_for('signin'))
        else:
            flash("Email confirmation failed. Invalid token or user.", "error")
            return redirect(url_for('signup'))

    except Exception as e:
        logger.error(f"Email confirmation error: {str(e)}")
        flash(f"Email confirmation failed: {str(e)}", "error")
        return redirect(url_for('signup'))

@app.route('/sign-in', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            return render_template('sign-in.html', error="Email and password are required.")
        if not is_valid_email(email):
            return render_template('sign-in.html', error="Invalid email format.")

        try:
            auth_response = supabase.auth.sign_in_with_password({
                "email": email,
                "password": password
            })

            user = auth_response.user
            session_info = auth_response.session

            if not user or not session_info:
                return render_template('sign-in.html', error="Invalid email or password.")

            supabase.auth.set_session(session_info.access_token, session_info.refresh_token)

            # Get profile and check if email is confirmed
            profile = supabase.table('profiles').select('*').eq('id', user.id).execute()
            if not profile.data or not profile.data[0].get('email_confirmed'):
                return render_template('sign-in.html', error="Please confirm your email before signing in.")

            session['user_id'] = user.id
            session['email'] = user.email

            return redirect(url_for('welcome'))

        except Exception as e:
            logger.error(f"Signin error: {str(e)}")
            return render_template('sign-in.html', error="Signin failed. Try again.")

    return render_template('sign-in.html')

@app.route('/logout')
def logout():
    session.clear()
    supabase.auth.sign_out()
    return redirect(url_for('home'))

@app.route('/welcome')
def welcome():
    if 'user_id' not in session:
        flash("Please sign in to access this page.", "error")
        return redirect(url_for('signin'))
    return render_template('welcome.html', user=session)

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