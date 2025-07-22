from flask import Flask, request, render_template, redirect, url_for, session
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

        if not email or not username or not password:
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

            # Signup with Supabase
            auth_response = supabase.auth.sign_up({
                "email": email,
                "password": password
            })

            user = auth_response.user
            session_info = auth_response.session

            if not user or not session_info:
                return render_template('sign-up.html', error="Signup failed. No user/session returned.")

            # Set session
            access_token = session_info.access_token
            refresh_token = session_info.refresh_token
            supabase.auth.set_session(access_token, refresh_token)
            
            # Insert profile to DB
            profile_response = supabase.table('profiles').insert({
                "id": user.id,
                "username": username,
                "email": email
            }).execute()

            if not profile_response.data:
                return render_template('sign-up.html', error="Profile insert failed. Check RLS or schema.")

            session['user_id'] = user.id
            session['email'] = email

            return render_template('welcome.html', user={"id": user.id, "username": username, "email": email})

        except Exception as e:
            logger.error(f"Signup error: {str(e)}")
            return render_template('sign-up.html', error="Signup failed. Please try again.")

    return render_template('sign-up.html')

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

            # Get profile
            profile = supabase.table('profiles').select('*').eq('id', user.id).execute()
            if not profile.data:
                return render_template('sign-in.html', error="User profile not found.")

            session['user_id'] = user.id
            session['email'] = user.email

            return render_template('welcome.html', user=profile.data[0])

        except Exception as e:
            logger.error(f"Signin error: {str(e)}")
            return render_template('sign-in.html', error="Signin failed. Try again.")

    return render_template('sign-in.html')

@app.route('/logout')
def logout():
    session.clear()
    supabase.auth.sign_out()
    return redirect(url_for('home'))

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

