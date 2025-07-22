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
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not username or not password:
            logger.error("Missing required fields: email, username, or password")
            return render_template('sign-up.html', error="All fields are required.")
        if not is_valid_email(email):
            logger.error(f"Invalid email format: {email}")
            return render_template('sign-up.html', error="Invalid email format.")
        if not is_valid_username(username):
            logger.error(f"Invalid username: {username}")
            return render_template('sign-up.html', error="Username must be alphanumeric and at least 3 characters.")
        if not is_valid_password(password):
            logger.error(f"Password too short: {len(password)} characters")
            return render_template('sign-up.html', error="Password must be at least 8 characters.")

        try:
            # Check for existing username
            existing_username = supabase.table('profiles').select('username').eq('username', username).execute()
            if existing_username.data:
                logger.error(f"Username already taken: {username}")
                return render_template('sign-up.html', error="Username already taken.")

            # Check for existing email
            existing_email = supabase.table('profiles').select('email').eq('email', email).execute()
            if existing_email.data:
                logger.error(f"Email already registered: {email}")
                return render_template('sign-up.html', error="Email already registered.")

            # Supabase signup
            logger.info(f"Attempting signup for email: {email}")
            auth_response = supabase.auth.sign_up({
                "email": email,
                "password": password,
                "options": {"data": {"username": username}}
            })

            user = auth_response.user
            if not user:
                logger.error("Signup failed: No user returned")
                return render_template('sign-up.html', error="Signup failed. No user created.")

            # Insert profile data into the profiles table
            logger.info(f"Inserting profile for user ID: {user.id}, username: {username}, email: {email}")
            response = supabase.table('profiles').insert({
                "id": user.id,
                "username": username,
                "email": email
            }).execute()

            if not response.data:
                logger.error(f"Failed to insert profile for user ID: {user.id}")
                # Optionally roll back the auth signup if profile insertion fails
                supabase.auth.admin.delete_user(user.id)  # This is an admin action, requires service role key
                return render_template('sign-up.html', error="Failed to create user profile.")

            logger.info(f"Signup successful for user ID: {user.id}")
            session['user_id'] = user.id
            session['email'] = email
            return render_template('welcome.html', user={"id": user.id, "username": username, "email": email})

        except Exception as e:
            error_message = str(e)
            if "already registered" in error_message.lower():
                error_message = "Email already registered."
            elif "row-level security" in error_message.lower():
                error_message = "Permission denied when saving profile. Contact support."
            logger.error(f"Signup failed for email {email}: {error_message}")
            return render_template('sign-up.html', error=error_message)

    return render_template('sign-up.html')

@app.route('/sign-in', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            logger.error("Missing email or password in sign-in")
            return render_template('sign-in.html', error="Email and password are required.")
        if not is_valid_email(email):
            logger.error(f"Invalid email format in sign-in: {email}")
            return render_template('sign-in.html', error="Invalid email format.")

        try:
            logger.info(f"Attempting sign-in for email: {email}")
            auth_response = supabase.auth.sign_in_with_password({
                "email": email,
                "password": password
            })

            user = auth_response.user
            access_token = auth_response.session.access_token if auth_response.session else None
            refresh_token = auth_response.session.refresh_token if auth_response.session else None

            if not user or not access_token or not refresh_token:
                logger.error(f"Sign-in failed for email {email}: No user or tokens")
                return render_template('sign-in.html', error="Invalid email or password.")

            # Verify profile exists in profiles table
            logger.info(f"Fetching profile for user ID: {user.id}")
            profile_response = supabase.table('profiles').select('*').eq('id', user.id).execute()
            if not profile_response.data:
                logger.error(f"No profile found for user ID {user.id}")
                return render_template('sign-in.html', error="User profile not found.")

            user_profile = profile_response.data[0]
            logger.info(f"Setting session for user ID: {user.id}")
            supabase.auth.set_session(access_token, refresh_token)
            session['user_id'] = user.id
            session['email'] = user.email
            logger.info(f"Sign-in successful for user ID: {user.id}")
            return render_template('welcome.html', user=user_profile)

        except Exception as e:
            error_message = str(e)
            logger.error(f"Sign-in failed for email {email}: {error_message}")
            return render_template('sign-in.html', error="Invalid email or password.")

    return render_template('sign-in.html')

@app.route('/logout')
def logout():
    session.clear()
    supabase.auth.sign_out()
    logger.info("User logged out")
    return redirect(url_for('home'))

@app.route('/debug/profiles')
def debug_profiles():
    try:
        supabase_debug = create_client(supabase_url, os.getenv("SUPABASE_SERVICE_ROLE_KEY"))
        response = supabase_debug.table('profiles').select('*').execute()
        logger.info(f"Debug profiles fetched: {response.data}")
        return render_template('debug.html', profiles=response.data)
    except Exception as e:
        logger.error(f"Error fetching profiles: {str(e)}")
        return f"Error: {str(e)}"

if __name__ == '__main__':
    app.run(debug=True)