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

            logger.info(f"Setting session for user ID: {user.id}")
            supabase.auth.set_session(access_token, refresh_token)

            logger.info(f"Fetching profile for user ID: {user.id}")
            result = supabase.table('profiles').select('*').eq('id', user.id).execute()
            if not result.data:
                logger.error(f"No profile found for user ID {user.id}")
                return render_template('sign-in.html', error="User profile not found.")

            user_profile = result.data[0]
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