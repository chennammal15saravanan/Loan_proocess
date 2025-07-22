from flask import Flask, request, render_template, redirect, url_for, session
from supabase import create_client, Client
from dotenv import load_dotenv
import os
import re
import logging
import httpx
import bcrypt  # ADD THIS IMPORT AT THE TOP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('app.log'),  # Save logs to app.log
        logging.StreamHandler()          # Also print to console
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

# Create Supabase client
try:
    supabase: Client = create_client(supabase_url, supabase_key)
    logger.info("Supabase client initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize Supabase client: {str(e)}")
    raise

app = Flask(__name__, static_folder='assets', template_folder='templates')
app.secret_key = os.getenv("FLASK_SECRET_KEY", "your-secret-key")  # For session management

# Input validation helper functions
def is_valid_email(email):
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(regex, email)

def is_valid_username(username):
    return len(username) >= 3 and username.isalnum()  # Min 3 chars, alphanumeric

def is_valid_password(password):
    return len(password) >= 8  # Min 8 chars

@app.route('/')
def home():
    logger.info("Rendering home page (sign-in.html)")
    return render_template('sign-in.html')

@app.route('/sign-up.html')
def signup_html():
    logger.info("Rendering sign-up page (sign-up.html)")
    return render_template('sign-up.html')


@app.route('/sign-in', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Input validation
        if not email or not password:
            logger.error("Missing email or password in sign-in form")
            return render_template('sign-in.html', error="Email and password are required")
        if not is_valid_email(email):
            logger.error(f"Invalid email format: {email}")
            return render_template('sign-in.html', error="Invalid email format")

        try:
            # Sign in with Supabase Auth
            logger.info(f"Attempting to sign in user with email: {email}")
            response = supabase.auth.sign_in_with_password({"email": email, "password": password})

            if response.session:
                # Store session data
                session['user_id'] = response.user.id
                session['access_token'] = response.session.access_token
                logger.info(f"User signed in successfully, user_id: {response.user.id}")

                # Fetch user profile
                logger.info(f"Fetching profile for email: {email}")
                profile = supabase.table('profiles').select('*').eq('email', email).execute()
                if profile.data:
                    logger.info(f"Profile found: {profile.data[0]}")
                    return render_template("welcome.html", user=profile.data[0])
                logger.error("Profile not found in database")
                return render_template('sign-in.html', error="Profile not found.")
            logger.error("Login failed: invalid credentials")
            return render_template('sign-in.html', error="Login failed.")

        except Exception as e:
            logger.exception(f"Sign-in error: {str(e)}")
            return render_template('sign-in.html', error="Invalid email or password")

    logger.info("Rendering sign-in page (GET request)")
    return render_template('sign-in.html')

@app.route('/logout')
def logout():
    logger.info("User logging out")
    session.clear()
    supabase.auth.sign_out()
    return redirect(url_for('home'))

@app.route('/debug/profiles')
def debug_profiles():
    logger.info("Fetching all profiles for debugging")
    try:
        response = supabase.table('profiles').select('*').execute()
        logger.info(f"Profiles retrieved: {response.data}")
        return render_template('debug.html', profiles=response.data)
    except Exception as e:
        logger.exception(f"Debug error: {str(e)}")
        return f"Error: {str(e)}"

if __name__ == '__main__':
    logger.info("Starting Flask application")
    app.run(debug=True)