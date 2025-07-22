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
            return render_template('sign-in.html', error="Email and password are required.")
        if not is_valid_email(email):
            return render_template('sign-in.html', error="Invalid email format.")

        try:
            # Sign in with Supabase auth
            auth_response = supabase.auth.sign_in_with_password({
                "email": email,
                "password": password
            })

            user = auth_response.user
            access_token = auth_response.session.access_token if auth_response.session else None

            if not user or not access_token:
                return render_template('sign-in.html', error="Invalid email or password.")

            # Set the session for subsequent requests
            supabase.auth.set_session(access_token)

            # Fetch user profile
            result = supabase.table('profiles').select('*').eq('id', user.id).execute()
            if not result.data:
                return render_template('sign-in.html', error="User profile not found.")

            user_profile = result.data[0]
            session['user_id'] = user.id
            session['email'] = user.email
            return render_template('welcome.html', user=user_profile)

        except Exception as e:
            logger.exception("Signin failed")
            return render_template('sign-in.html', error="Invalid email or password.")

    return render_template('sign-in.html')

@app.route('/logout')
def logout():
    session.clear()
    supabase.auth.sign_out()
    return redirect(url_for('home'))

@app.route('/debug/profiles')
def debug_profiles():
    try:
        # For debugging, you might use the service role key with caution
        # Alternatively, ensure the user is authenticated and has permission
        response = supabase.table('profiles').select('*').execute()
        return render_template('debug.html', profiles=response.data)
    except Exception as e:
        logger.exception("Error fetching profiles")
        return f"Error: {str(e)}"
if __name__ == '__main__':
    app.run(debug=True)
