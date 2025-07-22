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
            return render_template('sign-up.html', error="All fields are required.")
        if not is_valid_email(email):
            return render_template('sign-up.html', error="Invalid email format.")
        if not is_valid_username(username):
            return render_template('sign-up.html', error="Username must be alphanumeric and at least 3 characters.")
        if not is_valid_password(password):
            return render_template('sign-up.html', error="Password must be at least 8 characters.")

        try:
            # Sign up user
            auth_response = supabase.auth.sign_up({
                "email": email,
                "password": password,
                "options": {"data": {"username": username}}
            })

            user = auth_response.user

            # If session not returned, sign in manually (email confirmation disabled)
            if not auth_response.session:
                signin_response = supabase.auth.sign_in_with_password({
                    "email": email,
                    "password": password
                })
                access_token = signin_response.session.access_token
            else:
                access_token = auth_response.session.access_token

            if not user or not access_token:
                return render_template('sign-up.html', error="Signup failed. Try again.")

            # Hash the password
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

            # Insert into profiles
            supabase.table('profiles').insert({
                "id": user.id,
                "username": username,
                "email": email,
                    "password": hashed_password
}).execute()


            return redirect(url_for('signin'))

        except Exception as e:
            logger.exception("Signup failed")
            return render_template('sign-up.html', error=str(e))

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
            # Get user from profiles table
            result = supabase.table('profiles').select('*').eq('email', email).execute()
            if not result.data:
                return render_template('sign-in.html', error="User not found.")

            user = result.data[0]
            hashed_password = user['password']

            if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
                session['user_id'] = user['id']
                session['email'] = user['email']
                return render_template('welcome.html', user=user)
            else:
                return render_template('sign-in.html', error="Invalid password.")

        except Exception as e:
            logger.exception("Signin failed")
            return render_template('sign-in.html', error="Login error.")

    return render_template('sign-in.html')

@app.route('/logout')
def logout():
    session.clear()
    supabase.auth.sign_out()
    return redirect(url_for('home'))

@app.route('/debug/profiles')
def debug_profiles():
    try:
        response = supabase.table('profiles').select('*').execute()
        return render_template('debug.html', profiles=response.data)
    except Exception as e:
        logger.exception("Error fetching profiles")
        return f"Error: {str(e)}"

if __name__ == '__main__':
    app.run(debug=True)
