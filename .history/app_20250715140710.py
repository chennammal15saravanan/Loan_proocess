from flask import Flask, request, render_template, redirect, url_for, session
from supabase import create_client, Client
from dotenv import load_dotenv
import os
import re
import logging
import httpx

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
    logger.info("" \
    "" \
    " client initialized successfully")
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

@app.route('/sign-up', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        # Input validation
        if not username or not email or not password:
            logger.error("Missing form input: username, email, or password")
            return render_template('sign-up.html', error="All fields are required")
        if not is_valid_email(email):
            logger.error(f"Invalid email format: {email}")
            return render_template('sign-up.html', error="Invalid email format")
        if not is_valid_username(username):
            logger.error(f"Invalid username: {username}")
            return render_template('sign-up.html', error="Username must be at least 3 characters and alphanumeric")
        if not is_valid_password(password):
            logger.error("Invalid password: less than 8 characters")
            return render_template('sign-up.html', error="Password must be at least 8 characters")

        try:
            # Step 1: Register user with Supabase Auth
            logger.info(f"Attempting to register user with email: {email}")
            auth_response = supabase.auth.sign_up({
                "email": email,
                "password": password,
                "options": {
                    "data": {"username": username}  # Store username in auth metadata
                }
            })

            # Step 2: Extract user ID from auth response
            user = auth_response.user
            if not user:
                logger.error("Supabase Auth failed, no user returned")
                return render_template('sign-up.html', error="Signup failed. Please check your email confirmation.")

            user_id = user.id
            logger.info(f"User created with ID: {user_id}")

            # Step 3: Store user details in the 'profiles' table
            logger.info(f"Inserting user profile into 'profiles' table: username={username}, email={email}")
            insert_response = supabase.table('profiles').insert({
                "id": user_id,
                "username": username,
                "email": email
            }).execute()

            # Step 4: Verify database insertion
            if insert_response.data:
                logger.info(f"User profile inserted into DB: {insert_response.data}")
                return redirect(url_for('signin'))
            else:
                logger.error("Insert response empty: could not save user profile")
                return render_template('sign-up.html', error="Could not save user profile to database.")

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 500:
                logger.error(f"Supabase Auth 500 error: {e.response.text}")
                return render_template('sign-up.html', error="Server error. Please try again later.")
            elif e.response.status_code == 400 and "already registered" in e.response.text.lower():
                logger.error(f"Email already registered: {email}")
                return render_template('sign-up.html', error="Email is already registered.")
            logger.exception(f"HTTP error during signup: {str(e)}")
            return render_template('sign-up.html', error=f"Error: {str(e)}")
        except Exception as e:
            logger.exception(f"Failed to store user details: {str(e)}")
            return render_template('sign-up.html', error=f"Error: {str(e)}")

    logger.info("Rendering sign-up page (GET request)")
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