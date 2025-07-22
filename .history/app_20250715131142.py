from flask import Flask, request, render_template, redirect, url_for, session
from supabase import create_client, Client
from dotenv import load_dotenv
import os
import re

# Load environment variables
load_dotenv()
supabase_url = os.getenv("SUPABASE_URL")
supabase_key = os.getenv("SUPABASE_KEY")

if not supabase_url or not supabase_key:
    raise ValueError("Supabase credentials not found. Check .env file.")

# Create Supabase client
supabase: Client = create_client(supabase_url, supabase_key)

app = Flask(__name__, static_folder='assets', template_folder='templates')
app.secret_key = os.getenv("FLASK_SECRET_KEY", "your-secret-key")  # Required for session management

# Input validation helper
def is_valid_email(email):
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(regex, email)

def is_valid_password(password):
    return len(password) >= 8  # Example: Minimum 8 characters

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

        # Input validation
        if not username or not email or not password:
            return render_template('sign-up.html', error="All fields are required")
        if not is_valid_email(email):
            return render_template('sign-up.html', error="Invalid email format")
        if not is_valid_password(password):
            return render_template('sign-up.html', error="Password must be at least 8 characters")

        try:
            # Register user with Supabase Auth
            auth_response = supabase.auth.sign_up({
                "email": email,
                "password": password,
                "options": {
                    "data": {"username": username}  # Store username in auth metadata
                }
            })

            # Extract user ID
            user = auth_response.user
            if not user:
                print("[ERROR] Supabase Auth failed, no user returned")
                return render_template('sign-up.html', error="Signup failed. Please check your email confirmation.")

            user_id = user.id
            print(f"[INFO] User created with ID: {user_id}")

            # Check if email is confirmed (if required by Supabase settings)
            if not user.email_confirmed_at and supabase.auth.get_session():
                return render_template('sign-up.html', error="Please confirm your email before proceeding.")

            # Insert into profiles table (no password, as it's handled by Supabase Auth)
            insert_response = supabase.table('profiles').insert({
                "id": user_id,
                "username": username,
                "email": email
            }).execute()

            if insert_response.data:
                print(f"[SUCCESS] User profile inserted into DB: {insert_response.data}")
                return redirect(url_for('signin'))
            else:
                print("[ERROR] Insert response empty")
                return render_template('sign-up.html', error="Could not save user profile.")

        except Exception as e:
            print(f"[EXCEPTION] {str(e)}")
            return render_template('sign-up.html', error=f"Error: {str(e)}")

    return render_template('sign-up.html')

@app.route('/sign-in', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Input validation
        if not email or not password:
            return render_template('sign-in.html', error="Email and password are required")
        if not is_valid_email(email):
            return render_template('sign-in.html', error="Invalid email format")

        try:
            # Sign in with Supabase Auth
            response = supabase.auth.sign_in_with_password({"email": email, "password": password})

            if response.session:
                # Store session token and user ID in Flask session
                session['user_id'] = response.user.id
                session['access_token'] = response.session.access_token

                # Fetch user profile
                profile = supabase.table('profiles').select('*').eq('email', email).execute()
                if profile.data:
                    return render_template("welcome.html", user=profile.data[0])
                return render_template('sign-in.html', error="Profile not found.")
            return render_template('sign-in.html', error="Login failed.")

        except Exception as e:
            print(f"[EXCEPTION] {str(e)}")
            return render_template('sign-in.html', error="Invalid email or password")

    return render_template('sign-in.html')

@app.route('/logout')
def logout():
    session.clear()
    supabase.auth.sign_out()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)