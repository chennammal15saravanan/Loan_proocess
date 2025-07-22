from flask import Flask, request, render_template, redirect, url_for
from supabase import create_client, Client
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()
supabase_url = os.getenv("SUPABASE_URL")
supabase_key = os.getenv("SUPABASE_KEY")

# Create Supabase client
supabase: Client = create_client(supabase_url, supabase_key)

app = Flask(__name__, static_folder='assets', template_folder='templates')

# Home route redirects to sign-in
@app.route('/')
def home():
    return redirect(url_for('signin'))

# Sign-up page route
@app.route('/sign-up', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        # Validate input
        if not username or not email or not password:
            return render_template('sign-up.html', error="All fields are required")

        # Check if email already exists
        existing = supabase.table('profiles').select('email').eq('email', email).execute()
        if existing.data:
            return render_template('sign-up.html', error="Email already registered")

        try:
            # Sign up user with Supabase Auth
            auth_response = supabase.auth.sign_up({"email": email, "password": password})
            if auth_response.user:
                # Insert user details into profiles table (excluding password)
                supabase.table('profiles').insert({
                    "id": auth_response.user.id,
                    "username": username,
                    "email": email
                }).execute()
                return redirect(url_for('signin'))
        except Exception as e:
            return render_template('sign-up.html', error=f"Sign-up failed: {str(e)}")

    return render_template('sign-up.html')

# Sign-in page route
@app.route('/sign-in', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Validate input
        if not email or not password:
            return render_template('sign-in.html', error="Email and password are required")

        try:
            # Sign in user with Supabase Auth
            response = supabase.auth.sign_in_with_password({"email": email, "password": password})
            if response.session:
                # Fetch user profile from profiles table
                profile = supabase.table('profiles').select('*').eq('email', email).execute()
                if profile.data:
                    return render_template("welcome.html", user=profile.data[0])
                else:
                    return render_template('sign-in.html', error="Profile not found")
        except Exception as e:
            return render_template('sign-in.html', error="Invalid email or password")

    return render_template('sign-in.html')

if __name__ == '__main__':
    app.run(debug=True)