from flask import Flask, request, render_template, redirect, url_for
from supabase import create_client, Client
from dotenv import load_dotenv
import os
from werkzeug.security import generate_password_hash, check_password_hash

# Load environment variables
load_dotenv()
supabase_url = os.getenv("SUPABASE_URL")
supabase_key = os.getenv("SUPABASE_KEY")

if not supabase_url or not supabase_key:
    raise ValueError("Supabase credentials not found. Check .env file.")

# Create Supabase client
supabase: Client = create_client(supabase_url, supabase_key)

app = Flask(__name__, static_folder='assets', template_folder='templates')


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

        # Basic validation
        if not username or not email or not password:
            return render_template('sign-up.html', error="All fields are required")

        # Check if email already exists
        existing = supabase.table('profiles').select('email').eq('email', email).execute()
        if existing.data:
            return render_template('sign-up.html', error="Email already registered")

        try:
            # Sign up with Supabase Auth
            auth_response = supabase.auth.sign_up({"email": email, "password": password})
            user = auth_response.user

            if user:
                # Store user details in 'profiles' table with Supabase UID
                hashed_password = generate_password_hash(password)
                supabase.table('profiles').insert({
                    "id": user.id,  # Supabase Auth UID
                    "username": username,
                    "email": email,
                    "password": hashed_password
                }).execute()

                return redirect(url_for('signin'))
            else:
                return render_template('sign-up.html', error="Auth failed. Please try again.")

        except Exception as e:
            return render_template('sign-up.html', error=str(e))

    return render_template('sign-up.html')


@app.route('/sign-in', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        try:
            # Sign in with Supabase Auth
            response = supabase.auth.sign_in_with_password({"email": email, "password": password})

            if response.session:
                # Fetch user profile
                profile = supabase.table('profiles').select('*').eq('email', email).execute()
                if profile.data:
                    return render_template("welcome.html", user=profile.data[0])
            return render_template('sign-in.html', error="Login failed.")

        except Exception:
            return render_template('sign-in.html', error="Invalid email or password")

    return render_template('sign-in.html')


if __name__ == '__main__':
    app.run(debug=True)
