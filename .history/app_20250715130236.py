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

        # Validation
        if not username or not email or not password:
            return render_template('sign-up.html', error="All fields are required")

        # Check if user already exists
        existing = supabase.table('profiles').select('*').eq('email', email).execute()
        if existing.data:
            return render_template('sign-up.html', error="Email already exists")

        try:
            # Sign up user using Supabase Auth (optional, for login purpose)
            supabase.auth.sign_up({"email": email, "password": password})

            # Save to database manually
            hashed_password = generate_password_hash(password)
            result = supabase.table('profiles').insert({
                "username": username,
                "email": email,
                "password": hashed_password
            }).execute()

            if result.data:
                return redirect(url_for('signin'))
            else:
                return render_template('sign-up.html', error="Failed to save to database")

        except Exception as e:
            return render_template('sign-up.html', error=f"Error: {str(e)}")

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
