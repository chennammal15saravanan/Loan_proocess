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

        # Input check
        if not username or not email or not password:
            print("[ERROR] Missing form input")
            return render_template('sign-up.html', error="All fields are required")

        try:
            # 1. Register user with Supabase Auth
            auth_response = supabase.auth.sign_up({
                "email": email,
                "password": password
            })

            # 2. Extract user ID (UUID) from auth.users
            user = auth_response.user
            if not user:
                print("[ERROR] Supabase Auth failed, no user returned")
                return render_template('sign-up.html', error="Signup failed. Please check your email confirmation.")

            user_id = user.id
            print(f"[INFO] User created with ID: {user_id}")

            # 3. Insert into profiles with foreign key UUID
            hashed_password = generate_password_hash(password)
            insert_response = supabase.table('profiles').insert({
                "id": user_id,
                "username": username,
                "email": email,
                "password": hashed_password
            }).execute()

            if insert_response.data:
                print(f"[SUCCESS] User profile inserted into DB: {insert_response.data}")
                return redirect(url_for('signin'))
            else:
                print("[ERROR] Insert response empty")
                return render_template('sign-up.html', error="Could not save user profile.")

        except Exception as e:
            print(f"[EXCEPTION] {e}")
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
