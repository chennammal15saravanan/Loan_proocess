from flask import Flask, request, render_template, redirect, url_for, session
from supabase import create_client, Client
import os
import bcrypt
from dotenv import load_dotenv
from gotrue.errors import AuthApiError


load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your_random_flask_secret_key')
app.static_folder = 'assets'
app.static_url_path = '/assets'

# Supabase configuration
url = os.environ.get("SUPABASE_URL", "https://ysycfzejjbefsbdjqyrt.supabase.co")
key = os.environ.get("SUPABASE_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InlzeWNmemVqamJlZnNiZGpxeXJ0Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc1MjQ5NDMxNiwiZXhwIjoyMDY4MDcwMzE2fQ.KbTFlrLwjbqzpK5kbBVUsfXeLOHM3Mm5GcLMKQl_lfU")
supabase: Client = create_client(url, key)

@app.route('/')
def home():
    if 'user' in session:
        return render_template('home.html', username=session['user'])
    return redirect(url_for('signin'))

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    error = None
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        if not email or not password:
            error = "Please provide both email and password"
        else:
            try:
                # Query Supabase for user
                response = supabase.from_('profiles').select('email, password, username').eq('email', email).execute()
                if response.data and len(response.data) > 0:
                    stored_password = response.data[0]['password']
                    if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                        session['user'] = response.data[0]['username']
                        session['email'] = email
                        return redirect(url_for('home'))
                    else:
                        error = "Invalid password"
                else:
                    error = "Email not found"
            except Exception as e:
                error = f"Error during sign-in: {str(e)}"
    return render_template('Signin.html', error=error)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        terms_accepted = request.form.get('condition') == 'on'

        if not username or not email or not password:
            error = "Please fill in all fields"
        elif not terms_accepted:
            error = "You must agree to the Terms & Conditions"
        elif len(password) < 8:
            error = "Password must be at least 8 characters"
        else:
            # Check if email already exists
            response = supabase.from_('profiles').select('email').eq('email', email).execute()
            if response.data:
                error = "Email already registered"
            else:
                try:
                    # Hash the password
                    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                    # Sign up with Supabase Auth
                    auth_response = supabase.auth.sign_up({
                        "email": email,
                        "password": password,
                        "options": {"data": {"username": username}}
                    })
                    if auth_response.user:
                        # Check if profile already exists (in case of trigger)
                        profile_check = supabase.from_('profiles').select('id').eq('id', auth_response.user.id).execute()
                        if not profile_check.data:
                            # Insert into profiles table
                            supabase.from_('profiles').insert({
                                'id': auth_response.user.id,
                                'email': email,
                                'username': username,
                                'password': hashed_password
                            }).execute()
                        session['user'] = username
                        session['email'] = email
                        return redirect(url_for('home'))
                    else:
                        error = "Sign-up failed. Please try again."
                except AuthApiError as e:
                    error = f"Authentication error: {str(e)}"
                except Exception as e:
                    error = f"Error during sign-up: {str(e)}"
    return render_template('Signup.html', error=error)

@app.route('/logout')
def logout():
    supabase.auth.sign_out()
    session.pop('user', None)
    session.pop('email', None)
    return redirect(url_for('signin'))

if __name__ == '__main__':
    app.run(debug=True)