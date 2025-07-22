from flask import Flask, render_template, request, redirect, url_for
from supabase import create_client
from dotenv import load_dotenv
import os
from werkzeug.security import generate_password_hash

# Load .env values
load_dotenv()
supabase_url = os.getenv("SUPABASE_URL")
supabase_key = os.getenv("SUPABASE_KEY")
supabase = create_client(supabase_url, supabase_key)

app = Flask(__name__, static_folder='assets', template_folder='templates')

@app.route('/')
def home():
    return render_template('sign-in.html')

@app.route('/sign-up', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_password = generate_password_hash(password)

        existing = supabase.table('profiles').select('email').eq('email', email).execute()
        if existing.data:
            return render_template('sign-up.html', error="Email already registered")

        try:
            auth_response = supabase.auth.sign_up({"email": email, "password": password})
            if auth_response.user:
                supabase.table('profiles').insert({
                    "id": auth_response.user.id,
                    "username": username,
                    "email": email,
                    "password": hashed_password
                }).execute()
                return redirect(url_for('home'))
        except Exception as e:
            return render_template('sign-up.html', error=str(e))

    return render_template('sign-up.html')

@app.route('/sign-in', methods=['GET'])
def signin():
    return render_template('sign-in.html')

if __name__ == '__main__':
    app.run(debug=True)
