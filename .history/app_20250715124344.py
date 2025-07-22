from flask import Flask, request, render_template, jsonify, redirect, url_for
from supabase import create_client, Client
from dotenv import load_dotenv
import os
from werkzeug.security import generate_password_hash, check_password_hash

   # Load environment variables
load_dotenv()
supabase_url = os.getenv("SUPABASE_URL")
supabase_key = os.getenv("SUPABASE_KEY")

   # Create Supabase client
supabase: Client = create_client(supabase_url, supabase_key)

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
                return redirect(url_for('signin'))
        except Exception as e:
            return render_template('sign-up.html', error=str(e))

    return render_template('sign-up.html')

@app.route('/sign-in', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
    email = request.form.get('email')
        password = request.form.get('password')

           try:
               response = supabase.auth.sign_in_with_password({"email": email, "password": password})
               if response.session:
                   profile = supabase.table('profiles').select('*').eq('email', email).execute()
                   if profile.data:
                       return render_template("welcome.html", user=profile.data[0])
           except Exception:
               return render_template('sign-in.html', error="Invalid email or password")

       return render_template('sign-in.html')

   if __name__ == '__main__':
       app.run(debug=True)