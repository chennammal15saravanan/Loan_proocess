from flask import Flask, request, render_template, jsonify
from supabase import create_client, Client
from dotenv import load_dotenv
import os
from werkzeug.security import generate_password_hash, check_password_hash

# Load environment variables
load_dotenv()
supabase_url = os.getenv("SUPABASE_URL")
supabase_key = os.getenv("SUPABASE_KEY")

# ✅ Create Supabase client
supabase: Client = create_client(supabase_url, supabase_key)

app = Flask(__name__, static_folder='assets', template_folder='templates')
@app.route('/')
def home():
    return render_template('sign-in.html')  # or 'sign-up.html' if you want
@app.route('/')
def home():
    return render_template('sign-up.html')  # or 'sign-up.html' if you want
# Sign-up route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)

        response = supabase.table('profiles').select('email').eq('email', email).execute()
        if response.data:
            return jsonify({"error": "Email already registered"}), 400

        try:
            auth_response = supabase.auth.sign_up({"email": email, "password": password})
            if auth_response.user:
                supabase.table('profiles').insert({
                    "id": auth_response.user.id,
                    "email": email,
                    "username": username,
                    "password": hashed_password
                }).execute()
                return jsonify({"message": "Sign-up successful, please verify your email"}), 201
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    return render_template('sign-up.html')

# Sign-in route
@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        try:
            response = supabase.auth.sign_in_with_password({"email": email, "password": password})
            if response.session:
                profile = supabase.table('profiles').select('*').eq('email', email).execute()
                if profile.data:
                    return jsonify({"message": "Login successful", "user": profile.data[0]}), 200
        except Exception as e:
            return jsonify({"error": "Invalid credentials"}), 401

    return render_template('sign-in.html')

if __name__ == '__main__':
    app.run(debug=True)
