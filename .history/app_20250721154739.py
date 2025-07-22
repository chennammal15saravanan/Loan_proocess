from flask import Flask, request, render_template, redirect, url_for, session, flash
from supabase import create_client, Client
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import re
import logging
import uuid

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    logger.error("Supabase credentials not found. Check .env file.")
    raise ValueError("Supabase credentials not found. Check .env file.")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
logger.info("Supabase client initialized successfully")

app = Flask(__name__, static_folder='assets', template_folder='templates')
app.secret_key = os.getenv("FLASK_SECRET_KEY", str(uuid.uuid4()))

# Validation functions
def is_valid_email(email):
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(regex, email)

def is_valid_username(username):
    return len(username) >= 3 and username.isalnum()

def is_valid_password(password):
    return len(password) >= 8

def is_valid_sign_up_as(sign_up_as):
    return sign_up_as in ['merchant', 'loan_borrower', 'NBFC Admin']

@app.route('/')
def home():
    return redirect(url_for('signin'))

@app.route('/sign-up', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        sign_up_as = request.form.get('signup_as')

        # Validation
        if not all([username, email, password, sign_up_as]):
            flash("All fields are required.", "error")
            return render_template('sign-up.html')

        if not is_valid_email(email):
            flash("Invalid email format.", "error")
            return render_template('sign-up.html')

        if not is_valid_username(username):
            flash("Username must be at least 3 characters and alphanumeric.", "error")
            return render_template('sign-up.html')

        if not is_valid_password(password):
            flash("Password must be at least 8 characters.", "error")
            return render_template('sign-up.html')

        if not is_valid_sign_up_as(sign_up_as):
            flash("Invalid role selected.", "error")
            return render_template('sign-up.html')

        try:
            # Check if username or email already exists
            if supabase.table('users').select('username').eq('username', username).execute().data:
                flash("Username already taken.", "error")
                return render_template('sign-up.html')

            if supabase.table('users').select('email').eq('email', email).execute().data:
                flash("Email already registered.", "error")
                return render_template('sign-up.html')

            # Create user
            hashed_password = generate_password_hash(password)
            user_data = {
                'id': str(uuid.uuid4()),
                'username': username,
                'email': email,
                'password': hashed_password,
                'sign_up_as': sign_up_as,
                'created_at': datetime.utcnow().isoformat()
            }

            response = supabase.table('users').insert(user_data).execute()
            if response.data:
                session['user_id'] = user_data['id']
                session['username'] = username
                session['sign_in_as'] = sign_up_as
                flash("Sign-up successful!", "info")
                return redirect(url_for('dashboard'))
            else:
                flash("Database error: could not insert user.", "error")

        except Exception as e:
            logger.error(f"Sign-up error: {str(e)}")
            flash(f"Sign-up failed: {str(e)}", "error")

    return render_template('sign-up.html')

@app.route('/sign-in', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        sign_in_as = request.form.get('signin_as')

        if not all([email, password, sign_in_as]):
            flash("All fields are required.", "error")
            return render_template('sign-in.html')

        if not is_valid_email(email):
            flash("Invalid email format.", "error")
            return render_template('sign-in.html')

        if not is_valid_sign_up_as(sign_in_as):
            flash("Invalid role selected.", "error")
            return render_template('sign-in.html')

        try:
            user = supabase.table('users').select('*').eq('email', email).execute()
            if not user.data:
                flash("Invalid credentials.", "error")
                return render_template('sign-in.html')

            user_data = user.data[0]
            if check_password_hash(user_data['password'], password) and user_data['sign_up_as'] == sign_in_as:
                session['user_id'] = user_data['id']
                session['username'] = user_data['username']
                session['sign_in_as'] = sign_in_as
                flash("Signed in successfully!", "info")
                return redirect(url_for('dashboard'))
            else:
                flash("Incorrect password or role.", "error")

        except Exception as e:
            logger.error(f"Sign-in error: {str(e)}")
            flash(f"Sign-in failed: {str(e)}", "error")

    return render_template('sign-in.html')

@app.route('/dashboard')
def dashboard():

    if 'user_id' not in session:
        flash("Please sign in to continue.", "error")
        return redirect(url_for('signin'))

    role = session.get('sign_in_as')
    username = session.get('username')

    if role == 'merchant':
        return render_template('Merchant.html', username=username, role=role)
    elif role == 'loan_borrower':
        return render_template('loan-browser.html', username=username, role=role)
    elif role == 'admin':
        return render_template('admin.html', username=username, role=role)
    else:
        flash("Invalid role. Please sign in again.", "error")
        return redirect(url_for('signin'))
@app.route('/merchant-profile')
def merchant_profile():
    if 'user_id' not in session:
        flash("Please sign in to continue.", "error")
        return redirect(url_for('signin'))

    role = session.get('sign_in_as')
    if role != 'merchant':
        flash("Access denied. This page is for merchants only.", "error")
        return redirect(url_for('dashboard'))

    username = session.get('username')
    email = session.get('email')  # Assume email is stored in session or retrieved from Supabase

    # Fetch merchant details from Supabase (example)
    try:
        user_data = supabase.table('users').select('*').eq('id', session['user_id']).execute().data[0]
        merchant_id = user_data.get('merchant_id', f"MERCH{user_data['id'][:8]}")  # Auto-generated
        business_name = user_data.get('business_name', 'N/A')
        phone_number = user_data.get('phone_number', 'N/A')
        age = user_data.get('age', 'N/A')
        business_type = user_data.get('business_type', 'N/A')
        business_category = user_data.get('business_category', 'N/A')
        business_address = user_data.get('business_address', 'N/A')
        gst_number = user_data.get('gst_number', 'N/A')
        pan_number = user_data.get('pan_number', 'N/A')
        bank_name = user_data.get('bank_name', 'N/A')
        account_number = user_data.get('account_number', 'N/A')
        ifsc_code = user_data.get('ifsc_code', 'N/A')
        upi_id = user_data.get('upi_id', 'N/A')
        account_status = user_data.get('account_status', 'Pending')
    except Exception as e:
        flash(f"Error fetching profile data: {str(e)}", "error")
        return redirect(url_for('dashboard'))

    return render_template('merchant_profile.html', 
                          username=username, 
                          email=email, 
                          merchant_id=merchant_id,
                          business_name=business_name,
                          phone_number=phone_number,
                          age=age,
                          business_type=business_type,
                          business_category=business_category,
                          business_address=business_address,
                          gst_number=gst_number,
                          pan_number=pan_number,
                          bank_name=bank_name,
                          account_number=account_number,
                          ifsc_code=ifsc_code,
                          upi_id=upi_id,
                          account_status=account_status,
                          role=role)
@app.route('/loan-profiles')
def loan_profiles():
    if 'user_id' not in session:
        flash("Please sign in to continue.", "error")
        return redirect(url_for('signin'))

    role = session.get('sign_in_as')
    if role != 'loan_borrower':
        flash("Access denied. This page is for loan borrowers only.", "error")
        return redirect(url_for('dashboard'))

    username = session.get('username')
    email = session.get('email')  # Assume email is stored in session or retrieved later

    # Placeholder data (to be replaced with Supabase fetch)
    full_name = session.get('full_name', username)  # Default to username if not set
    loan_browser_id = session.get('loan_browser_id', f"LB{session['user_id'][:8]}")  # Auto-generated
    mobile_number = session.get('mobile_number', 'N/A')
    date_of_birth = session.get('date_of_birth', '1990-01-01')
    gender = session.get('gender', 'male')
    address = session.get('address', 'N/A, N/A, 123456')
    date_of_joining = session.get('date_of_joining', '2023-01-01')

    return render_template('loan_profiles.html', 
                          username=username, 
                          email=email,
                          full_name=full_name,
                          loan_browser_id=loan_browser_id,
                          mobile_number=mobile_number,
                          date_of_birth=date_of_birth,
                          gender=gender,
                          address=address,
                          date_of_joining=date_of_joining,
                          role=role)

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('signin'))

@app.route('/debug/users')
def debug_users():
    try:
        users = supabase.table('users').select('*').execute()
        return render_template('debug.html', users=users.data)
    except Exception as e:
        return f"Error: {str(e)}"
    

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)