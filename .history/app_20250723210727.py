from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify
from supabase import create_client, Client
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
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
app.permanent_session_lifetime = timedelta(days=1)

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

def is_valid_aadhar_number(aadhar_number):
    regex = r'^\d{12}$'
    return re.match(regex, aadhar_number)

def is_valid_pan_number(pan_number):
    regex = r'^[A-Z]{5}\d{4}[A-Z]{1}$'
    return re.match(regex, pan_number)

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
        phone = request.form.get('phone')
        age = request.form.get('age')

        # Validate required fields
        if not all([username, email, password, sign_up_as]):
            flash("Username, email, password, and role are required.", "error")
            logger.error("Missing required fields: username, email, password, or sign_up_as")
            return render_template('sign-up.html')

        # Validate email
        if not is_valid_email(email):
            flash("Invalid email format.", "error")
            logger.error(f"Invalid email format: {email}")
            return render_template('sign-up.html')

        # Validate username
        if not is_valid_username(username):
            flash("Username must be at least 3 characters and alphanumeric.", "error")
            logger.error(f"Invalid username: {username}")
            return render_template('sign-up.html')

        # Validate password
        if not is_valid_password(password):
            flash("Password must be at least 8 characters.", "error")
            logger.error("Invalid password: too short")
            return render_template('sign-up.html')

        # Validate sign_up_as
        valid_roles = ['merchant', 'loan_borrower', 'nbfc_admin']
        if sign_up_as not in valid_roles:
            flash("Invalid role selected.", "error")
            logger.error(f"Invalid role: {sign_up_as}")
            return render_template('sign-up.html')

        # Validate phone (optional)
        if phone and not re.match(r'^\+?\d{10,15}$', phone):
            flash("Invalid phone number format.", "error")
            logger.error(f"Invalid phone number: {phone}")
            return render_template('sign-up.html')

        # Validate age (optional)
        if age:
            try:
                age = int(age)
                if age < 18:
                    flash("Age must be at least 18.", "error")
                    logger.error(f"Invalid age: {age}")
                    return render_template('sign-up.html')
            except ValueError:
                flash("Age must be a valid number.", "error")
                logger.error(f"Invalid age format: {age}")
                return render_template('sign-up.html')
        else:
            age = None

        try:
            # Check if username exists
            username_check = supabase.table('user_profiles').select('username').eq('username', username).execute()
            if username_check.data:
                flash("Username already taken.", "error")
                logger.error(f"Username already taken: {username}")
                return render_template('sign-up.html')

            # Check if email exists
            email_check = supabase.table('user_profiles').select('email').eq('email', email).execute()
            if email_check.data:
                flash("Email already registered.", "error")
                logger.error(f"Email already registered: {email}")
                return render_template('sign-up.html')

            # Generate user ID
            user_id = str(uuid.uuid4())

            # Hash password
            hashed_password = generate_password_hash(password)

            # Prepare user data
            user_data = {
                'id': user_id,
                'username': username,
                'email': email,
                'password': hashed_password,
                'sign_up_as': sign_up_as,
                'phone': phone or None,
                'age': age,
                'created_at': datetime.utcnow().isoformat(),
            }

            # Insert into user_profiles table
            response = supabase.table('user_profiles').insert(user_data).execute()
            if response.data:
                session.permanent = True
                session['user_id'] = user_id
                session['username'] = username
                session['sign_in_as'] = sign_up_as
                logger.info(f"User signed up: {username}, role: {sign_up_as}, phone: {phone}, age: {age}")
                flash("Sign-up successful!", "info")
                return redirect(url_for('dashboard'))
            else:
                flash("Database error: could not insert user.", "error")
                logger.error("Database error: could not insert user")
                return render_template('sign-up.html')

        except Exception as e:
            logger.error(f"Sign-up error: {str(e)}")
            if 'infinite recursion detected' in str(e).lower():
                flash("Sign-up failed due to a database configuration error. Please contact support.", "error")
            else:
                flash(f"Sign-up failed: {str(e)}", "error")
            return render_template('sign-up.html')

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
            user = supabase.table('user_profiles').select('*').eq('email', email).execute()
            if not user.data:
                flash("Invalid credentials.", "error")
                return render_template('sign-in.html')

            user_data = user.data[0]
            if check_password_hash(user_data['password'], password) and user_data['sign_up_as'] == sign_in_as:
                session.permanent = True
                session['user_id'] = user_data['id']
                session['username'] = user_data['username']
                session['sign_in_as'] = sign_in_as
                logger.info(f"User signed in: {user_data['username']}, role: {sign_in_as}")
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
    logger.info(f"Accessing dashboard, session: {session.get('user_id')}, {session.get('sign_in_as')}")
    if 'user_id' not in session:
        flash("Please sign in to continue.", "error")
        return redirect(url_for('signin'))

    role = session.get('sign_in_as')
    username = session.get('username')

    if role == 'merchant':
        try:
            products = supabase.table('products').select('*').eq('user_id', session['user_id']).execute().data
            return render_template('Merchant.html', username=username, role=role, products=products or [])
        except Exception as e:
            logger.error(f"Error fetching products: {str(e)}")
            flash(f"Error fetching products: {str(e)}", "error")
            return render_template('Merchant.html', username=username, role=role, products=[])
    elif role == 'loan_borrower':
        return render_template('loan-browser.html', username=username, role=role)
    elif role == 'NBFC Admin':
        return render_template('admin.html', username=username, role=role)
    else:
        flash("Invalid role. Please sign in again.", "error")
        return redirect(url_for('signin'))

@app.route('/add-product', methods=['POST'])
def add_product():
    if 'user_id' not in session:
        flash("Please sign in to add a product.", "error")
        return jsonify({'error': 'Unauthorized'}), 401

    user_id = session['user_id']
    name = request.form.get('productName')
    description = request.form.get('productDescription')
    price = request.form.get('productPrice')

    if not all([name, price]):
        flash("Name and price are required.", "error")
        return jsonify({'error': 'Name and price are required'}), 400

    try:
        product_data = {
            'user_id': user_id,
            'name': name,
            'description': description,
            'price': float(price),
            'created_at': datetime.utcnow().isoformat()
        }

        response = supabase.table('products').insert(product_data).execute()

        if response.data:
            flash("Product added successfully!", "info")
            return jsonify({'message': 'Product added successfully', 'product': response.data[0]}), 200
        else:
            flash("Failed to add product.", "error")
            return jsonify({'error': 'Failed to add product'}), 500

    except Exception as e:
        logger.error(f"Error adding product: {str(e)}")
        flash(f"Error: {str(e)}", "error")
        return jsonify({'error': str(e)}), 500

@app.route('/update-product/<product_id>', methods=['POST'])
def update_product(product_id):
    if 'user_id' not in session:
        logger.error("Unauthorized access: No user_id in session")
        flash("Please sign in to update a product.", "error")
        return jsonify({'error': 'Unauthorized'}), 401

    user_id = session['user_id']
    name = request.form.get('productName')
    description = request.form.get('productDescription')
    price = request.form.get('productPrice')

    logger.info(f"Updating product {product_id} for user {user_id}: name={name}, description={description}, price={price}")

    if not all([name, price]):
        logger.error("Missing required fields: name or price")
        flash("Name and price are required.", "error")
        return jsonify({'error': 'Name and price are required'}), 400

    try:
        product = supabase.table('products').select('*').eq('product_id', product_id).eq('user_id', user_id).execute()
        logger.info(f"Product query result: {product.data}")
        if not product.data:
            logger.error(f"Product not found or unauthorized: {product_id}")
            flash("Product not found or unauthorized.", "error")
            return jsonify({'error': 'Product not found or unauthorized'}), 403

        product_data = {
            'name': name,
            'description': description,
            'price': float(price)
        }

        response = supabase.table('products').update(product_data).eq('product_id', product_id).execute()
        logger.info(f"Update response: {response.data}")
        if response.data:
            flash("Product updated successfully!", "info")
            return jsonify({'message': 'Product updated successfully', 'product': response.data[0]}), 200
        else:
            logger.error("Failed to update product: No data in response")
            flash("Failed to update product.", "error")
            return jsonify({'error': 'Failed to update product'}), 500

    except Exception as e:
        logger.error(f"Error updating product: {str(e)}")
        flash(f"Error: {str(e)}", "error")
        return jsonify({'error': str(e)}), 500

@app.route('/get-products', methods=['GET'])
def get_products():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        products = supabase.table('products').select('*').eq('user_id', session['user_id']).execute().data
        return jsonify({'products': products or []}), 200
    except Exception as e:
        logger.error(f"Error fetching products: {str(e)}")
        return jsonify({'error': str(e)}), 500

from werkzeug.utils import secure_filename

@app.route('/add-loan', methods=['POST'])
def add_loan():
    if 'user_id' not in session:
        logger.error("Unauthorized access: No user_id in session")
        return jsonify({'error': 'Unauthorized'}), 401

    user_id = session['user_id']
    first_name = request.form.get('first_name')
    last_name = request.form.get('last_name')
    dob = request.form.get('dob')
    age = request.form.get('age')
    phone = request.form.get('phone')
    address = request.form.get('address')
    occupation = request.form.get('occupation')
    monthly_income = request.form.get('monthlyIncome')
    loan_amount = request.form.get('loanAmount')
    loan_purpose = request.form.get('loanPurpose')
    aadhar_number = request.form.get('aadharNumber')
    pan_number = request.form.get('panNumber')
    aadhar_file = request.files.get('aadharFile')
    pan_file = request.files.get('panFile')

    # Validate required fields
    if not all([first_name, last_name, dob, age, phone, address, occupation,
                monthly_income, loan_amount, loan_purpose, aadhar_number, pan_number,
                aadhar_file, pan_file]):
        logger.error("Missing required fields in loan application")
        return jsonify({'error': 'All fields are required'}), 400

    # Validate Aadhar number
    if not is_valid_aadhar_number(aadhar_number):
        logger.error(f"Invalid Aadhar number: {aadhar_number}")
        return jsonify({'error': 'Aadhar number must be a 12-digit number'}), 400

    # Validate PAN number
    if not is_valid_pan_number(pan_number):
        logger.error(f"Invalid PAN number: {pan_number}")
        return jsonify({'error': 'PAN number must be in the format ABCDE1234F'}), 400

    # Validate age
    try:
        age = int(age)
        if age < 18:
            logger.error(f"Invalid age: {age}")
            return jsonify({'error': 'Age must be at least 18'}), 400
    except ValueError:
        logger.error(f"Invalid age format: {age}")
        return jsonify({'error': 'Age must be a valid number'}), 400

    # Validate phone
    if not re.match(r'^\+?\d{10,15}$', phone):
        logger.error(f"Invalid phone number: {phone}")
        return jsonify({'error': 'Phone number must be 10-15 digits, optionally starting with +'}), 400

    # Validate file types and sizes
    if aadhar_file and (not aadhar_file.filename.endswith('.pdf') or aadhar_file.content_length > 5 * 1024 * 1024):
        logger.error("Invalid Aadhar file: not a PDF or exceeds 5MB")
        return jsonify({'error': 'Aadhar file must be a PDF and less than 5MB'}), 400
    if pan_file and (not pan_file.filename.endswith('.pdf') or pan_file.content_length > 5 * 1024 * 1024):
        logger.error("Invalid PAN file: not a PDF or exceeds 5MB")
        return jsonify({'error': 'PAN file must be a PDF and less than 5MB'}), 400

    try:
        # Check for duplicate Aadhar or PAN
        aadhar_check = supabase.table('loans').select('aadhaar_number').eq('aadhaar_number', aadhar_number).execute()
        if aadhar_check.data:
            logger.error(f"Aadhar number already used: {aadhar_number}")
            return jsonify({'error': 'Aadhar number already used'}), 400

        pan_check = supabase.table('loans').select('pan_number').eq('pan_number', pan_number).execute()
        if pan_check.data:
            logger.error(f"PAN number already used: {pan_number}")
            return jsonify({'error': 'PAN number already used'}), 400

        # Upload files to Supabase Storage
        aadhar_path = f'aadhar/{user_id}_{secure_filename(aadhar_file.filename)}'
        pan_path = f'pan/{user_id}_{secure_filename(pan_file.filename)}'

        supabase.storage.from_('documents').upload(aadhar_path, aadhar_file.read(), file_options={"content-type": "application/pdf"})
        supabase.storage.from_('documents').upload(pan_path, pan_file.read(), file_options={"content-type": "application/pdf"})

        # Prepare loan data
        loan_data = {
            'id': str(uuid.uuid4()),
            'user_id': user_id,
            'first_name': first_name,
            'last_name': last_name,
            'dob': dob,
            'age': age,
            'phone': phone,
            'address': address,
            'occupation': occupation,
            'monthly_income': float(monthly_income),
            'loan_amount': float(loan_amount),
            'loan_purpose': loan_purpose,
            'aadhaar_number': aadhar_number,
            'pan_number': pan_number,
            'aadhaar_url': aadhar_path,
            'pan_url': pan_path,
            'status': 'pending',
            'review_status': 'awaiting',
            'created_at': datetime.utcnow().isoformat()
        }

        # Insert into loans table
        response = supabase.table('loans').insert(loan_data).execute()
        if response.data:
            logger.info(f"Loan submitted successfully for user_id: {user_id}")
            return jsonify({'message': 'Loan submitted successfully', 'loan': response.data[0]}), 200
        else:
            logger.error("Failed to insert loan into database")
            return jsonify({'error': 'Failed to insert loan'}), 500

    except Exception as e:
        logger.error(f"Error submitting loan: {str(e)}")
        if 'infinite recursion detected' in str(e).lower():
            return jsonify({'error': 'Database configuration error. Please contact support.'}), 500
        return jsonify({'error': str(e)}), 500

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
    try:
        user_data = supabase.table('user_profiles').select('*').eq('id', session['user_id']).execute().data[0]
        merchant_id = user_data.get('merchant_id', f"MERCH{user_data['id'][:8]}")
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
                          email=user_data.get('email', 'N/A'), 
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
    try:
        user_data = supabase.table('user_profiles').select('*').eq('id', session['user_id']).execute().data[0]
        full_name = user_data.get('full_name', username)
        loan_browser_id = user_data.get('loan_browser_id', f"LB{session['user_id'][:8]}")
        mobile_number = user_data.get('mobile_number', 'N/A')
        date_of_birth = user_data.get('date_of_birth', '1990-01-01')
        gender = user_data.get('gender', 'male')
        address = user_data.get('address', 'N/A, N/A, 123456')
        date_of_joining = user_data.get('created_at', '2023-01-01')
    except Exception as e:
        flash(f"Error fetching profile data: {str(e)}", "error")
        return redirect(url_for('dashboard'))

    return render_template('loan_profiles.html', 
                          username=username, 
                          email=user_data.get('email', 'N/A'),
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
        users = supabase.table('user_profiles').select('*').execute()
        return render_template('debug.html', users=users.data)
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)