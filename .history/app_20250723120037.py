from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify
from supabase import create_client, Client
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
from werkzeug.utils import secure_filename
import re
import logging
import uuid
from datetime import datetime

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
            if supabase.table('users').select('username').eq('username', username).execute().data:
                flash("Username already taken.", "error")
                return render_template('sign-up.html')

            if supabase.table('users').select('email').eq('email', email).execute().data:
                flash("Email already registered.", "error")
                return render_template('sign-up.html')

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
                session.permanent = True
                session['user_id'] = user_data['id']
                session['username'] = username
                session['sign_in_as'] = sign_up_as
                logger.info(f"User signed up: {username}, role: {sign_up_as}")
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

@app.route("/add-loan", methods=["POST"])
def add_loan():
    if 'user_id' not in session:
        logger.error("Unauthorized access: No user_id in session")
        return jsonify({'error': 'Please sign in to continue.'}), 401

    try:
        # Get form data matching HTML field names
        full_name = request.form.get("fullName")
        age = request.form.get("age")
        monthly_income = request.form.get("monthlyIncome")
        occupation = request.form.get("occupation")
        loan_amount = request.form.get("loanAmount")
        loan_purpose = request.form.get("loanPurpose")
        aadhar_number = request.form.get("aadharNumber")
        pan_number = request.form.get("panNumber")
        user_id = session.get("user_id")

        # Validate required fields
        if not all([full_name, age, monthly_income, occupation, loan_amount, loan_purpose, aadhar_number, pan_number]):
            logger.error("Missing required fields in loan application")
            return jsonify({'error': 'All fields are required.'}), 400

        # Validate numeric fields
        try:
            age = int(age)
            monthly_income = float(monthly_income)
            loan_amount = float(loan_amount)
        except ValueError:
            logger.error("Invalid numeric field values")
            return jsonify({'error': 'Age, monthly income, and loan amount must be valid numbers.'}), 400

        # Validate schema constraints
        if age < 18:
            logger.error("Age must be at least 18")
            return jsonify({'error': 'Age must be at least 18.'}), 400
        if monthly_income < 0:
            logger.error("Monthly income must be non-negative")
            return jsonify({'error': 'Monthly income must be non-negative.'}), 400
        if loan_amount <= 0:
            logger.error("Loan amount must be greater than 0")
            return jsonify({'error': 'Loan amount must be greater than 0.'}), 400

        # Validate Aadhar and PAN numbers
        if not is_valid_aadhar_number(aadhar_number):
            logger.error("Invalid Aadhar number format")
            return jsonify({'error': 'Aadhar number must be a 12-digit number.'}), 400

        if not is_valid_pan_number(pan_number):
            logger.error("Invalid PAN number format")
            return jsonify({'error': 'PAN number must be in the format ABCDE1234F.'}), 400

        # Check for existing Aadhar number (UNIQUE constraint) with explicit cast
        query = f"SELECT aadhar_number FROM loans WHERE aadhar_number = '{aadhar_number}'::text"
        logger.debug(f"Executing query: {query}")  # Log query for debugging
        existing_aadhar = supabase.rpc('custom_query', {'sql': query}).execute()
        if existing_aadhar.data and len(existing_aadhar.data) > 0:
            logger.error(f"Aadhar number {aadhar_number} already exists")
            return jsonify({'error': 'Aadhar number already exists.'}), 400

        # Handle file uploads
        aadhar_file = request.files.get("aadharFile")
        pan_file = request.files.get("panFile")

        if not aadhar_file or not pan_file:
            logger.error("Missing Aadhar or PAN file")
            return jsonify({'error': 'Both Aadhar and PAN files are required.'}), 400

        # Validate file types (PDF only)
        if not (aadhar_file.filename.endswith('.pdf') and pan_file.filename.endswith('.pdf')):
            logger.error("Invalid file type: Only PDF files are allowed")
            return jsonify({'error': 'Only PDF files are allowed.'}), 400

        # Validate file sizes (max 5MB)
        max_size = 5 * 1024 * 1024  # 5MB in bytes
        aadhar_file.seek(0, os.SEEK_END)
        aadhar_size = aadhar_file.tell()
        pan_file.seek(0, os.SEEK_END)
        pan_size = pan_file.tell()
        if aadhar_size > max_size or pan_size > max_size:
            logger.error("File size exceeds 5MB")
            return jsonify({'error': 'Files must be less than 5MB.'}), 400

        # Reset file pointers to the beginning
        aadhar_file.seek(0)
        pan_file.seek(0)

        # Read file content as bytes
        aadhar_file_content = aadhar_file.read()
        pan_file_content = pan_file.read()

        # Generate unique filenames
        aadhar_filename = f"{uuid.uuid4()}_{secure_filename(aadhar_file.filename)}"
        pan_filename = f"{uuid.uuid4()}_{secure_filename(pan_file.filename)}"

        # Upload files to Supabase bucket "loan-files"
        try:
            supabase.storage.from_("loan-files").upload(
                aadhar_filename, aadhar_file_content, {"content-type": "application/pdf"}
            )
            supabase.storage.from_("loan-files").upload(
                pan_filename, pan_file_content, {"content-type": "application/pdf"}
            )
        except Exception as e:
            logger.error(f"Error uploading files to Supabase storage: {str(e)}")
            return jsonify({'error': f"Failed to upload files: {str(e)}"}), 500

        # Get public URLs for uploaded files
        aadhar_file_url = supabase.storage.from_("loan-files").get_public_url(aadhar_filename)
        pan_file_url = supabase.storage.from_("loan-files").get_public_url(pan_filename)

        # Prepare loan data for database
        loan_data = {
            "user_id": user_id,
            "full_name": full_name,
            "age": age,
            "monthly_income": monthly_income,
            "occupation": occupation,
            "loan_amount": loan_amount,
            "loan_purpose": loan_purpose,
            "aadhar_number": aadhar_number,
            "pan_number": pan_number,
            "aadhar_file_url": aadhar_file_url,
            "pan_file_url": pan_file_url,
            "status": "Pending",
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }

        # Insert loan data into Supabase "loans" table
        try:
            response = supabase.table("loans").insert(loan_data).execute()
            if response.data:
                logger.info(f"Loan application submitted successfully for user {user_id}")
                return jsonify({'message': 'Loan application submitted successfully.'}), 200
            else:
                logger.error("Failed to insert loan data into database")
                # Clean up uploaded files on failure
                supabase.storage.from_("loan-files").remove([aadhar_filename, pan_filename])
                return jsonify({'error': 'Failed to save loan data.'}), 500
        except Exception as e:
            logger.error(f"Error inserting loan data: {str(e)}")
            # Clean up uploaded files on failure
            supabase.storage.from_("loan-files").remove([aadhar_filename, pan_filename])
            return jsonify({'error': f"Failed to save loan data: {str(e)}"}), 500

    except Exception as e:
        logger.error(f"Error in add_loan: {str(e)}")
        # Attempt to clean up any uploaded files if an error occurs
        try:
            supabase.storage.from_("loan-files").remove([aadhar_filename, pan_filename])
        except:
            pass  # Ignore cleanup errors
        return jsonify({'error': f'Internal Server Error: {str(e)}'}), 500
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
        user_data = supabase.table('users').select('*').eq('id', session['user_id']).execute().data[0]
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
        user_data = supabase.table('users').select('*').eq('id', session['user_id']).execute().data[0]
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
        users = supabase.table('users').select('*').execute()
        return render_template('debug.html', users=users.data)
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)