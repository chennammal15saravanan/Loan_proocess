from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify
from supabase import create_client, Client
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
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
    return sign_up_as in ['merchant', 'loan_borrower', 'nbfc_admin']

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

        if not all([username, email, password, sign_up_as]):
            flash("Username, email, password, and role are required.", "error")
            logger.error("Missing required fields: username, email, password, or sign_up_as")
            return render_template('sign-up.html')

        if not is_valid_email(email):
            flash("Invalid email format.", "error")
            logger.error(f"Invalid email format: {email}")
            return render_template('sign-up.html')

        if not is_valid_username(username):
            flash("Username must be at least 3 characters and alphanumeric.", "error")
            logger.error(f"Invalid username: {username}")
            return render_template('sign-up.html')

        if not is_valid_password(password):
            flash("Password must be at least 8 characters.", "error")
            logger.error("Invalid password: too short")
            return render_template('sign-up.html')

        if sign_up_as not in ['merchant', 'loan_borrower', 'nbfc_admin']:
            flash("Invalid role selected.", "error")
            logger.error(f"Invalid role: {sign_up_as}")
            return render_template('sign-up.html')

        if phone and not re.match(r'^\+?\d{10,15}$', phone):
            flash("Invalid phone number format.", "error")
            logger.error(f"Invalid phone number: {phone}")
            return render_template('sign-up.html')

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
            username_check = supabase.table('user_profiles').select('username').eq('username', username).execute()
            if username_check.data:
                flash("Username already taken.", "error")
                logger.error(f"Username already taken: {username}")
                return render_template('sign-up.html')

            email_check = supabase.table('user_profiles').select('email').eq('email', email).execute()
            if email_check.data:
                flash("Email already registered.", "error")
                logger.error(f"Email already registered: {email}")
                return render_template('sign-up.html')

            user_id = str(uuid.uuid4())
            hashed_password = generate_password_hash(password)

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

        if sign_in_as not in ['merchant', 'loan_borrower', 'nbfc_admin']:
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
        return render_template('loan-browser..html', username=username, role=role)
    elif role == 'nbfc_admin':
        return render_template('nbfc_admin.html', username=username, role=role)
    else:
        flash("Invalid role. Please sign in again.", "error")
        return redirect(url_for('signin'))

@app.route('/update-loan-status', methods=['POST'])
def update_loan_status():
    if 'user_id' not in session or session.get('sign_in_as') != 'nbfc_admin':
        logger.error("Unauthorized access to update-loan-status")
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        loan_id = request.form.get('loan_id')
        status = request.form.get('status')
        manager_name = request.form.get('manager_name')
        if not loan_id or not status:
            logger.error("Missing loan_id or status")
            return jsonify({'error': 'Loan ID and status are required'}), 400
        if status.lower() not in ['accepted', 'rejected', 'pending']:
            logger.error(f"Invalid status: {status}")
            return jsonify({'error': 'Invalid status'}), 400
        loan = supabase.table('loans').select('*').eq('id', loan_id).execute()
        if not loan.data:
            logger.error(f"Loan not found: {loan_id}")
            return jsonify({'error': 'Loan not found'}), 404
        update_data = {
            'status': status.lower(),
            'review_status': 'confirmed' if status.lower() == 'accepted' else 'rejected' if status.lower() == 'rejected' else 'awaiting',
            'manager_name': manager_name or session.get('username', 'Unknown'),
            'confirmed_at': datetime.utcnow().isoformat() if status.lower() == 'accepted' else None
        }
        response = supabase.table('loans').update(update_data).eq('id', loan_id).execute()
        if response.data:
            logger.info(f"Loan {loan_id} status updated to {status} by {manager_name or 'Unknown'}")
            return jsonify({'message': f'Loan {status.capitalize()} successfully'}), 200
        else:
            logger.error(f"Failed to update loan status for {loan_id}")
            return jsonify({'error': 'Failed to update loan status'}), 500
    except Exception as e:
        logger.error(f"Error updating loan status: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/add-referral-loan', methods=['POST'])
def add_referral_loan():
    if 'user_id' not in session or session.get('sign_in_as') != 'merchant':
        logger.error("Unauthorized access: No user_id or not a merchant")
        return jsonify({'error': 'Please sign in as a merchant to continue.'}), 401

    try:
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")
        dob = request.form.get("dob")
        age = request.form.get("age")
        phone = request.form.get("phone")
        address = request.form.get("address")
        occupation = request.form.get("occupation")
        monthly_income = request.form.get("monthlyIncome")
        loan_amount = request.form.get("loanAmount")
        loan_purpose = request.form.get("loanPurpose")
        aadhaar_number = request.form.get("aadharNumber")
        pan_number = request.form.get("panNumber")
        user_id = session.get("user_id")

        aadhaar_file = request.files.get("aadharFile")
        pan_file = request.files.get("panFile")

        required_fields = [first_name, last_name, dob, age, phone, address, occupation, 
                         monthly_income, loan_amount, loan_purpose, aadhaar_number, pan_number]
        if not all(required_fields) or not aadhaar_file or not pan_file:
            logger.error(f"Missing required fields: {request.form}, files: {aadhaar_file is None}, {pan_file is None}")
            return jsonify({'error': 'All fields are required.'}), 400

        try:
            age = int(age)
            monthly_income = float(monthly_income)
            loan_amount = float(loan_amount)
        except ValueError:
            logger.error("Invalid numeric field values")
            return jsonify({'error': 'Age, monthly income, and loan amount must be valid numbers.'}), 400

        if age < 18:
            logger.error("Age must be at least 18")
            return jsonify({'error': 'Age must be at least 18.'}), 400
        if monthly_income < 0:
            logger.error("Monthly income must be non-negative")
            return jsonify({'error': 'Monthly income must be non-negative.'}), 400
        if loan_amount <= 0:
            logger.error("Loan amount must be greater than 0")
            return jsonify({'error': 'Loan amount must be greater than 0.'}), 400

        try:
            dob_date = datetime.strptime(dob, "%Y-%m-%d").date()
            if dob_date > datetime.now().date():
                logger.error("Date of birth cannot be in the future")
                return jsonify({'error': 'Date of birth cannot be in the future.'}), 400
        except ValueError:
            logger.error("Invalid date of birth format")
            return jsonify({'error': 'Date of birth must be in YYYY-MM-DD format.'}), 400

        if not is_valid_aadhar_number(aadhaar_number):
            logger.error("Invalid Aadhar number format")
            return jsonify({'error': 'Aadhar number must be a 12-digit number.'}), 400
        if not is_valid_pan_number(pan_number):
            logger.error("Invalid PAN number format")
            return jsonify({'error': 'PAN number must be in the format ABCDE1234F.'}), 400

        existing_aadhaar = supabase.table('loans').select('aadhaar_number').eq('aadhaar_number', aadhaar_number).execute()
        if existing_aadhaar.data:
            logger.error(f"Aadhaar number {aadhaar_number} already exists")
            return jsonify({'error': 'Aadhaar number already exists.'}), 400

        existing_pan = supabase.table('loans').select('pan_number').eq('pan_number', pan_number).execute()
        if existing_pan.data:
            logger.error(f"PAN number {pan_number} already exists")
            return jsonify({'error': 'PAN number already exists.'}), 400

        if not (aadhaar_file.filename.endswith('.pdf') and pan_file.filename.endswith('.pdf')):
            logger.error("Invalid file type: Only PDF files are allowed")
            return jsonify({'error': 'Only PDF files are allowed.'}), 400
        max_size = 5 * 1024 * 1024
        if aadhaar_file.content_length > max_size or pan_file.content_length > max_size:
            logger.error("File size exceeds 5MB")
            return jsonify({'error': 'Files must be less than 5MB.'}), 400

        aadhaar_file_content = aadhaar_file.read()
        pan_file_content = pan_file.read()

        aadhaar_filename = f"aadhar/{uuid.uuid4()}_{secure_filename(aadhaar_file.filename)}"
        pan_filename = f"pan/{uuid.uuid4()}_{secure_filename(pan_file.filename)}"

        try:
            supabase.storage.from_("documents").upload(
                aadhaar_filename, aadhaar_file_content, {"content-type": "application/pdf"}
            )
            supabase.storage.from_("documents").upload(
                pan_filename, pan_file_content, {"content-type": "application/pdf"}
            )
        except Exception as e:
            logger.error(f"Error uploading files to Supabase storage: {str(e)}")
            return jsonify({'error': f"Failed to upload files: {str(e)}"}), 500

        aadhaar_file_url = supabase.storage.from_("documents").get_public_url(aadhaar_filename)
        pan_file_url = supabase.storage.from_("documents").get_public_url(pan_filename)

        loan_data = {
            "user_id": user_id,
            "first_name": first_name,
            "last_name": last_name,
            "dob": dob_date.isoformat(),
            "phone": phone,
            "address": address,
            "occupation": occupation,
            "age": age,
            "monthly_income": monthly_income,
            "loan_amount": loan_amount,
            "loan_purpose": loan_purpose,
            "aadhaar_number": aadhaar_number,
            "pan_number": pan_number,
            "aadhaar_url": aadhaar_file_url,
            "pan_url": pan_file_url,
            "status": "pending",
            "created_at": datetime.utcnow().isoformat(),
            "review_status": "awaiting",
            "referred_by": user_id
        }

        try:
            response = supabase.table("loans").insert(loan_data).execute()
            if response.data:
                logger.info(f"Referral loan application submitted successfully for merchant {user_id}")
                return jsonify({'message': 'Referral loan application submitted successfully.'}), 200
            else:
                logger.error("Failed to insert referral loan data into database")
                supabase.storage.from_("documents").remove([aadhaar_filename, pan_filename])
                return jsonify({'error': 'Failed to save loan data.'}), 500
        except Exception as e:
            logger.error(f"Error inserting referral loan data: {str(e)}")
            supabase.storage.from_("documents").remove([aadhaar_filename, pan_filename])
            return jsonify({'error': f"Failed to save loan data: {str(e)}"}), 500

    except Exception as e:
        logger.error(f"Error in add_referral_loan: {str(e)}")
        try:
            supabase.storage.from_("documents").remove([aadhaar_filename, pan_filename])
        except:
            pass
        return jsonify({'error': f'Internal Server Error: {str(e)}'}), 500

@app.route('/get-referral-loans', methods=['GET'])
def get_referral_loans():
    if 'user_id' not in session or session.get('sign_in_as') != 'merchant':
        logger.error("Unauthorized access to get-referral-loans")
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        loans = supabase.table('loans').select('id, first_name, last_name, loan_amount, status').eq('referred_by', session['user_id']).execute().data
        loan_data = []
        for loan in loans:
            loan_data.append({
                'id': loan['id'],
                'customer_name': f"{loan['first_name']} {loan['last_name']}",
                'amount': loan['loan_amount'],
                'status': loan['status'].capitalize()
            })
        logger.info(f"Fetched {len(loan_data)} referral loans for merchant {session['user_id']}")
        return jsonify({'loans': loan_data}), 200
    except Exception as e:
        logger.error(f"Error fetching referral loans: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/get-user-loans', methods=['GET'])
def get_user_loans():
    if 'user_id' not in session or session.get('sign_in_as') != 'loan_borrower':
        logger.error("Unauthorized access to get-user-loans")
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        user_id = session['user_id']
        logger.info(f"Fetching loans for user ID: {user_id}")

        response = supabase.table('loans').select('id, loan_amount, loan_purpose, status').eq('user_id', user_id).execute()
        logger.info(f"Supabase response: {response}")

        loans = response.data
        loan_data = []
        for loan in loans:
            loan_data.append({
                'loan_id': loan['id'],
                'amount': loan['loan_amount'],
                'purpose': loan['loan_purpose'],
                'status': loan['status'].capitalize()
            })

        logger.info(f"Fetched {len(loan_data)} loans for user {user_id}")
        return jsonify({'loans': loan_data}), 200

    except Exception as e:
        logger.error(f"Error fetching user loans: {str(e)}")
        return jsonify({'error': str(e)}), 500

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
        product = supabase.table('products').select('*').eq('id', product_id).eq('user_id', user_id).execute()
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

        response = supabase.table('products').update(product_data).eq('id', product_id).execute()
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

@app.route('/get-all-products', methods=['GET'])
def get_all_products():
    try:
        products = supabase.table('products').select('name, description, price, user_id').execute().data
        enriched_products = []
        for p in products:
            merchant = supabase.table('user_profiles').select('username').eq('id', p['user_id']).execute()
            merchant_name = merchant.data[0]['username'] if merchant.data else 'Unknown'
            enriched_products.append({
                'name': p['name'],
                'description': p.get('description', ''),
                'price': p['price'],
                'merchant_name': merchant_name
            })
        return jsonify({'products': enriched_products}), 200
    except Exception as e:
        logger.error(f"Error fetching all products: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/add-loan', methods=['POST'])
def add_loan():
    if 'user_id' not in session:
        logger.error("Unauthorized access: No user_id in session")
        return jsonify({'error': 'Please sign in to continue.'}), 401

    try:
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")
        dob = request.form.get("dob")
        age = request.form.get("age")
        phone = request.form.get("phone")
        address = request.form.get("address")
        occupation = request.form.get("occupation")
        monthly_income = request.form.get("monthlyIncome")
        loan_amount = request.form.get("loanAmount")
        loan_purpose = request.form.get("loanPurpose")
        aadhaar_number = request.form.get("aadharNumber")
        pan_number = request.form.get("panNumber")
        user_id = session.get("user_id")

        aadhaar_file = request.files.get("aadharFile")
        pan_file = request.files.get("panFile")

        required_fields = [first_name, last_name, dob, age, phone, address, occupation, 
                         monthly_income, loan_amount, loan_purpose, aadhaar_number, pan_number]
        if not all(required_fields) or not aadhaar_file or not pan_file:
            logger.error(f"Missing required fields: {request.form}, files: {aadhaar_file is None}, {pan_file is None}")
            return jsonify({'error': 'All fields are required.'}), 400

        try:
            age = int(age)
            monthly_income = float(monthly_income)
            loan_amount = float(loan_amount)
        except ValueError:
            logger.error("Invalid numeric field values")
            return jsonify({'error': 'Age, monthly income, and loan amount must be valid numbers.'}), 400

        if age < 18:
            logger.error("Age must be at least 18")
            return jsonify({'error': 'Age must be at least 18.'}), 400
        if monthly_income < 0:
            logger.error("Monthly income must be non-negative")
            return jsonify({'error': 'Monthly income must be non-negative.'}), 400
        if loan_amount <= 0:
            logger.error("Loan amount must be greater than 0")
            return jsonify({'error': 'Loan amount must be greater than 0.'}), 400

        try:
            dob_date = datetime.strptime(dob, "%Y-%m-%d").date()
            if dob_date > datetime.now().date():
                logger.error("Date of birth cannot be in the future")
                return jsonify({'error': 'Date of birth cannot be in the future.'}), 400
        except ValueError:
            logger.error("Invalid date of birth format")
            return jsonify({'error': 'Date of birth must be in YYYY-MM-DD format.'}), 400

        if not is_valid_aadhar_number(aadhaar_number):
            logger.error("Invalid Aadhar number format")
            return jsonify({'error': 'Aadhar number must be a 12-digit number.'}), 400
        if not is_valid_pan_number(pan_number):
            logger.error("Invalid PAN number format")
            return jsonify({'error': 'PAN number must be in the format ABCDE1234F.'}), 400

        existing_aadhaar = supabase.table('loans').select('aadhaar_number').eq('aadhaar_number', aadhaar_number).execute()
        if existing_aadhaar.data:
            logger.error(f"Aadhaar number {aadhaar_number} already exists")
            return jsonify({'error': 'Aadhaar number already exists.'}), 400

        existing_pan = supabase.table('loans').select('pan_number').eq('pan_number', pan_number).execute()
        if existing_pan.data:
            logger.error(f"PAN number {pan_number} already exists")
            return jsonify({'error': 'PAN number already exists.'}), 400

        if not (aadhaar_file.filename.endswith('.pdf') and pan_file.filename.endswith('.pdf')):
            logger.error("Invalid file type: Only PDF files are allowed")
            return jsonify({'error': 'Only PDF files are allowed.'}), 400
        max_size = 5 * 1024 * 1024
        if aadhaar_file.content_length > max_size or pan_file.content_length > max_size:
            logger.error("File size exceeds 5MB")
            return jsonify({'error': 'Files must be less than 5MB.'}), 400

        aadhaar_file_content = aadhaar_file.read()
        pan_file_content = pan_file.read()

        aadhaar_filename = f"aadhar/{uuid.uuid4()}_{secure_filename(aadhaar_file.filename)}"
        pan_filename = f"pan/{uuid.uuid4()}_{secure_filename(pan_file.filename)}"

        try:
            supabase.storage.from_("documents").upload(
                aadhaar_filename, aadhaar_file_content, {"content-type": "application/pdf"}
            )
            supabase.storage.from_("documents").upload(
                pan_filename, pan_file_content, {"content-type": "application/pdf"}
            )
        except Exception as e:
            logger.error(f"Error uploading files to Supabase storage: {str(e)}")
            return jsonify({'error': f"Failed to upload files: {str(e)}"}), 500

        aadhaar_file_url = supabase.storage.from_("documents").get_public_url(aadhaar_filename)
        pan_file_url = supabase.storage.from_("documents").get_public_url(pan_filename)

        loan_data = {
            "user_id": user_id,
            "first_name": first_name,
            "last_name": last_name,
            "dob": dob_date.isoformat(),
            "phone": phone,
            "address": address,
            "occupation": occupation,
            "age": age,
            "monthly_income": monthly_income,
            "loan_amount": loan_amount,
            "loan_purpose": loan_purpose,
            "aadhaar_number": aadhaar_number,
            "pan_number": pan_number,
            "aadhaar_url": aadhaar_file_url,
            "pan_url": pan_file_url,
            "status": "pending",
            "created_at": datetime.utcnow().isoformat(),
            "review_status": "awaiting"
        }

        try:
            response = supabase.table("loans").insert(loan_data).execute()
            if response.data:
                logger.info(f"Loan application submitted successfully for user {user_id}")
                return jsonify({'message': 'Loan application submitted successfully.'}), 200
            else:
                logger.error("Failed to insert loan data into database")
                supabase.storage.from_("documents").remove([aadhaar_filename, pan_filename])
                return jsonify({'error': 'Failed to save loan data.'}), 500
        except Exception as e:
            logger.error(f"Error inserting loan data: {str(e)}")
            supabase.storage.from_("documents").remove([aadhaar_filename, pan_filename])
            return jsonify({'error': f"Failed to save loan data: {str(e)}"}), 500

    except Exception as e:
        logger.error(f"Error in add_loan: {str(e)}")
        try:
            supabase.storage.from_("documents").remove([aadhaar_filename, pan_filename])
        except:
            pass
        return jsonify({'error': f'Internal Server Error: {str(e)}'}), 500

@app.route('/get-loan-details/<id>', methods=['GET'])
def get_loan_details(id):
    if 'user_id' not in session or session.get('sign_in_as') != 'nbfc_admin':
        logger.error("Unauthorized access to get-loan-details")
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        loan = supabase.table('loans').select('*').eq('id', id).execute()
        if not loan.data:
            logger.error(f"Loan not found: {id}")
            return jsonify({'error': 'Loan not found'}), 404

        loan_data = loan.data[0]
        merchant_name = 'N/A'
        if loan_data.get('referred_by'):
            merchant = supabase.table('user_profiles').select('username').eq('id', loan_data['referred_by']).execute()
            merchant_name = merchant.data[0]['username'] if merchant.data else 'Unknown'

        response_data = {
            'first_name': loan_data['first_name'],
            'last_name': loan_data.get('last_name', 'N/A'),
            'dob': loan_data.get('dob', 'N/A'),
            'age': loan_data.get('age', 'N/A'),
            'phone': loan_data.get('phone', 'N/A'),
            'address': loan_data.get('address', 'N/A'),
            'occupation': loan_data.get('occupation', 'N/A'),
            'monthly_income': float(loan_data['monthly_income']) if loan_data['monthly_income'] else 0.0,
            'loan_amount': float(loan_data['loan_amount']) if loan_data['loan_amount'] else 0.0,
            'loan_purpose': loan_data.get('loan_purpose', 'N/A'),
            'aadhaar_number': loan_data.get('aadhaar_number', 'N/A'),
            'pan_number': loan_data.get('pan_number', 'N/A'),
            'aadhaar_url': loan_data.get('aadhaar_url', 'N/A'),
            'pan_url': loan_data.get('pan_url', 'N/A'),
            'status': loan_data['status'].capitalize() if loan_data['status'] else 'N/A',
            'created_at': loan_data.get('created_at', 'N/A'),
            'review_status': loan_data.get('review_status', 'N/A'),
            'referred_by': merchant_name
        }

        logger.info(f"Fetched loan details for ID: {id}")
        return jsonify({'loan': response_data}), 200
    except Exception as e:
        logger.error(f"Error fetching loan details for ID {id}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/admin-profile')
def admin_profile():
    if 'user_id' not in session:
        flash("Please sign in to continue.", "error")
        return redirect(url_for('signin'))

    role = session.get('sign_in_as')
    if role != 'nbfc_admin':
        flash("Access denied. This page is for NBFC Admins only.", "error")
        return redirect(url_for('dashboard'))

    username = session.get('username')
    try:
        user_data = supabase.table('user_profiles').select('*').eq('id', session['user_id']).execute().data[0]
        admin_id = user_data.get('admin_id', f"ADMIN{user_data['id'][:8]}")
        email = user_data.get('email')
        phone = user_data.get('phone')
        age = user_data.get('age')
        created_at = user_data.get('created_at')
    except Exception as e:
        logger.error(f"Error fetching admin profile data: {str(e)}")
        flash(f"Error fetching profile data: {str(e)}", "error")
        return redirect(url_for('dashboard'))

    return render_template('admin_profile.html', 
                          username=username, 
                          email=email,
                          admin_id=admin_id,
                          phone=phone,
                          age=age,
                          created_at=created_at,
                          role=role)

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

@app.route('/get-loan-applications', methods=['GET'])
def get_loan_applications():
    if 'user_id' not in session or session.get('sign_in_as') != 'nbfc_admin':
        logger.error("Unauthorized access to get-loan-applications")
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        status = request.args.get('status')
        query = supabase.table('loans').select('id, first_name, address, loan_amount, status')
        if status:
            query = query.eq('status', status.lower())
        loans = query.execute().data
        loan_data = []
        for loan in loans:
            loan_data.append({
                'request_id': loan['id'],
                'first_name': loan['first_name'],
                'address': loan['address'] or 'N/A',
                'amount': loan['loan_amount'],
                'status': loan['status'].capitalize()
            })
        logger.info(f"Fetched {len(loan_data)} loan applications")
        return jsonify({'loans': loan_data}), 200
    except Exception as e:
        logger.error(f"Error fetching loan applications: {str(e)}")
        return jsonify({'error': str(e)}), 500

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
    app.run(host="0.0.0.0", port=5000)