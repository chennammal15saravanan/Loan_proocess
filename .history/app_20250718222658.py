from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Database Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    sign_up_as = db.Column(db.String(50), nullable=False)

# Create database
with app.app_context():
    db.create_all()

@app.route('/')
def index():
    return redirect(url_for('signin'))

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        sign_in_as = request.form['signin_as']
        
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password) and user.sign_up_as == sign_in_as:
            session['user_id'] = user.id
            session['username'] = user.username
            session['sign_in_as'] = user.sign_up_as
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email, password, or role. Please try again.', 'error')
    
    return render_template('signin.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        sign_up_as = request.form['signup_as']
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists.', 'error')
        elif User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
        else:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(username=username, email=email, password=hashed_password, sign_up_as=sign_up_as)
            db.session.add(new_user)
            db.session.commit()
            session['user_id'] = new_user.id
            session['username'] = new_user.username
            session['sign_in_as'] = new_user.sign_up_as
            return redirect(url_for('dashboard'))
    
    return render_template('signup.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('signin'))
    return render_template('dashboard.html', username=session['username'], role=session['sign_in_as'])

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('sign_in_as', None)
    return redirect(url_for('signin'))

if __name__ == '__main__':
    app.run(debug=True)