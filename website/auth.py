from flask import Blueprint, render_template, request, redirect, url_for,flash,session
from db_manager import Database
from functools import wraps  # Added for login_required decorator
import sqlite3

auth = Blueprint('auth', __name__)


def login_required(f):
    """Ensures user is logged in before accessing protected routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_email' not in session:
            flash('Please log in first.', 'error')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

#Login Page
@auth.route('/login', methods=['GET','POST'])
def login():
    """
    SECURITY IMPROVEMENTS:
    1. Checks for existing session to prevent duplicate logins
    2. Validates required fields
    3. Uses secure database methods
    4. Proper session management
    5. User-friendly error messages
    """
    if 'user_email' in session:
        return redirect(url_for('views.home'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # SECURITY: Validate required fields
        if not email or not password:
            flash('Please fill in all fields.', 'error')
            return redirect(url_for('auth.login'))

        db = Database()
        try:
            if db.validate_user_login(email, password):
                session['user_email'] = email  # SECURITY: Set session after successful login
                flash('Logged in successfully!', 'success')
                return redirect(url_for('views.home'))
            else:
                flash('Invalid email or password.', 'error')
        finally:
            db.close()
            
    return render_template("login.html")

#Logout Page
@auth.route('/logout')
@login_required  # SECURITY: Protect logout route
def logout():
    """
    SECURITY IMPROVEMENTS:
    1. Protected with login_required
    2. Properly clears session
    3. Redirects to login page
    """
    session.pop('user_email', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('auth.login'))


#Register Page
@auth.route('/register', methods=['GET','POST'])
def register():
    """
    SECURITY IMPROVEMENTS:
    1. Proper error handling
    2. Input validation
    3. Secure database operations
    4. User feedback through flash messages
    """
    if request.method == 'POST':
        db = Database()
        try:
            data = db.fetch_data_from_a_page(page="register")
            if not data:
                flash('Please fill in all fields correctly.', 'error')
                return redirect(url_for('auth.register'))

            db.create_table('employees')
            db.insert_user_to_table('employees', data)
            flash('Registration successful!', 'success')
            return redirect(url_for('auth.login'))
        except sqlite3.IntegrityError:
            flash('Email already exists.', 'error')
        finally:
            db.close()
            
    return render_template("register.html")
#change password Page
@auth.route('/changepass', methods=['GET','POST'])
def changepass():

    if request.method == 'POST':
        email = request.form.get('email')
        old_password = request.form.get('oldPassword')
        new_password = request.form.get('newPassword')

        db = Database()
        db.change_password(email,old_password,new_password)
        db.close()
        return redirect(url_for('auth.login'))

    return render_template("changepass.html")

#change password Page
@auth.route('/randval')
def randval():
    return render_template("randval.html")

#add clients Page
@auth.route('/addclients', methods=['GET','POST'])
def addclient():
    db = Database()
    try:
        if request.method == 'POST':
            data = db.fetch_data_from_a_page(page= "addClients")
            if data:
                db.create_table('clients')
                db.insert_user_to_table('clients', data)
                return redirect(url_for('auth.addclient'))
    finally:
        db.close()
    return render_template("addClients.html")

@auth.route('/forgotpass', methods=['GET', 'POST'])
def forgotpass():
    return render_template("forgotpass.html")