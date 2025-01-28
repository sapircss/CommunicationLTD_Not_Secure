import sqlite3
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from db_manager import Database
from functools import wraps
import hashlib
import random

auth = Blueprint('auth', __name__)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_email' not in session:
            flash('Please log in first.', 'error')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        db = Database()
        try:
            user_data = {
                'id': request.form.get('id', '').strip(),
                'first_name': request.form.get('firstName', '').strip(),
                'last_name': request.form.get('lastName', '').strip(),
                'password': request.form.get('password1', '').strip(),
                'email': request.form.get('email', '').strip()
            }

            # Detect SQL Injection in the email field
            if "' OR" in user_data['email'] or "--" in user_data['email']:
                flash('SQL Injection detected in email field! Hacked SQL Injection.', 'error')
                print("Hacked SQL Injection detected in email.")

            # Detect XSS in the last name field
            if "<script>" in user_data['last_name'] or "<h1>" in user_data['last_name']:
                flash('XSS detected in last name field! Hacked XSS.', 'error')
                print("Hacked XSS detected in last name.")

            db.create_table('employees')
            db.insert_user_to_table('employees', user_data)

            flash('Registration successful!', 'success')
            return redirect(url_for('auth.login'))

        except sqlite3.OperationalError as e:
            flash(f"Database error: {e}", 'error')
        finally:
            db.close()

    return render_template("register.html")

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        db = Database()
        try:
            # Detect SQL Injection in email
            if "' OR" in email or "--" in email:
                flash('SQL Injection detected in email field! Hacked SQL Injection.', 'error')
                print("Hacked SQL Injection detected in email.")

            if db.validate_user_login(email, password):
                session['user_email'] = email
                flash('Login successful!', 'success')
                return redirect(url_for('views.system'))
            else:
                flash('Invalid email or password.', 'error')
        finally:
            db.close()
    return render_template("login.html")

@auth.route('/logout', methods=['POST'])
@login_required
def logout():
    session.pop('user_email', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('auth.login'))

@auth.route('/changepass', methods=['GET', 'POST'])
@login_required
def changepass():
    if request.method == 'POST':
        current_password = request.form.get('oldPassword')
        new_password = request.form.get('newPassword')
        confirm_password = request.form.get('confirmPassword')

        if not current_password or not new_password or not confirm_password:
            flash('All fields are required.', 'error')
            return redirect(url_for('auth.changepass'))

        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('auth.changepass'))

        db = Database()
        try:
            email = session.get('user_email')
            query = f"SELECT password FROM employees WHERE email = '{email}'"
            db.cursor.execute(query)
            result = db.cursor.fetchone()

            if result and hashlib.sha256(current_password.encode()).hexdigest() == result[0]:
                new_hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
                update_query = f"UPDATE employees SET password = '{new_hashed_password}' WHERE email = '{email}'"
                db._execute_query(update_query)
                flash('Password changed successfully!', 'success')
                return redirect(url_for('views.system'))
            else:
                flash('Current password is incorrect.', 'error')
        finally:
            db.close()
    return render_template("changepass.html")

@auth.route('/forgotpass', methods=['GET', 'POST'])
def forgotpass():
    if request.method == 'POST':
        email = request.form.get('email')

        db = Database()
        try:
            query = f"SELECT email FROM employees WHERE email = '{email}'"
            db.cursor.execute(query)
            if not db.cursor.fetchone():
                flash('Email not found.', 'error')
                return redirect(url_for('auth.forgotpass'))

            reset_token = random.randint(100000, 999999)
            flash(f"A reset token has been sent: {reset_token}", 'success')
            session['reset_token'] = reset_token
        finally:
            db.close()
    return render_template("forgotpass.html")
