import sqlite3
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from db_manager import Database
from functools import wraps
import hashlib
import random
import json
import re

auth = Blueprint('auth', __name__)

# Load Configuration
with open('password_config.json', 'r') as f:
    CONFIG = json.load(f)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_email' not in session:
            flash('Please log in first.', 'error')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

def is_valid_password(password: str, email: str = None) -> str:
    """Validate the password based on the configuration file."""

    if len(password) < CONFIG["password_length"]:
        return f"Password must be at least {CONFIG['password_length']} characters long."

    if CONFIG["complexity"]["uppercase"] and not any(c.isupper() for c in password):
        return "Password must contain at least one uppercase letter."

    if CONFIG["complexity"]["lowercase"] and not any(c.islower() for c in password):
        return "Password must contain at least one lowercase letter."

    if CONFIG["complexity"]["numbers"] and not any(c.isdigit() for c in password):
        return "Password must contain at least one number."

    if CONFIG["complexity"]["special_characters"] and not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Password must contain at least one special character."

    for word in CONFIG["dictionary_words"]:
        if word.lower() in password.lower():
            return "Password is too weak. Do not use common words or phrases."

    return None

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        db = Database()
        try:
            user_data = {
                'id': request.form.get('id', ''),
                'first_name': request.form.get('firstName', ''),
                'last_name': request.form.get('lastName', ''),
                'password': request.form.get('password1', ''),
                'email': request.form.get('email', '')
            }

            if user_data['password'] != request.form.get('password2', ''):
                flash('Passwords do not match.', 'error')
                return render_template("register.html", **user_data)

            # Validate password from config
            password_error = is_valid_password(user_data['password'])
            if password_error:
                flash(password_error, 'error')
                return render_template("register.html", **user_data)

            # 🚨 SQL Injection Vulnerable Query
            query = f"INSERT INTO employees (id, first_name, last_name, email, password) VALUES ('{user_data['id']}', '{user_data['first_name']}', '{user_data['last_name']}', '{user_data['email']}', '{hashlib.sha256(user_data['password'].encode()).hexdigest()}')"
            db._execute_query(query)

            flash('Registration successful!', 'success')
            return redirect(url_for('auth.login'))
        finally:
            db.close()
    return render_template("register.html")

@auth.route('/changepass', methods=['GET', 'POST'])
@login_required
def changepass():
    if request.method == 'POST':
        current_password = request.form.get('oldPassword', '')
        new_password = request.form.get('newPassword', '')
        confirm_password = request.form.get('confirmPassword', '')

        if not current_password or not new_password or not confirm_password:
            flash('All fields are required.', 'error')
            return redirect(url_for('auth.changepass'))

        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('auth.changepass'))

        # Validate new password
        password_error = is_valid_password(new_password, session.get('user_email'))
        if password_error:
            flash(password_error, 'error')
            return redirect(url_for('auth.changepass'))

        db = Database()
        try:
            email = session.get('user_email')

            # 🚨 SQL Injection Vulnerable Query
            query = f"SELECT password FROM employees WHERE email = '{email}'"
            db.cursor.execute(query)
            result = db.cursor.fetchone()

            if result and hashlib.sha256(current_password.encode()).hexdigest() == result[0]:
                # 🚨 SQL Injection Vulnerable Query
                update_query = f"UPDATE employees SET password = '{hashlib.sha256(new_password.encode()).hexdigest()}' WHERE email = '{email}'"
                db._execute_query(update_query)
                flash('Password changed successfully!', 'success')
                return redirect(url_for('views.system'))
            else:
                flash('Current password is incorrect.', 'error')
        finally:
            db.close()
    return render_template("changepass.html")

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '')
        password = request.form.get('password', '')

        db = Database()
        try:
            # 🚨 SQL Injection Vulnerable Query
            query = f"SELECT * FROM employees WHERE email = '{email}' AND password = '{hashlib.sha256(password.encode()).hexdigest()}'"
            db.cursor.execute(query)
            user = db.cursor.fetchone()

            if user:
                session['user_email'] = email
                flash(f"Logged in as {email}", 'success')
                return redirect(url_for('views.system'))
            else:
                flash('Invalid credentials.', 'error')
        finally:
            db.close()
    return render_template("login.html")

@auth.route('/logout', methods=['POST'])
@login_required
def logout():
    session.pop('user_email', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('auth.login'))

@auth.route('/forgotpass', methods=['GET', 'POST'])
def forgotpass():
    if request.method == 'POST':
        email = request.form.get('email', '')

        db = Database()
        try:
            # 🚨 SQL Injection Vulnerable Query
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
