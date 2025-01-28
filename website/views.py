from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from db_manager import Database
from .auth import login_required

views = Blueprint('views', __name__)

@views.route('/')
def home():
    return render_template("home.html")

@views.route('/system', methods=['GET', 'POST'])
@login_required
def system():
    db = Database()
    clients = []

    try:
        db.create_table('clients')

        if request.method == 'POST':
            client_data = {
                'id': request.form['id'],
                'first_name': request.form['firstName'],
                'last_name': request.form['lastName']
            }

            if "<script>" in client_data['first_name'] or "<script>" in client_data['last_name']:
                flash('XSS detected in input fields! Hacked XSS.', 'error')
                print("Hacked XSS detected in input fields.")

            db.insert_user_to_table('clients', client_data)
            flash('Client added successfully!', 'success')

        filter_id = request.args.get('filter_id')
        if filter_id:
            query = f"SELECT * FROM clients WHERE id = '{filter_id}'"
            db.cursor.execute(query)
        else:
            query = "SELECT * FROM clients"
            db.cursor.execute(query)

        clients = db.cursor.fetchall()
    finally:
        db.close()

    return render_template("system.html", clients=clients)
