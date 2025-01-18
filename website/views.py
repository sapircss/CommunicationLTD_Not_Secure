from flask import Blueprint, render_template, session
from .auth import login_required  # Added for route protection

views = Blueprint('views', __name__)

@views.route('/')
@login_required  # SECURITY: Protect home page from unauthorized access
def home():
    return render_template("home.html", user_email=session.get('user_email')) #Passes user email from session to template