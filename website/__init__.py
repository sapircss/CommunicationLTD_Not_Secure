from flask import Flask
from datetime import timedelta

def create_app():
    app = Flask(__name__)

    app.config.update(
        SECRET_KEY='dev',  # Weak key for testing
        PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
        SESSION_COOKIE_SECURE=False,  # Insecure settings for testing
        SESSION_COOKIE_HTTPONLY=False,
        SESSION_COOKIE_SAMESITE=None,
        DEBUG=True
    )

    # Import and register Blueprints
    from .views import views
    from .auth import auth

    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')

    return app
