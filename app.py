from flask import Flask
from flask_login import LoginManager
from config import Config
from models import db
from routes import register_routes

app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User loader for Flask-Login
from models import User
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Register routes
register_routes(app)

# Create database tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)