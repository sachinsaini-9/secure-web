from flask import Flask, render_template, request, redirect, url_for, flash, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import re
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()  

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sachin'


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db.init_app(app)
with app.app_context():
    db.create_all()
bcrypt = Bcrypt(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["5 per minute"])
login_manager = LoginManager(app)
login_manager.login_view = "login"

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def sanitize_input(input_text):
    """Prevent XSS by removing special characters"""
    return re.sub(r"[<>\"';]", "", input_text)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = sanitize_input(request.form["username"])
        password = request.form["password"]

  #  Input Validation 
        if User.query.filter_by(username=username).first():
            flash("Username already taken", "danger")
            return redirect(url_for("register"))
   
   # Password Strength Validation (Reject Weak Passwords)
        if not is_strong_password(password):
            flash("Password must be at least 8 characters, include uppercase, lowercase, a number, and a special character.", "danger")
            return redirect(url_for('register'))

  # Hash Password Before Storing to Database
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful!", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

# Password Strength Meter
def is_strong_password(password):
    return (
        len(password) >= 8 and
        re.search(r'[A-Z]', password) and  # At least one uppercase letter
        re.search(r'[a-z]', password) and  # At least one lowercase letter
        re.search(r'\d', password) and     # At least one number
        re.search(r'[\W_]', password)      # At least one special character
    )

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")  # Prevent brute-force attacks
def login():
    if request.method == "POST":
        username = sanitize_input(request.form["username"])
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("dashboard"))

        flash("Invalid credentials", "danger")
        return redirect(url_for("login"))

    return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", username=current_user.username)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully", "info")
    return redirect(url_for("login"))

#  Adding Security Headers to All Responses
@app.after_request
def set_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"  # Prevent clickjacking
    response.headers["X-XSS-Protection"] = "1; mode=block"  # Prevent XSS
    response.headers["X-Content-Type-Options"] = "nosniff"  # Prevent MIME sniffing
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'"  # Restrict scripts
    return response

if __name__ == "__main__":
    app.run(debug=True)

