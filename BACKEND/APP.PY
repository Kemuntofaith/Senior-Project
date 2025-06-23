# Import necessary libraries
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import mysql.connector
from dotenv import load_dotenv
import os

# Load environment variables (for database credentials)
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = "your_secret_key_here"  # Required for session management

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"  # Redirect to login if unauthorized

# Mock User Class (for authentication)
class User(UserMixin):
    def __init__(self, id, username, role, school_id=None):
        self.id = id
        self.username = username
        self.role = role
        self.school_id = school_id

# Database Connection
def get_db():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME")
    )

# Mock Users (for testing)
users = {
    1: User(1, "parent1", "parent"),
    2: User(2, "school1", "school"),
    3: User(3, "retailer1", "retailer")
}

# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    return users.get(int(user_id))

# Routes
@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")  # In real apps, use hashed passwords!
        
         
        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user_data = cursor.fetchone()
        db.close()
        
        # Check user (mock validation)
        user = next((u for u in users.values() if u.username == username), None)
        
        if user and password == "test123":  # Simple password for demo
            login_user(user)
            flash("Logged in successfully!", "success")
            
            # Redirect based on role
            if user.role == "parent":
                return redirect(url_for("parent_dashboard"))
            elif user.role == "school":
                return redirect(url_for("school_portal"))
            elif user.role == "retailer":
                return redirect(url_for("retailer_dashboard"))
        
        flash("Invalid username or password", "danger")
    
    return render_template("login.html")

@app.route("/parent")
@login_required
def parent_dashboard():
    if current_user.role != "parent":
        flash("Access denied!", "danger")
        return redirect(url_for("login"))
    
    # Fetch school-approved items (mock data)
    approved_items = ["Notebook", "Pen", "Uniform"]
    
    return render_template("parent.html", items=approved_items)

@app.route("/school")
@login_required
def school_portal():
    if current_user.role != "school":
        flash("Access denied!", "danger")
        return redirect(url_for("login"))
    
    return render_template("school.html")

@app.route("/retailer")
@login_required
def retailer_dashboard():
    if current_user.role != "retailer":
        flash("Access denied!", "danger")
        return redirect(url_for("login"))
    
    return render_template("retailer.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully!", "success")
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)  # Run in development mode