# backtoschool_app/app.py
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime, timedelta
import mysql.connector
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-key")

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user_data = cursor.fetchone()
    db.close()
    
    if user_data:
        return User(
            id=user_data['id'],
            username=user_data['username'],
            role=user_data['role'],
            school_id=user_data['school_id'],
            is_verified=user_data['is_verified'],
            is_active=user_data['is_active']
        )
    return None

class User(UserMixin):
    def __init__(self, id, username, role, school_id=None, is_verified=False, is_active=True):
        self.id = id
        self.username = username
        self.role = role
        self.school_id = school_id
        self.is_verified = is_verified
        self.is_active = is_active

def get_db():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "backtoschool")
    )

def check_account_status(user_id):
    """Check if account is expired (4 years)"""
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("""
        SELECT created_at FROM users WHERE id = %s
    """, (user_id,))
    result = cursor.fetchone()
    db.close()
    
    if result and result['created_at']:
        account_age = datetime.now() - result['created_at']
        return account_age < timedelta(days=1460)  # 4 years
    return True

@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/register/student", methods=["GET", "POST"])
def register_student():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        admission_number = request.form.get("admission_number")
        school_name = request.form.get("school_name")

        db = get_db()
        cursor = db.cursor(dictionary=True)
        try:
            cursor.execute("SELECT id FROM users WHERE username = %s AND role = 'school'", (school_name,))
            school = cursor.fetchone()
            if not school:
                flash("School not found", "danger")
                return redirect(url_for("register_student"))

            cursor.execute("""
                INSERT INTO users (username, password, role, admission_number, school_id, is_verified, is_active)
                VALUES (%s, %s, 'parent', %s, %s, FALSE, TRUE)
            """, (username, password, admission_number, school['id']))
            
            db.commit()
            flash("Registration submitted for school approval", "success")
            return redirect(url_for("login"))
        except Exception as e:
            db.rollback()
            flash(str(e), "danger")
        finally:
            db.close()
    return render_template("register_student.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user_data = cursor.fetchone()
        db.close()

        if user_data:
            if password == user_data['password']:
                if user_data['role'] == 'parent' and not user_data['is_verified']:
                    flash("Account pending school approval", "danger")
                    return redirect(url_for("login"))
                
                if not user_data['is_active']:
                    flash("Account deactivated. Contact your school.", "danger")
                    return redirect(url_for("login"))
                
                if user_data['role'] == 'parent' and not check_account_status(user_data['id']):
                    flash("Account expired after 4 years. Contact school for reactivation.", "danger")
                    return redirect(url_for("login"))
                
                user = User(
                    id=user_data['id'],
                    username=user_data['username'],
                    role=user_data['role'],
                    school_id=user_data['school_id'],
                    is_verified=user_data['is_verified'],
                    is_active=user_data['is_active']
                )
                login_user(user)
                flash("Login successful", "success")
                
                if user.role == "parent":
                    return redirect(url_for("parent_dashboard"))
                elif user.role == "school":
                    return redirect(url_for("school_dashboard"))
                elif user.role == "retailer":
                    return redirect(url_for("retailer_dashboard"))
        
        flash("Invalid credentials or account issue", "danger")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully", "success")
    return redirect(url_for("login"))

@app.route("/school/students")
@login_required
def manage_students():
    if current_user.role != "school":
        flash("Access denied", "danger")
        return redirect(url_for("login"))

    db = get_db()
    cursor = db.cursor(dictionary=True)
    
    cursor.execute("""
        SELECT id, username, admission_number, is_verified, is_active, created_at
        FROM users 
        WHERE school_id = %s AND role = 'parent'
    """, (current_user.id,))
    students = cursor.fetchall()
    
    for student in students:
        student['is_expired'] = (datetime.now() - student['created_at']) > timedelta(days=1460)
    
    db.close()
    return render_template("school/manage_students.html", students=students)

@app.route("/school/student/<int:student_id>/<action>")
@login_required
def update_student_status(student_id, action):
    if current_user.role != "school":
        flash("Access denied", "danger")
        return redirect(url_for("login"))

    db = get_db()
    cursor = db.cursor()
    
    try:
        if action == "approve":
            cursor.execute("""
                UPDATE users SET is_verified = TRUE 
                WHERE id = %s AND school_id = %s
            """, (student_id, current_user.id))
            message = "Student approved"
        
        elif action == "reactivate":
            cursor.execute("""
                UPDATE users SET is_active = TRUE 
                WHERE id = %s AND school_id = %s
            """, (student_id, current_user.id))
            message = "Account reactivated"
        
        elif action == "deactivate":
            cursor.execute("""
                UPDATE users SET is_active = FALSE 
                WHERE id = %s AND school_id = %s
            """, (student_id, current_user.id))
            message = "Account deactivated"
        
        db.commit()
        flash(message, "success")
    except Exception as e:
        db.rollback()
        flash(str(e), "danger")
    finally:
        db.close()
    
    return redirect(url_for("manage_students"))

@app.route("/parent/dashboard")
@login_required
def parent_dashboard():
    if current_user.role != "parent":
        flash("Access denied", "danger")
        return redirect(url_for("login"))
    
    if not current_user.is_verified:
        flash("Account not yet approved by school", "danger")
        return redirect(url_for("login"))
    
    if not current_user.is_active:
        flash("Account deactivated. Contact your school.", "danger")
        return redirect(url_for("login"))
    
    db = get_db()
    cursor = db.cursor(dictionary=True)
    
    cursor.execute("""
        SELECT item_name, max_quantity 
        FROM school_items 
        WHERE school_id = %s AND allowed = TRUE
    """, (current_user.school_id,))
    requirements = cursor.fetchall()
    
    db.close()
    return render_template("parent/dashboard.html", requirements=requirements)

@app.route("/parent/shop")
@login_required
def parent_shop():
    if current_user.role != "parent":
        flash("Access denied", "danger")
        return redirect(url_for("login"))
    
    db = get_db()
    cursor = db.cursor(dictionary=True)
    
    cursor.execute("""
        SELECT p.id, p.item_name, p.price, u.username as retailer
        FROM products p
        JOIN users u ON p.retailer_id = u.id
        WHERE p.item_name IN (
            SELECT item_name FROM school_items 
            WHERE school_id = %s AND allowed = TRUE
        )
    """, (current_user.school_id,))
    products = cursor.fetchall()
    
    price_comparison = {}
    for product in products:
        if product['item_name'] not in price_comparison:
            price_comparison[product['item_name']] = []
        price_comparison[product['item_name']].append({
            'retailer': product['retailer'],
            'price': product['price'],
            'id': product['id']
        })
    
    db.close()
    return render_template("parent/shop.html", 
        price_comparison=price_comparison
    )

@app.route("/parent/cart", methods=["GET", "POST"])
@login_required
def parent_cart():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    
    cursor.execute("SELECT id FROM carts WHERE user_id = %s", (current_user.id,))
    cart = cursor.fetchone()
    if not cart:
        cursor.execute("INSERT INTO carts (user_id) VALUES (%s)", (current_user.id,))
        cart_id = cursor.lastrowid
    else:
        cart_id = cart['id']
    
    if request.method == "POST":
        product_id = request.form.get("product_id")
        quantity = int(request.form.get("quantity", 1))
        
        cursor.execute("""
            INSERT INTO cart_items (cart_id, product_id, quantity)
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE quantity = quantity + %s
        """, (cart_id, product_id, quantity, quantity))
        db.commit()
        flash("Item added to cart", "success")
    
    cursor.execute("""
        SELECT ci.*, p.item_name, p.price, u.username as retailer
        FROM cart_items ci
        JOIN products p ON ci.product_id = p.id
        JOIN users r ON p.retailer_id = r.id
        WHERE ci.cart_id = %s
    """, (cart_id,))
    items = cursor.fetchall()
    
    is_compliant = check_compliance(cart_id, current_user.school_id)
    total = sum(item['price'] * item['quantity'] for item in items)
    
    db.close()
    return render_template("parent/cart.html", 
        items=items,
        is_compliant=is_compliant,
        total=total
    )

@app.route("/parent/wallet", methods=["GET", "POST"])
@login_required
def parent_wallet():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    
    cursor.execute("SELECT balance FROM wallets WHERE user_id = %s", (current_user.id,))
    wallet = cursor.fetchone()
    if not wallet:
        cursor.execute("INSERT INTO wallets (user_id, balance) VALUES (%s, 1000.00)", (current_user.id,))
        db.commit()
        balance = 1000.00
    else:
        balance = wallet['balance']
    
    if request.method == "POST":
        cursor.execute("SELECT id FROM carts WHERE user_id = %s", (current_user.id,))
        cart = cursor.fetchone()
        
        if cart:
            cursor.execute("""
                SELECT SUM(p.price * ci.quantity) as total
                FROM cart_items ci
                JOIN products p ON ci.product_id = p.id
                WHERE ci.cart_id = %s AND ci.is_compliant = TRUE
            """, (cart['id'],))
            total = cursor.fetchone()['total'] or 0.00
            
            if balance >= total:
                cursor.execute("""
                    UPDATE wallets 
                    SET balance = balance - %s 
                    WHERE user_id = %s
                """, (total, current_user.id))
                
                cursor.execute("""
                    INSERT INTO orders (user_id, cart_id, total)
                    VALUES (%s, %s, %s)
                """, (current_user.id, cart['id'], total))
                
                cursor.execute("DELETE FROM cart_items WHERE cart_id = %s", (cart['id'],))
                cursor.execute("DELETE FROM carts WHERE id = %s", (cart['id'],))
                
                cursor.execute("""
                    INSERT INTO notifications (user_id, message)
                    VALUES (%s, %s)
                """, (current_user.id, f"Order placed! Total: Ksh {total}"))
                
                db.commit()
                flash("Payment successful!", "success")
            else:
                flash("Insufficient funds", "danger")
    
    db.close()
    return render_template("parent/wallet.html", 
        balance=balance
    )

@app.route("/school/requirements", methods=["GET", "POST"])
@login_required
def school_requirements():
    if current_user.role != "school":
        flash("Access denied", "danger")
        return redirect(url_for("login"))

    db = get_db()
    cursor = db.cursor(dictionary=True)
    
    if request.method == "POST":
        item_name = request.form.get("item_name")
        allowed = True if request.form.get("allowed") == "on" else False
        max_quantity = request.form.get("max_quantity")
        
        try:
            cursor.execute("""
                INSERT INTO school_items (school_id, item_name, allowed, max_quantity)
                VALUES (%s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE allowed = VALUES(allowed), max_quantity = VALUES(max_quantity)
            """, (current_user.id, item_name, allowed, max_quantity))
            
            db.commit()
            flash("Requirements updated successfully!", "success")
        except Exception as e:
            db.rollback()
            flash(f"Error: {str(e)}", "danger")
    
    cursor.execute("""
        SELECT item_name, allowed, max_quantity 
        FROM school_items 
        WHERE school_id = %s
    """, (current_user.id,))
    requirements = cursor.fetchall()
    
    db.close()
    return render_template("school/requirements.html",
        requirements=requirements
    )

@app.route("/retailer")
@login_required
def retailer_dashboard():
    if current_user.role != "retailer":
        flash("Access denied", "danger")
        return redirect(url_for("login"))

    db = get_db()
    cursor = db.cursor(dictionary=True)
    
    cursor.execute("""
        SELECT id, item_name, price, stock 
        FROM products 
        WHERE retailer_id = %s
    """, (current_user.id,))
    products = cursor.fetchall()
    
    db.close()
    return render_template("retailer/inventory.html",
        products=products
    )

@app.route("/retailer/inventory", methods=["POST"])
@login_required
def update_inventory():
    if current_user.role != "retailer":
        flash("Access denied", "danger")
        return redirect(url_for("login"))

    item_name = request.form.get("item_name")
    price = float(request.form.get("price"))
    stock = int(request.form.get("stock"))
    
    db = get_db()
    cursor = db.cursor()
    
    try:
        cursor.execute("""
            INSERT INTO products (retailer_id, item_name, price, stock)
            VALUES (%s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE price = VALUES(price), stock = VALUES(stock)
        """, (current_user.id, item_name, price, stock))
        
        db.commit()
        flash("Inventory updated successfully!", "success")
    except Exception as e:
        db.rollback()
        flash(f"Error: {str(e)}", "danger")
    finally:
        db.close()
    
    return redirect(url_for("retailer_dashboard"))

if __name__ == "__main__":
    app.run(debug=True)