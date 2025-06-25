# backtoschool_app/app.py
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime, timedelta
import mysql.connector
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-key")

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
            is_active=user_data['is_active'],
            is_approved=user_data['is_approved']
        )
    return None

class User(UserMixin):
    def __init__(self, id, username, role, school_id=None, is_verified=False, is_active=True, is_approved=False):
        self.id = id
        self.username = username
        self.role = role
        self.school_id = school_id
        self.is_verified = is_verified
        self.is_active = is_active
        self.is_apprroved = is_approved

def get_db():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "back2school")
    )

def check_compliance(cart_id, school_id):
    """Validate all items in cart against school rules"""
    db = get_db()
    cursor = db.cursor(dictionary=True)
    
    # Get cart items
    cursor.execute("""
        SELECT ci.product_id, ci.quantity, p.item_name 
        FROM cart_items ci
        JOIN products p ON ci.product_id = p.id
        WHERE ci.cart_id = %s
    """, (cart_id,))
    items = cursor.fetchall()
    
    # Check each item against school rules
    all_compliant = True
    for item in items:
        cursor.execute("""
            SELECT allowed, max_quantity 
            FROM school_items 
            WHERE item_name = %s AND school_id = %s
        """, (item['item_name'], school_id))
        rule = cursor.fetchone()
        
        # Update compliance status
        compliant = rule and rule['allowed'] and (not rule['max_quantity'] or item['quantity'] <= rule['max_quantity'])
        cursor.execute("""
            UPDATE cart_items 
            SET is_compliant = %s 
            WHERE cart_id = %s AND product_id = %s
        """, (compliant, cart_id, item['product_id']))
        
        if not compliant:
            all_compliant = False
    
    db.commit()
    db.close()
    return all_compliant

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
            flash(f"Registration error: {str(e)}", "danger")
        finally:
            db.close()
    return render_template("register_student.html")

@app.route("/register/school", methods=["GET", "POST"])
def register_school():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        school_name = request.form.get("school_name")

        db = get_db()
        cursor = db.cursor(dictionary=True)
        try:
            cursor.execute("""
                INSERT INTO users (username, password, role, is_verified)
                VALUES (%s, %s, 'school', FALSE)
            """, (username, password))
            
            db.commit()
            flash("School registration submitted for admin approval", "success")
            return redirect(url_for("login"))
        except Exception as e:
            db.rollback()
            flash(f"Registration error: {str(e)}", "danger")
        finally:
            db.close()
    return render_template("register_school.html")

@app.route("/register/retailer", methods=["GET", "POST"])
def register_retailer():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        business_name = request.form.get("business_name")

        db = get_db()
        cursor = db.cursor(dictionary=True)
        try:
            cursor.execute("""
                INSERT INTO users (username, password, role, is_approved)
                VALUES (%s, %s, 'retailer', FALSE)
            """, (username, password))

            retailer_id = cursor.lastrowid
            cursor.execute("""
                INSERT INTO retailer_profiles (user_id, business_name)
                VALUES (%s, %s)
            """, (retailer_id, business_name))
            
            db.commit()
            flash("Retailer registration submitted for school approval", "success")
            return redirect(url_for("login"))
        except Exception as e:
            db.rollback()
            flash(f"Registration error: {str(e)}", "danger")
        finally:
            db.close()
    return render_template("register_retailer.html")

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
                if user_data['role'] == 'school' and not user_data['is_verified']:
                    flash("School account pending admin approval")
                    return redirect(url_for("login"))
                    
                if user_data['role'] == 'retailer' and not user_data['is_approved']:
                    flash("Retailer account pending school approval")
                    return redirect(url_for("login"))
                
                if user_data['role'] == 'parent' and not user_data['is_verified']:
                    flash("Account pending school approval")
                    return redirect(url_for("login"))
                
                if not user_data['is_active']:
                    flash("Account deactivated. Contact your school.", "danger")
                    return redirect(url_for("login"))
                
                if user_data['role'] == 'parent' and not check_account_status(user_data['id']):
                    flash("Account expired after 4 years. Contact school for reactivation.")
                    return redirect(url_for("login"))
                
                user = User(
                    id=user_data['id'],
                    username=user_data['username'],
                    role=user_data['role'],
                    school_id=user_data['school_id'],
                    is_verified=user_data['is_verified'],
                    is_active=user_data['is_active'],
                    is_approved=user_data['is_approved']
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

@app.route("/school")
@login_required
def school_dashboard():
    if current_user.role != "school":
        flash("Access denied", "danger")
        return redirect(url_for("login"))
    
    db = get_db()
    cursor = db.cursor(dictionary=True)
    
    cursor.execute("""
        SELECT COUNT(*) as pending_students 
        FROM users 
        WHERE school_id = %s AND role = 'parent' AND is_verified = FALSE
    """, (current_user.id,))
    pending_students = cursor.fetchone()['pending_students']

    cursor.execute("""
        SELECT COUNT(*) as pending_retailers
        FROM users u
        JOIN retailer_profiles r ON u.id = r.user_id
        WHERE u.role = 'retailer' AND u.is_approved = FALSE
    """)
    pending_retailers = cursor.fetchone()['pending_retailers']
    
    db.close()
    return render_template("school/dashboard.html",
        pending_students=pending_students,
        pending_retailers=pending_retailers
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
            flash(f"Error updating requirements: {str(e)}", "danger")
    
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

@app.route("/school/students")
@login_required
def manage_students():
    if current_user.role != "school":
        flash("Access denied")
        return redirect(url_for("login"))

    db = get_db()
    cursor = db.cursor(dictionary=True)
    
    cursor.execute("""
        SELECT id, username, admission_number, is_verified, is_active, created_at
        FROM users 
        WHERE school_id = %s AND role = 'parent'
        ORDER BY is_verified, created_at DESC
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
        flash("Access denied")
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
        flash(F"Error: {str(e)}", "danger")
    finally:
        db.close()
    
    return redirect(url_for("manage_students"))

@app.route("/school/retailers")
@login_required
def retailer_approvals():
    if current_user.role != "school":
        flash("Access denied")
        return redirect(url_for("login"))

    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("""
        SELECT u.id, u.username, r.business_name, u.created_at
        FROM users u
        JOIN retailer_profiles r ON u.id = r.user_id
        WHERE u.role = 'retailer' AND u.is_approved = FALSE
        ORDER BY u.created_at
    """)
    pending_retailers = cursor.fetchall()
    db.close()
    return render_template("school/retailer_approvals.html",
        retailers=pending_retailers
    )

@app.route("/school/approve_retailer/<int:retailer_id>")
@login_required
def approve_retailer(retailer_id):
    if current_user.role != "school":
        flash("Access denied")
        return redirect(url_for("login"))

    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("""
            UPDATE users SET is_approved = TRUE 
            WHERE id = %s AND role = 'retailer'
        """, (retailer_id,))
        db.commit()
        flash("Retailer approved successfully", "success")
    except Exception as e:
        db.rollback()
        flash(f"Approval failed: {str(e)}", "danger")
    finally:
        db.close()
    return redirect(url_for("retailer_approvals"))

@app.route("/parent/dashboard")
@login_required
def parent_dashboard():
    if current_user.role != "parent":
        flash("Access denied")
        return redirect(url_for("login"))
    
    if not current_user.is_verified:
        flash("Account not yet approved by school", "danger")
        return redirect(url_for("login"))
    
    if not current_user.is_active:
        flash("Account deactivated. Contact your school.")
        return redirect(url_for("login"))
    
    db = get_db()
    cursor = db.cursor(dictionary=True)
    
    cursor.execute("""
        SELECT item_name, max_quantity 
        FROM school_items 
        WHERE school_id = %s AND allowed = TRUE
    """, (current_user.school_id,))
    requirements = cursor.fetchall()

    cursor.execute("""
        SELECT message, created_at 
        FROM notifications 
        WHERE user_id = %s
        ORDER BY created_at DESC
        LIMIT 5
    """, (current_user.id,))
    notifications = cursor.fetchall()
    
    db.close()
    return render_template("parent/dashboard.html", requirements=requirements, notifications=notifications)

@app.route("/parent/shop")
@login_required
def parent_shop():
    if current_user.role != "parent":
        flash("Access denied", "danger")
        return redirect(url_for("login"))
    
    db = get_db()
    cursor = db.cursor(dictionary=True)
    
    cursor.execute("""
        SELECT p.id, p.item_name, p.price, u.username as retailer, p.stock
        FROM products p
        JOIN users u ON p.retailer_id = u.id
        WHERE p.item_name IN (
            SELECT item_name FROM school_items 
            WHERE school_id = %s AND allowed = TRUE
        ) AND u.is_approved = TRUE AND p.stock > 0
        ORDER BY p.item_name, p.price
    """, (current_user.school_id,))
    products = cursor.fetchall()
    
    price_comparison = {}
    for product in products:
        if product['item_name'] not in price_comparison:
            price_comparison[product['item_name']] = []
        price_comparison[product['item_name']].append({
            'retailer': product['retailer'],
            'price': product['price'],
            'id': product['id'],
            'stock': product['stock']
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
        db.commit()
    else:
        cart_id = cart['id']

    if request.method == "POST":
        product_id = request.form.get("product_id")
        quantity = int(request.form.get("quantity", 1))
        
        try:
            cursor.execute("SELECT stock FROM products WHERE id = %s", (product_id,))
            product = cursor.fetchone()
            
            if product and product['stock'] >= quantity:
                cursor.execute("""
                    INSERT INTO cart_items (cart_id, product_id, quantity)
                    VALUES (%s, %s, %s)
                    ON DUPLICATE KEY UPDATE quantity = quantity + VALUES(quantity)
                """, (cart_id, product_id, quantity))
                db.commit()
                flash("Item added to cart", "success")
            else:
                flash("Insufficient stock", "danger")
        except Exception as e:
            db.rollback()
            flash(f"Error: {str(e)}", "danger")

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

@app.route("/parent/cart/remove/<int:product_id>")
@login_required
def remove_from_cart(product_id):
    db = get_db()
    cursor = db.cursor()
    
    try:
        cursor.execute("""
            DELETE FROM cart_items 
            WHERE cart_id = (SELECT id FROM carts WHERE user_id = %s) 
            AND product_id = %s
        """, (current_user.id, product_id))
        db.commit()
        flash("Item removed from cart", "success")
    except Exception as e:
        db.rollback()
        flash(f"Error: {str(e)}", "danger")
    finally:
        db.close()
    
    return redirect(url_for("parent_cart"))

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
                    INSERT INTO orders (user_id, cart_id, total, status)
                    VALUES (%s, %s, %s, 'pending')
                """, (current_user.id, cart['id'], total))
                order_id = cursor.lastrowid

                cursor.execute("""
                        UPDATE products p
                        JOIN cart_items ci ON p.id = ci.product_id
                        SET p.stock = p.stock - ci.quantity
                        WHERE ci.cart_id = %s
                    """, (cart['id'],))
                
                cursor.execute("DELETE FROM cart_items WHERE cart_id = %s", (cart['id'],))
                cursor.execute("DELETE FROM carts WHERE id = %s", (cart['id'],))
                
                cursor.execute("""
                    INSERT INTO notifications (user_id, message)
                    VALUES (%s, %s)
                """, (current_user.id, f"Order placed! #{order_id}Total: Ksh {total:.2f}"))

                db.commit()
                flash("Payment successful! Order placed.", "success")
                return redirect(url_for("parent_dashboard"))
        else:
            flash("Insufficient funds or no valid items")
    
    cursor.execute("""
        SELECT id, total, created_at 
        FROM orders 
        WHERE user_id = %s
        ORDER BY created_at DESC
        LIMIT 5
    """, (current_user.id,))
    transactions = cursor.fetchall()

    db.close()
    return render_template("parent/wallet.html", 
        balance=balance,transactions=transactions
    )
           
@app.route("/retailer")
@login_required
def retailer_dashboard():
    if current_user.role != "retailer":
        flash("Access denied", "danger")
        return redirect(url_for("login"))
    
    if not current_user.is_approved:
        flash("Account pending approval", "danger")
        return redirect(url_for("login"))

    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute("""
        SELECT COUNT(*) as order_count, SUM(o.total) as revenue
        FROM orders o
        JOIN carts c ON o.cart_id = c.id
        JOIN cart_items ci ON c.id = ci.cart_id
        JOIN products p ON ci.product_id = p.id
        WHERE p.retailer_id = %s
    """, (current_user.id,))
    sales = cursor.fetchone()
    
    cursor.execute("""
        SELECT item_name, stock 
        FROM products 
        WHERE retailer_id = %s AND stock < 5
        ORDER BY stock
        LIMIT 5
    """, (current_user.id,))
    low_stock = cursor.fetchall()
    
    db.close()
    return render_template("retailer/dashboard.html",
        order_count=sales['order_count'] or 0,
        revenue=sales['revenue'] or 0,
        low_stock=low_stock
    )

@app.route("/retailer/inventory", methods=["GET", "POST"])
@login_required
def update_inventory():
    if current_user.role != "retailer":
        flash("Access denied", "danger")
        return redirect(url_for("login"))

    item_name = request.form.get("item_name")
    price = float(request.form.get("price"))
    stock = int(request.form.get("stock"))
    
    db = get_db()
    cursor = db.cursor(dictionary=True)
    
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

    cursor.execute("""
        SELECT id, item_name, price, stock
        FROM products
        WHERE retailer_id = %s
        ORDER BY item_name
    """, (current_user.id,))
    inventory = cursor.fetchall()
    
    db.close()
    return render_template("retailer/inventory.html",
        inventory=inventory
    )

@app.route("/retailer/orders")
@login_required
def retailer_orders():
    if current_user.role != "retailer":
        flash("Access denied", "danger")
        return redirect(url_for("login"))
    
    db = get_db()
    cursor = db.cursor(dictionary=True)
    
    cursor.execute("""
        SELECT o.id, o.total, o.status, o.created_at, u.username as customer
        FROM orders o
        JOIN carts c ON o.cart_id = c.id
        JOIN users u ON c.user_id = u.id
        JOIN cart_items ci ON c.id = ci.cart_id
        JOIN products p ON ci.product_id = p.id
        WHERE p.retailer_id = %s
        GROUP BY o.id
        ORDER BY o.created_at DESC
    """, (current_user.id,))
    orders = cursor.fetchall()
    
    db.close()
    return render_template("retailer/orders.html",
        orders=orders
    )

@app.route("/retailer/order/<int:order_id>/<status>")
@login_required
def update_order_status(order_id, status):
    if current_user.role != "retailer":
        flash("Access denied", "danger")
        return redirect(url_for("login"))
    
    if status not in ['pending', 'shipped', 'delivered']:
        flash("Invalid status", "danger")
        return redirect(url_for("retailer_orders"))
    
    db = get_db()
    cursor = db.cursor()
    
    try:
        cursor.execute("""
            UPDATE orders 
            SET status = %s 
            WHERE id = %s AND id IN (
                SELECT o.id
                FROM orders o
                JOIN carts c ON o.cart_id = c.id
                JOIN cart_items ci ON c.id = ci.cart_id
                JOIN products p ON ci.product_id = p.id
                WHERE p.retailer_id = %s
            )
        """, (status, order_id, current_user.id))
        
        if cursor.rowcount == 0:
            flash("Order not found or not authorized", "danger")
        else:
            db.commit()
            flash(f"Order status updated to {status}", "success")
    except Exception as e:
        db.rollback()
        flash(f"Error: {str(e)}", "danger")
    finally:
        db.close()
    
    return redirect(url_for("retailer_orders"))

@app.route("/admin/approve_school/<int:school_id>")
@login_required
def approve_school(school_id):
    if current_user.role != "admin":
        flash("Access denied", "danger")
        return redirect(url_for("login"))
    
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("""
            UPDATE users SET is_verified = TRUE 
            WHERE id = %s AND role = 'school'
        """, (school_id,))
        db.commit()
        flash("School approved successfully", "success")
    except Exception as e:
        db.rollback()
        flash(f"Approval failed: {str(e)}", "danger")
    finally:
        db.close()
    return redirect(url_for("admin_dashboard"))

@app.route("/admin")
@login_required
def admin_dashboard():
    if current_user.role != "admin":
        flash("Access denied", "danger")
        return redirect(url_for("login"))
    
    db = get_db()
    cursor = db.cursor(dictionary=True)
    
    cursor.execute("""
        SELECT id, username, created_at
        FROM users
        WHERE role = 'school' AND is_verified = FALSE
        ORDER BY created_at
    """)
    pending_schools = cursor.fetchall()
 
    cursor.execute("SELECT COUNT(*) as user_count FROM users")
    user_count = cursor.fetchone()['user_count']
    
    cursor.execute("SELECT COUNT(*) as school_count FROM users WHERE role = 'school'")
    school_count = cursor.fetchone()['school_count']
    
    db.close()
    return render_template("admin/dashboard.html",
        pending_schools=pending_schools,
        user_count=user_count,
        school_count=school_count
    )

@app.errorhandler(404)
def page_not_found(e):
    return render_template("errors/404.html"), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template("errors/500.html"), 500

if __name__ == "__main__":
    app.run(debug=True)