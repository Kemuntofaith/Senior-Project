from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event, Engine
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
import csv
import io
from datetime import datetime
from config import Config
import random

app = Flask(__name__)
app.config.from_object(Config)

# Allow overriding database name from .env for SQLite, defaulting to original name
db_name = os.getenv("DB_NAME", "back2school.sqlite")
if not db_name.endswith('.sqlite'): # Simple check to ensure we use a file for sqlite
    db_name = "back2school.sqlite"

app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_name}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# app.config['SECRET_KEY'] = os.urandom(24)

db = SQLAlchemy(app)

# ====================== MODELS ======================
parent_student_association = db.Table('parent_student_association',
    db.Column('parent_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('student_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20))  # app_admin, parent, student, school_admin, retailer, donor
    is_approved = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    school_id = db.Column(db.Integer, db.ForeignKey('school.id'))
    school = db.relationship('School', backref='users')
    
    children = db.relationship(
        'User', 
        secondary=parent_student_association,
        primaryjoin=(parent_student_association.c.parent_id == id),
        secondaryjoin=(parent_student_association.c.student_id == id),
        backref=db.backref('parents'),
        lazy='dynamic'
    )    
    # notification_list = db.relationship('Notification', back_populates='user')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    # @property
    # def wallet(self):
    #     return Wallet.query.filter_by(user_id=self.id).first() or Wallet(user_id=self.id, balance=0.0)
    def get_or_create_wallet(self):
        """Returns the user's wallet, creating it if it doesn't exist."""
        if self.wallet:
            return self.wallet
    
        # If no wallet exists, create and commit it
        new_wallet = Wallet(user_id=self.id)
        db.session.add(new_wallet)
        # You may need to commit here depending on your transaction logic
        # For now, we'll let the calling function handle the commit.
        return new_wallet
    # def add_notification(self, title, message, notification_type, reference_id=None):
    #     notification = Notification(
    #         user_id=self.id,
    #         title=title,
    #         message=message,
    #         notification_type=notification_type,
    #         reference_id=reference_id
    #     )
    #     db.session.add(notification)
    #     db.session.commit()
    #     return notification
    
    def get_retailer(self):
        if self.role == 'retailer':
            return Retailer.query.filter_by(user_id=self.id).first()
        return None

def check_compliance(items, school_id):
    """Check items against school requirements"""
    non_compliant = []
    requirements = SchoolRequirement.query.filter_by(school_id=school_id).all()
    
    for item in items:
        # Check if item is restricted
        req = next((r for r in requirements if r.item_name.lower() in item.product.name.lower()), None)
        if req and not req.is_allowed:
            non_compliant.append({
                'product': item.product,
                'reason': f'Restricted item: {req.item_name}'
            })
        
        # Check quantity limits if specified
        if req and req.quantity_required and item.quantity > req.quantity_required:
            non_compliant.append({
                'product': item.product,
                'reason': f'Quantity exceeds school limit of {req.quantity_required}'
            })
    
    return non_compliant

def compare_prices(product_name, school_id):
    """Compare prices across retailers for a product"""
    school = School.query.get(school_id)
    if not school:
        return []
    
    # Get all approved retailers for this school
    retailers = Retailer.query.filter(Retailer.approved_schools.any(id=school_id)).all()
    retailer_ids = [r.id for r in retailers]
    
    # Find matching products
    products = Product.query.filter(Product.name.ilike(f'%{product_name}%'),
                                  Product.retailer_id.in_(retailer_ids),
                                  Product.quantity > 0).all()
    
    comparisons = []
    for product in products:
        retailer = next(r for r in retailers if r.id == product.retailer_id)
        distance = calculate_distance(school.address, retailer.business_address)
        
        comparison = {
            'product': product,
            'retailer': retailer,
            'price': product.price,
            'distance': distance,
            'is_best_price': product.price == product.best_price
        }
        comparisons.append(comparison)
    
    # Sort by price then distance
    comparisons.sort(key=lambda x: (x['price'], x['distance']))
    return comparisons

def calculate_distance(address1, address2):
    """Simplified distance calculation - in a real app, use geocoding API"""
    # This is a placeholder - implement real distance calculation
    return random.uniform(0.5, 10.0)  # Random distance for demo

    
class School(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(200))
    is_approved = db.Column(db.Boolean, default=False)
    requirements = db.relationship('SchoolRequirement', backref='school', lazy=True)

class SchoolRequirement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    school_id = db.Column(db.Integer, db.ForeignKey('school.id'), nullable=False)
    item_name = db.Column(db.String(100), nullable=False)
    item_description = db.Column(db.Text)
    quantity_required = db.Column(db.Integer)
    is_allowed = db.Column(db.Boolean, default=True)
    category = db.Column(db.String(50))

class Retailer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    business_name = db.Column(db.String(100), nullable=False)
    business_address = db.Column(db.String(200))
    is_approved_by_admin = db.Column(db.Boolean, default=False)
    is_approved_by_school = db.Column(db.Boolean, default=False)
    approved_schools = db.relationship('School', secondary='retailer_school', backref='approved_retailers')

retailer_school = db.Table('retailer_school',
    db.Column('retailer_id', db.Integer, db.ForeignKey('retailer.id'), primary_key=True),
    db.Column('school_id', db.Integer, db.ForeignKey('school.id'), primary_key=True)
)



class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    retailer_id = db.Column(db.Integer, db.ForeignKey('retailer.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    original_price = db.Column(db.Float)  # For showing discounts
    quantity = db.Column(db.Integer, default=0)
    category_id = db.Column(db.Integer, db.ForeignKey('product_category.id'), nullable=False)
    category = db.relationship('ProductCategory', backref='products')
    is_featured = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    retailer = db.relationship('Retailer', backref='products')
    
    @property
    def best_price(self):
        comparison = PriceComparison.query.filter_by(product_id=self.id)\
                                        .order_by(PriceComparison.price)\
                                        .first()
        return comparison.price if comparison else self.price
    
class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    user = db.relationship('User', backref='carts')
    items = db.relationship('CartItem', backref='cart', cascade='all, delete-orphan')
    @property
    def total_price(self):
        """Calculates the grand total for all items in the cart."""
        return sum(item.total_price for item in self.items)

class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cart_id = db.Column(db.Integer, db.ForeignKey('cart.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1)
     
    product = db.relationship('Product')
    @property
    def total_price(self):
        """Calculates the total price for this specific cart item."""
        return self.product.price * self.quantity

class Donation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    donor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    donation_type = db.Column(db.String(20))  # monetary, item
    amount = db.Column(db.Float)  # for monetary donations
    description = db.Column(db.Text)  # for item donations
    status = db.Column(db.String(20), default='pending')  # pending, approved, distributed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    donor = db.relationship('User', foreign_keys=[donor_id])
    items = db.relationship('DonationItem', backref='donation', cascade='all, delete-orphan')
    donation_distributions = db.relationship('DonationDistribution', backref='donation_rel', cascade='all, delete-orphan')

class DonationItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    donation_id = db.Column(db.Integer, db.ForeignKey('donation.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    quantity = db.Column(db.Integer)
    description = db.Column(db.Text)  # For non-product donations
    
    product = db.relationship('Product')

class DonationDistribution(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    donation_id = db.Column(db.Integer, db.ForeignKey('donation.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'))
    amount = db.Column(db.Float)  
    item_id = db.Column(db.Integer, db.ForeignKey('donation_item.id'))  # For item donations
    distributed_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # donation_rel = db.relationship('Donation', foreign_keys=[donation_id])
    recipient = db.relationship('User', foreign_keys=[recipient_id])
    # order = db.relationship('Order', foreign_keys=[order_id])
    donation_item = db.relationship('DonationItem', foreign_keys=[item_id])

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    school_id = db.Column(db.Integer, db.ForeignKey('school.id'), nullable=False)
    total_amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, paid, processing, shipped, delivered
    payment_method = db.Column(db.String(20))  # wallet, donation, mixed
    donation_used = db.Column(db.Float, default=0.0)  # Amount covered by donations
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id')) # This is the student
    student = db.relationship('User', foreign_keys=[student_id])
    
    user = db.relationship('User', backref='orders', foreign_keys=[user_id])
    school = db.relationship('School', backref='orders')
    items = db.relationship('OrderItem', backref='order', cascade='all, delete-orphan')
    donations = db.relationship('DonationDistribution', backref='order', foreign_keys=[DonationDistribution.order_id], cascade='all, delete-orphan')
    # donations = db.relationship('DonationDistribution', backref='order', foreign_keys=['DonationDistribution.order_id'], cascade='all, delete-orphan')
class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(30), default='Pending')
    
    product = db.relationship('Product')

class Wallet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    balance = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    user = db.relationship('User', backref=db.backref('wallet', uselist=False))
    transactions = db.relationship('WalletTransaction', backref='wallet', cascade='all, delete-orphan')

class WalletTransaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    wallet_id = db.Column(db.Integer, db.ForeignKey('wallet.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    transaction_type = db.Column(db.String(20))  # deposit, payment, donation
    reference = db.Column(db.String(100))  # order_id or donation_id
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class OrderTracking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    status = db.Column(db.String(20))  # processing, packed, shipped, delivered
    location = db.Column(db.String(100))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    notes = db.Column(db.Text)
    order_item_id = db.Column(db.Integer, db.ForeignKey('order_item.id'))
    status = db.Column(db.String(30))
    order = db.relationship('Order', backref='tracking_updates')
    
class ProductCategory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

class PriceComparison(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    retailer_id = db.Column(db.Integer, db.ForeignKey('retailer.id'), nullable=False)
    price = db.Column(db.Float, nullable=False)
    distance = db.Column(db.Float)  # Distance from school in miles
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    product = db.relationship('Product', backref='comparisons')
    retailer = db.relationship('Retailer', backref='price_comparisons')

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    notification_type = db.Column(db.String(50))  # order, donation, compliance, deal
    reference_id = db.Column(db.Integer)  # ID of related item (order_id, etc.)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # user = db.relationship('User')
    # user = db.relationship('User', back_populates='notification_list')

@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if isinstance(dbapi_connection, sqlite3.Connection):    
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

def create_admin_user():
    with app.app_context():
        admin_user = User.query.filter_by(role='app_admin').first()
        if not admin_user:
            admin = User(
                username='admin',
                email='admin@schoolapp.com',
                role='app_admin',
                is_approved=True
            )
            admin.set_password('securepassword123')  # Change this!
            db.session.add(admin)
            db.session.commit()
            print("Admin admin user created successfully!")

# ====================== DECORATORS ======================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in to access this page', 'error')
                return redirect(url_for('login'))
            if session['role'] not in roles:
                flash('You do not have permission to access this page', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.context_processor
def inject_current_user():
    if 'user_id' in session:
        # user = User.query.get(session['user_id'])
        user = db.session.get(User, session['user_id'])
        return {'current_user': user}
    return {'current_user': None}

@app.context_processor
def inject_cart_item_count():
    if 'user_id' in session and session['role'] in ['parent', 'student']:
        user = db.session.get(User, session['user_id'])
        # CORRECTED LINE: Use list index [0] to get the first cart.
        cart = user.carts[0] if user.carts else None
        if cart and cart.items:
            return {'cart_item_count': len(cart.items)}
    return {'cart_item_count': 0}

@app.template_filter('datetime')
def format_datetime(value, format='medium'):
    if format == 'full':
        format = "%Y-%m-%d %H:%M:%S"
    elif format == 'medium':
        format = "%Y-%m-%d %H:%M"
    else:
        format = "%Y-%m-%d"
    return value.strftime(format)

# ====================== ROUTES ======================
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            if not user.is_approved and user.role in ['retailer', 'school_admin']:
                flash('Your account is pending approval', 'error')
                return render_template('login.html')
            
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            if user.role == 'school_admin' and user.school_id:
                session['school_id'] = user.school_id
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    # user = User.query.get(session['user_id'])
    user = db.session.get(User, session['user_id'])
    return render_template('dashboard.html', user=user)

# ====================== USER MANAGEMENT ROUTES ======================
@app.route('/register-school', methods=['GET', 'POST'])
def register_school():
    if request.method == 'POST':
        # User details
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        # School details
        school_name = request.form.get('school_name')
        school_address = request.form.get('school_address')

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('A user with that username or email already exists.', 'error')
            return redirect(url_for('register_school'))

        # Create the School first, but unapproved
        new_school = School(name=school_name, address=school_address, is_approved=False)
        db.session.add(new_school)
        db.session.flush()  # Flush to get the school's ID before creating the user

        # Create the school_admin user and link them to the new school
        new_user = User(
            username=username,
            email=email,
            role='school_admin',
            school_id=new_school.id,
            is_approved=False # Will be approved when the school is
        )
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash('School and admin account registered. Awaiting system approval.', 'success')
        return redirect(url_for('login'))

    return render_template('register_school.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        if role == 'school_admin':
            flash('Please use the dedicated school registration form.', 'info')
            return redirect(url_for('register_school'))
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'error')
            return redirect(url_for('register'))
        
        new_user = User(username=username, email=email, role=role)
        new_user.set_password(password)
        
        # Auto-approve certain roles
        if role in ['parent', 'student', 'donor']:
            new_user.is_approved = True
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Account created successfully!', 'success')
        if role in ['retailer', 'school_admin']:
            flash('Your account is pending approval', 'info')
        
        return redirect(url_for('login'))
    
    all_display_roles = ['parent', 'retailer', 'student', 'donor','delivery']
    enabled_roles = ['parent', 'retailer']
    return render_template('register.html', 
                     all_roles=all_display_roles, 
                     allowed_roles=enabled_roles)

@app.route('/admin/approvals')
@role_required(['app_admin'])
def approvals():
    pending_retailers = User.query.filter_by(role='retailer', is_approved=False).all()
    pending_schools = School.query.filter_by(is_approved=False).all()
    return render_template('admin/approvals.html',
                         pending_retailers=pending_retailers,
                         pending_schools=pending_schools)

@app.route('/admin/approve-user/<int:user_id>')
@role_required(['app_admin'])
def approve_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.role == 'retailer':
        user.is_approved = True
        # Create a retailer profile if it doesn't exist
        if not user.get_retailer():
            retailer = Retailer(user_id=user.id, business_name=f"{user.username}'s Business")
            db.session.add(retailer)
        db.session.commit()
        flash('Retailer account approved.', 'success')
    else:
        flash('This user role is not approved from this action.', 'warning')
    return redirect(url_for('approvals'))

@app.route('/school/approve-retailers')
@role_required(['school_admin'])
def approve_retailers():
    school = School.query.filter_by(id=session.get('school_id')).first()
    if not school:
        flash('School not found', 'error')
        return redirect(url_for('dashboard'))
    
    # Get retailers approved by admin but not yet by this school
    retailers = Retailer.query.filter_by(is_approved_by_admin=True)\
                             .filter(~Retailer.approved_schools.any(id=school.id))\
                             .all()
    return render_template('school/approve_retailers.html', retailers=retailers)

@app.route('/school/approve-retailer/<int:retailer_id>')
@role_required(['school_admin'])
def approve_retailer(retailer_id):
    retailer = Retailer.query.get_or_404(retailer_id)
    school = School.query.filter_by(id=session.get('school_id')).first()
    
    if not school:
        flash('School not found', 'error')
        return redirect(url_for('dashboard'))
    
    retailer.approved_schools.append(school)
    db.session.commit()
    
    flash('Retailer approved for your school', 'success')
    return redirect(url_for('approve_retailers'))

@app.route('/admin/user/<int:user_id>/reset-password', methods=['POST'])
@role_required(['app_admin'])
def admin_reset_password(user_id):
    user = User.query.get_or_404(user_id)
    new_password = request.form.get('new_password')
    
    if not new_password or len(new_password) < 8:
        flash('Password must be at least 8 characters long.', 'danger')
    else:
        user.set_password(new_password)
        db.session.commit()
        flash(f"Password for {user.username} has been reset successfully.", 'success')
        
    return redirect(url_for('admin_edit_user', user_id=user.id))

# ====================== ADMIN CATEGORY MANAGEMENT ======================
@app.route('/admin/categories', methods=['GET', 'POST'])
@role_required(['app_admin'])
def manage_categories():
    if request.method == 'POST':
        name = request.form.get('name')
        if name and not ProductCategory.query.filter_by(name=name).first():
            new_cat = ProductCategory(name=name)
            db.session.add(new_cat)
            db.session.commit()
            flash('Category added.', 'success')
        else:
            flash('Category name is empty or already exists.', 'danger')
        return redirect(url_for('manage_categories'))
        
    categories = ProductCategory.query.all()
    return render_template('admin/manage_categories.html', categories=categories)

@app.route('/admin/category/delete/<int:cat_id>', methods=['POST'])
@role_required(['app_admin'])
def delete_category(cat_id):
    category = ProductCategory.query.get_or_404(cat_id)
    # Add check if products are using it before deleting
    if category.products:
        flash('Cannot delete category as it is currently in use by products.', 'danger')
    else:
        db.session.delete(category)
        db.session.commit()
        flash('Category deleted.', 'success')
    return redirect(url_for('manage_categories'))

# ====================== PARENT STUDENT MANAGEMENT ======================
@app.route('/parent/manage-students')
@role_required(['parent'])
def parent_manage_students():
    parent = User.query.get(session['user_id'])
    schools = School.query.filter_by(is_approved=True).all()
    return render_template('parent/manage_students.html', parent=parent, schools=schools)

@app.route('/parent/find-students', methods=['POST'])
@role_required(['parent'])
def parent_find_students():
    school_id = request.form.get('school_id')
    search_term = request.form.get('search_term')
    
    students = User.query.filter(
        User.school_id == school_id,
        User.role == 'student',
        User.username.ilike(f'%{search_term}%')
    ).all()

    return jsonify([{
        'id': student.id,
        'username': student.username
    } for student in students])

@app.route('/parent/bind-student/<int:student_id>', methods=['POST'])
@role_required(['parent'])
def parent_bind_student(student_id):
    parent = User.query.get(session['user_id'])
    student = User.query.get_or_404(student_id)
    
    if student in parent.children:
        flash('Student is already linked to your account.', 'warning')
    else:
        parent.children.append(student)
        db.session.commit()
        flash(f'Successfully linked to student "{student.username}".', 'success')
        
    return redirect(url_for('parent_manage_students'))

@app.route('/parent/unbind-student/<int:student_id>', methods=['POST'])
@role_required(['parent'])
def parent_unbind_student(student_id):
    parent = User.query.get(session['user_id'])
    student_to_unbind = parent.children.filter_by(id=student_id).first()
    
    if student_to_unbind:
        parent.children.remove(student_to_unbind)
        db.session.commit()
        flash(f'Successfully unlinked from student "{student_to_unbind.username}".', 'success')
    else:
        flash('Student not found in your linked accounts.', 'error')
        
    return redirect(url_for('parent_manage_students'))

# ====================== ADMIN MANAGEMENT ROUTES ======================
@app.route('/admin/users')
@role_required(['app_admin'])
def admin_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/retailers')
@role_required(['app_admin'])
def admin_retailers():
    retailers = Retailer.query.order_by(Retailer.is_approved_by_admin).all()
    return render_template('admin/retailers.html', retailers=retailers)

@app.route('/admin/approve-retailer/<int:retailer_id>')
@role_required(['app_admin'])
def admin_approve_retailer(retailer_id):
    retailer = Retailer.query.get_or_404(retailer_id)
    retailer.is_approved_by_admin = True
    db.session.commit()
    
    # Notify retailer's user account
    user = User.query.get(retailer.user_id)
    # user.add_notification(
    #     "Retailer Approved",
    #     "Your retailer account has been approved by admin",
    #     "admin"
    # )
    
    flash('Retailer approved successfully', 'success')
    return redirect(url_for('admin_retailers'))

@app.route('/admin/config', methods=['GET', 'POST'])
@role_required(['app_admin'])
def admin_config():
    if request.method == 'POST':
        # Update system configurations here
        flash('Settings updated successfully', 'success')
        return redirect(url_for('admin_config'))
    
    return render_template('admin/config.html')


@app.route('/admin/schools')
@role_required(['app_admin'])
def admin_schools():
    schools = School.query.order_by(School.is_approved).all()
    return render_template('admin/schools.html', schools=schools)

@app.route('/admin/approve-school/<int:school_id>')
@role_required(['app_admin'])
def admin_approve_school(school_id):
    school = School.query.get_or_404(school_id)
    school.is_approved = True
    
    # Activate the school admin account
    admin_user = User.query.filter_by(school_id=school.id, role='school_admin').first()
    if admin_user:
        admin_user.is_approved = True
        # admin_user.add_notification(
        #     "School Approved",
        #     f"Your school '{school.name}' has been approved",
        #     "admin"
        # )
    
    db.session.commit()
    flash(f'School "{school.name}" approved successfully', 'success')
    return redirect(url_for('approvals'))

@app.route('/admin/edit-user/<int:user_id>', methods=['GET', 'POST'])
@role_required(['app_admin'])
def admin_edit_user(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        user.role = request.form.get('role', user.role)
        user.is_approved = request.form.get('is_approved') == 'true'
        db.session.commit()
        
        flash('User updated successfully', 'success')
        return redirect(url_for('admin_users'))
    
    return render_template('admin/edit_user.html', user=user)

@app.route('/admin/system-logs')
@role_required(['app_admin'])
def admin_logs():
    # In a production app, you'd connect to actual system logs
    # This is a simplified version showing recent activities
    recent_activities = {
        'users': User.query.order_by(User.created_at.desc()).limit(5).all(),
        'orders': Order.query.order_by(Order.created_at.desc()).limit(5).all(),
        'donations': Donation.query.order_by(Donation.created_at.desc()).limit(5).all()
    }
    return render_template('admin/logs.html', activities=recent_activities)

      
@app.route('/admin/reports')
@role_required(['app_admin'])
def admin_reports():
    schools = School.query.count()
    active_orders = Order.query.filter(Order.status.in_(['paid', 'shipped'])).count()
    recent_donations = Donation.query.order_by(Donation.created_at.desc()).limit(5).all()
    # FIX THE COUNTER HERE
    approved_retailers_count = Retailer.query.filter_by(is_approved_by_admin=True).count()
    
    return render_template('admin/reports.html',
                         schools=schools,
                         active_orders=active_orders,
                         recent_donations=recent_donations,
                         approved_retailers_count=approved_retailers_count) # Pass the correct variable

@app.route('/admin/user/<int:user_id>/set-status/<status>')
@role_required(['app_admin'])
def set_user_status(user_id, status):
    user = User.query.get_or_404(user_id)
    if status == 'approve':
        user.is_approved = True
        flash(f'User {user.username} has been approved.', 'success')
    elif status == 'deny':
        user.is_approved = False
        flash(f'User {user.username} has been denied.', 'warning')
    db.session.commit()
    return redirect(url_for('admin_users'))

@app.route('/school-admin/order/<int:order_id>', methods=['GET', 'POST'])
@login_required
@role_required(['school_admin'])
def school_admin_confirm_delivery(order_id):
    order = Order.query.filter_by(id=order_id, school_id=current_user.school_id).first_or_404()

    if request.method == 'POST':
        for item in order.items:
            # Check if the "delivered" checkbox for this item was sent in the form
            if f'delivered_{item.id}' in request.form:
                item.status = 'Delivered'
        
        # Update overall order status
        if all(item.status == 'Delivered' for item in order.items):
            order.status = 'Delivered'
        
        db.session.commit()
        flash('Delivery status updated successfully.', 'success')
        return redirect(url_for('school_admin_confirm_delivery', order_id=order.id))

    return render_template('school_admin/confirm_delivery.html', order=order)

# ====================== STUDENT MANAGEMENT (SCHOOL ADMIN) ======================
@app.route('/school/students')
@role_required(['school_admin'])
def manage_students():
    # Ensure school_admin is valid
    school_admin = User.query.get(session['user_id'])
    if not school_admin.school_id:
        flash('You are not associated with a school.', 'error')
        return redirect(url_for('dashboard'))
        
    students = User.query.filter_by(role='student', school_id=school_admin.school_id).all()
    return render_template('school/manage_students.html', students=students)

@app.route('/school/student/add', methods=['GET', 'POST'])
@role_required(['school_admin'])
def add_student():
    school_admin = User.query.get(session['user_id'])
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email') # Optional, can be blank

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return redirect(url_for('add_student'))

        # Create the new student
        new_student = User(
            username=username,
            email=email or None,
            role='student',
            school_id=school_admin.school_id,
            is_approved=True # Students are auto-approved
        )
        new_student.set_password('changeme123') # Set a default password
        db.session.add(new_student)
        db.session.commit()
        
        flash(f'Student "{username}" added successfully. Default password is "changeme123".', 'success')
        return redirect(url_for('manage_students'))
        
    return render_template('school/add_student.html')

@app.route('/school/student/delete/<int:student_id>', methods=['POST'])
@role_required(['school_admin'])
def delete_student(student_id):
    school_admin = User.query.get(session['user_id'])
    student_to_delete = User.query.get_or_404(student_id)

    # Security check: ensure student belongs to the admin's school
    if student_to_delete.school_id != school_admin.school_id:
        flash('You do not have permission to delete this student.', 'error')
        return redirect(url_for('manage_students'))

    # Unbind any parents before deleting
    for parent in student_to_delete.parents:
        parent.children.remove(student_to_delete)
        
    db.session.delete(student_to_delete)
    db.session.commit()
    flash('Student deleted successfully.', 'success')
    return redirect(url_for('manage_students'))

@app.route('/school/students/upload-csv', methods=['POST'])
@role_required(['school_admin'])
def upload_students_csv():
    if 'file' not in request.files:
        flash('No file part', 'error')
        return redirect(url_for('manage_students'))
    
    file = request.files['file']
    if file.filename == '' or not file.filename.endswith('.csv'):
        flash('No selected file or file is not a CSV.', 'error')
        return redirect(url_for('manage_students'))

    school_admin = User.query.get(session['user_id'])
    school = school_admin.school
    
    try:
        # Read CSV in-memory
        stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
        csv_reader = csv.reader(stream)
        
        # Skip header row
        next(csv_reader, None)
        
        added_count = 0
        failed_rows = []

        for i, row in enumerate(csv_reader):
            if not row or not row[0]: # Check if row or name is empty
                failed_rows.append(f"Row {i+2}: Empty row")
                continue
                
            student_name = row[0].strip()
            
            # Create a unique username
            base_username = f"{school.name.split()[0].lower()}.{student_name.replace(' ', '').lower()}"
            username = base_username
            counter = 1
            while User.query.filter_by(username=username).first():
                username = f"{base_username}{counter}"
                counter += 1

            new_student = User(
                username=username,
                role='student',
                school_id=school.id,
                is_approved=True
            )
            new_student.set_password('changeme123')
            db.session.add(new_student)
            added_count += 1

        db.session.commit()
        
        flash(f'Successfully added {added_count} new students.', 'success')
        if failed_rows:
            flash(f'Failed to process {len(failed_rows)} rows: {", ".join(failed_rows)}', 'danger')

    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred during CSV processing: {e}', 'danger')
        
    return redirect(url_for('manage_students'))

@app.route('/school/order/<int:order_id>/confirm', methods=['GET', 'POST'])
@login_required
@role_required(['school_admin'])
def school_confirm_delivery(order_id):
    order = Order.query.filter_by(id=order_id, school_id=current_user.school_id).first_or_404()

    # Fetch ONLY the items that are awaiting confirmation
    items_to_confirm = [item for item in order.items if item.status == 'Shipped to School']

    if request.method == 'POST':
        items_updated = False
        for item in items_to_confirm:
            if f'delivered_{item.id}' in request.form:
                item.status = 'Delivered'
                items_updated = True
        
        # Check if ALL items in the original order are now delivered
        if all(item.status == 'Delivered' for item in order.items):
            order.status = 'Delivered'
        else:
            order.status = 'Partially Delivered'

        if items_updated:
            db.session.commit()
            flash('Delivery status updated.', 'success')
        
        return redirect(url_for('school_confirm_delivery', order_id=order.id))

    # Pass the filtered list to the template
    return render_template('school_admin/confirm_delivery.html', order=order, items_to_confirm=items_to_confirm)

# ====================== SCHOOL REQUIREMENTS ROUTES ======================
@app.route('/school/requirements')
@role_required(['school_admin'])
def manage_requirements():
    school = School.query.filter_by(id=session.get('school_id')).first()
    if not school:
        flash('School not found', 'error')
        return redirect(url_for('dashboard'))
    
    categories = ProductCategory.query.all()
    
    return render_template('school/requirements.html', requirements=school.requirements, categories=categories)

@app.route('/school/requirements/edit/<int:req_id>', methods=['GET', 'POST'])
@role_required(['school_admin'])
def edit_requirement(req_id):
    requirement = SchoolRequirement.query.get_or_404(req_id)
    if requirement.school_id != current_user.school_id:
        flash('You do not have permission to edit this item.', 'error')
        return redirect(url_for('manage_requirements'))

    if request.method == 'POST':
        requirement.item_name = request.form.get('item_name')
        requirement.item_description = request.form.get('description')
        requirement.quantity_required = request.form.get('quantity')
        requirement.is_allowed = request.form.get('is_allowed') == 'on' # Checkbox logic
        requirement.category = request.form.get('category')
        db.session.commit()
        flash('Requirement updated successfully!', 'success')
        return redirect(url_for('manage_requirements'))

    return render_template('school/edit_requirement.html', requirement=requirement)

@app.route('/school/requirements/add', methods=['POST'])
@role_required(['school_admin'])
def add_requirement():
    school = School.query.filter_by(id=session.get('school_id')).first()
    if not school:
        return jsonify({'error': 'School not found'}), 404
    
    item_name = request.form.get('item_name')
    description = request.form.get('description')
    quantity = request.form.get('quantity')
    is_allowed = request.form.get('is_allowed', 'true') == 'true'
    category = request.form.get('category')
    
    requirement = SchoolRequirement(
        school_id=school.id,
        item_name=item_name,
        item_description=description,
        quantity_required=quantity,
        is_allowed=is_allowed,
        category=category
    )
    
    db.session.add(requirement)
    db.session.commit()
    
    flash('Requirement added successfully', 'success')
    return redirect(url_for('manage_requirements'))

@app.route('/school/requirements/delete/<int:req_id>')
@role_required(['school_admin'])
def delete_requirement(req_id):
    requirement = SchoolRequirement.query.get_or_404(req_id)
    if requirement.school_id != session.get('school_id'):
        flash('You cannot delete this requirement', 'error')
        return redirect(url_for('manage_requirements'))
    
    db.session.delete(requirement)
    db.session.commit()
    
    flash('Requirement deleted successfully', 'success')
    return redirect(url_for('manage_requirements'))

# ====================== SHOPPING & RETAIL ROUTES ======================

# @app.route('/shop/select-student', methods=['GET', 'POST'])
# @login_required
# @role_required(['parent'])
# def select_student_for_shopping():
#     parent = User.query.get(session['user_id'])
#     if not parent.children.first():
#         flash('You must link to a student before you can shop.', 'warning')
#         return redirect(url_for('parent_manage_students'))
        
#     if request.method == 'POST':
#         student_id = request.form.get('student_id')
#         student = parent.children.filter_by(id=student_id).first()
#         if student:
#             session['shopping_for_student_id'] = student.id
#             flash(f'You are now shopping for {student.username}.', 'info')
#             return redirect(url_for('shop'))
#         else:
#             flash('Invalid student selected.', 'error')

#     return render_template('shop/select_student.html', children=parent.children.all())
@app.route('/shop/select-student', methods=['GET', 'POST'])
@login_required
@role_required(['parent'])
def select_student():
    # If the user is already shopping for someone, redirect them to the cart
    # where they can choose to clear the session.
    if 'shopping_for_student_id' in session:
        flash('You are already in a shopping session. Clear your cart to start a new one.', 'warning')
        return redirect(url_for('cart'))

    # Get the parent object
    parent = db.session.get(User, session['user_id'])
    
    # --- THIS IS THE FIX ---
    # Fetch ONLY the students directly linked to this parent
    linked_students = parent.children.all()

    if request.method == 'POST':
        student_id = request.form.get('student_id')
        if student_id:
            session['shopping_for_student_id'] = student_id
            student = User.query.get(student_id)
            session['shopping_for_student_id'] = student.id
            session['shopping_for_student_username'] = student.username 
                       
            flash(f'You are now shopping for {student.username}.', 'success')
            return redirect(url_for('shop'))
    
    # Pass the correct list of linked students to the template
    return render_template('shop/select_student.html', students=linked_students)

@app.route('/cart/update', methods=['POST'])
@login_required
@role_required(['parent', 'student'])
def update_cart():
    """Updates quantities or removes items from the cart based on form submission."""
    cart = Cart.query.filter_by(user_id=session['user_id']).first()
    if not cart:
        return redirect(url_for('shop'))

    # Loop through all the form data submitted
    for key, value in request.form.items():
        if key.startswith('quantity_'):
            try:
                # Get the item ID and the new quantity
                item_id = int(key.split('_')[1])
                new_quantity = int(value)

                # Find the specific cart item
                item = CartItem.query.filter_by(id=item_id, cart_id=cart.id).first()

                if item:
                    if new_quantity <= 0:
                        # If quantity is 0 or less, remove the item
                        db.session.delete(item)
                    else:
                        # Otherwise, update the quantity
                        item.quantity = new_quantity
            except (ValueError, IndexError):
                # Ignore malformed form data
                continue
    
    db.session.commit()
    flash('Your cart has been updated.', 'success')
    return redirect(url_for('cart'))

# @app.route('/shop')
# @login_required
# @role_required(['parent', 'student'])
# def shop():
    
#     if 'shopping_for_student_id' not in session:
#         flash('Please select which student you are shopping for.', 'info')
#         return redirect(url_for('select_student'))
    
#     user = User.query.get(session['user_id'])
#     school_id = None
#     shopping_for_student = None

#     if user.role == 'parent':
#         student_id = session.get('shopping_for_student_id')
#         if not student_id: return redirect(url_for('select_student'))
#         student = user.children.filter_by(id=student_id).first()
#         if not student:
#             flash('Selected student not found.', 'error')
#             session.pop('shopping_for_student_id', None)
#             return redirect(url_for('select_student'))
#         school_id = student.school_id
#         shopping_for_student = student
#     else: # user is a student
#         school_id = user.school_id
#         shopping_for_student = user

#     if not school_id:
#         flash('Could not determine a school to shop for.', 'error')
#         return redirect(url_for('dashboard'))

#     # Get filter criteria from URL arguments
#     search_query = request.args.get('search_query', '')
#     category_id = request.args.get('category_id', type=int)
#     min_price = request.args.get('min_price', type=float)
#     max_price = request.args.get('max_price', type=float)
#     sort_by = request.args.get('sort_by', 'name')

#     # Base query for approved products for the student's school
#     base_query = Product.query.join(Retailer).filter(
#         Retailer.approved_schools.any(id=school_id),
#         Product.quantity > 0
#     )

#     # Apply filters
#     if search_query:
#         base_query = base_query.filter(Product.name.ilike(f'%{search_query}%'))
#     if category_id:
#         base_query = base_query.filter(Product.category_id == category_id)
#     if min_price:
#         base_query = base_query.filter(Product.price >= min_price)
#     if max_price:
#         base_query = base_query.filter(Product.price <= max_price)

#     # Apply sorting
#     if sort_by == 'price_asc':
#         base_query = base_query.order_by(Product.price.asc())
#     elif sort_by == 'price_desc':
#         base_query = base_query.order_by(Product.price.desc())
#     else: # Default sort by name
#         base_query = base_query.order_by(Product.name.asc())
        
#     products = Product.query.join(Retailer)\
#                    .filter(Retailer.approved_schools.any(id=user.school_id))\
#                    .filter(Product.quantity > 0)\
#                    .all()

#     # Get school requirements and create a set of allowed item names for fast lookup
#     requirements = SchoolRequirement.query.filter_by(school_id=user.school_id).all()
#     # This includes both allowed items and items not explicitly restricted
#     allowed_item_names = {r.item_name.lower() for r in requirements if r.is_allowed}
#     all_required_items = {r.item_name.lower() for r in requirements}

#     # This logic determines if an item is truly "not allowed"
#     for product in products:
#         product.is_allowed = True # Default to allowed
#         product_name_lower = product.name.lower()
        
#         # If the item is on the requirement list, check its 'is_allowed' flag
#         if product_name_lower in all_required_items:
#             if product_name_lower not in allowed_item_names:
#                 product.is_allowed = False
#         else:
#             # If the item is NOT on the requirement list at all, it's not allowed
#             product.is_allowed = False
    
#     student = User.query.get(session['shopping_for_student_id'])
#     return render_template('shop/index.html', products=products, requirements=requirements, student=student)
#---------------------

@app.route('/shop')
@login_required
@role_required(['parent', 'student'])
def shop():
    user = db.session.get(User, session['user_id'])
    student = None
    school_id = None

    if user.role == 'parent':
        student_id = session.get('shopping_for_student_id')
        if not student_id:
            flash('Please select which student you are shopping for.', 'info')
            return redirect(url_for('select_student'))
        
        student = next((child for child in user.children if child.id == int(student_id)), None)

        if not student:
            flash('Selected student not found or not linked to your account.', 'error')
            session.pop('shopping_for_student_id', None)
            session.pop('shopping_for_student_username', None)
            return redirect(url_for('select_student'))
        school_id = student.school_id
    else: # The user is a student
        student = user
        school_id = user.school_id

    if not school_id:
        flash('Could not determine a school. Please ensure the student is enrolled.', 'error')
        return redirect(url_for('dashboard'))

    # --- THIS IS THE CORRECTED FILTERING LOGIC ---

    # 1. Get all filter criteria from URL arguments, using 'type' for numbers
    search_query = request.args.get('search_query', '')
    category_id = request.args.get('category_id', type=int)
    min_price = request.args.get('min_price', type=float)
    max_price = request.args.get('max_price', type=float)

    # 2. Build the base query
    products_query = Product.query.join(Retailer).filter(
        Retailer.approved_schools.any(id=school_id),
        Product.quantity > 0
    )

    # 3. Apply ALL filters conditionally
    if search_query:
        products_query = products_query.filter(Product.name.ilike(f'%{search_query}%'))
    
    # THIS IS THE FIX FOR CATEGORY: Check if category_id is a valid number
    if category_id:
        products_query = products_query.filter(Product.category_id == category_id)
    
    # THIS IS THE FIX FOR MIN PRICE: Check if min_price is a valid number
    if min_price is not None:
        products_query = products_query.filter(Product.price >= min_price)
    
    # THIS IS THE FIX FOR MAX PRICE: Check if max_price is a valid number
    if max_price is not None:
        products_query = products_query.filter(Product.price <= max_price)
    
    # Execute the final query
    products = products_query.order_by(Product.name.asc()).all()

    # ... (Your existing compliance logic remains the same here) ...
    requirements = SchoolRequirement.query.filter_by(school_id=school_id).all()
    allowed_item_names = {r.item_name.lower() for r in requirements if r.is_allowed}
    is_req_list_enforced = bool(requirements)

    for product in products:
        if is_req_list_enforced:
            product.is_allowed = product.name.lower() in allowed_item_names
        else:
            product.is_allowed = True

    # Fetch all categories to populate the dropdown
    categories = ProductCategory.query.order_by('name').all() # Assuming you have a Category model

    return render_template(
        'shop/index.html', 
        products=products, 
        student=student,
        categories=categories,
        # Pass all filter values back to the template
        search_query=search_query,
        category_id=category_id,
        min_price=min_price,
        max_price=max_price
    )

# @app.route('/cart', methods=['GET', 'POST'])
# @login_required
# @role_required(['parent', 'student'])
# def cart():
#     user = User.query.get(session['user_id'])
#     cart = Cart.query.filter_by(user_id=user.id).first()
    
#     if not cart:
#         cart = Cart(user_id=user.id)
#         db.session.add(cart)
#         db.session.commit()
    
#     if request.method == 'POST':
#         product_id = request.form.get('product_id')
#         quantity = int(request.form.get('quantity', 1))
        
#         product = Product.query.get(product_id)
#         if not product or product.quantity < quantity:
#             # For AJAX requests, return a JSON error
#             if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
#                 return jsonify({'success': False, 'message': 'Product not found or not enough stock.'}), 400
#             flash('Product not found or not enough stock.', 'error')
#             return redirect(url_for('shop'))
        
#         # Check if product already in cart
#         cart_item = CartItem.query.filter_by(cart_id=cart.id, product_id=product.id).first()
#         if cart_item:
#             cart_item.quantity += quantity
#         else:
#             cart_item = CartItem(cart_id=cart.id, product_id=product.id, quantity=quantity)
#             db.session.add(cart_item)
        
#         db.session.commit()
#     # For AJAX requests, return a JSON success message
#     if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
#         return jsonify({
#             'success': True, 
#             'message': f'{product.name} added to cart.',
#             'cart_item_count': len(cart.items) # Send back the new total item count
#         })

#     flash('Product added to cart', 'success')
#     return redirect(url_for('cart'))
    
#     # return render_template('shop/cart.html', cart=cart)
#-----------------------------------------------------------------------------
# @app.route('/cart') # Note: We've removed methods=['GET', 'POST']
# @login_required
# @role_required(['parent', 'student'])
# def cart():
#     user = User.query.get(session['user_id'])
#     # Find the user's cart. If it doesn't exist, create it.
#     # This logic is safe and correct.
#     user_cart = Cart.query.filter_by(user_id=user.id).first()
#     if not user_cart:
#         user_cart = Cart(user_id=user.id)
#         db.session.add(user_cart)
#         db.session.commit()
        
#     total_price = sum(item.product.price * item.quantity for item in cart.items) if cart else 0
#     # The ONLY job of this route is to render the template.
#     return render_template('shop/cart.html', cart=cart, total_price=total_price)

@app.route('/cart', methods=['GET', 'POST'])
@login_required
@role_required(['parent', 'student'])
def cart():
    user = db.session.get(User, session['user_id'])

    # Handle POST request for adding items to the cart first
    if request.method == 'POST':
        product_id = request.form.get('product_id')
        quantity = int(request.form.get('quantity', 1))
        
        product = Product.query.get(product_id)
        if not product:
            flash('Product not found', 'error')
            return redirect(url_for('shop'))
        
        # Find or create the cart
        user_cart = Cart.query.filter_by(user_id=user.id).first()
        if not user_cart:
            user_cart = Cart(user_id=user.id)
            db.session.add(user_cart)
        
        # Check if product already in cart and update/add
        cart_item = CartItem.query.filter_by(cart_id=user_cart.id, product_id=product.id).first()
        if cart_item:
            cart_item.quantity += quantity
        else:
            cart_item = CartItem(cart_id=user_cart.id, product_id=product.id, quantity=quantity)
            db.session.add(cart_item)
        
        db.session.commit()
        flash('Product added to cart', 'success')
        return redirect(url_for('cart'))

    # Handle GET request to view the cart
    user_cart = Cart.query.filter_by(user_id=user.id).first()

    # Safely calculate total price. If cart is None or has no items, total is 0.
    total_price = 0
    if user_cart and user_cart.items:
        total_price = sum(item.product.price * item.quantity for item in user_cart.items)

    # Pass the user_cart object to the template using the name 'cart'
    return render_template('shop/cart.html', cart=user_cart, total_price=total_price)

@app.route('/cart/remove/<int:item_id>')
@login_required
@role_required(['parent', 'student'])
def remove_from_cart(item_id):
    cart_item = CartItem.query.get_or_404(item_id)
    if cart_item.cart.user_id != session['user_id']:
        flash('You cannot remove this item', 'error')
        return redirect(url_for('cart'))
    
    db.session.delete(cart_item)
    db.session.commit()
    flash('Item removed from cart', 'success')
    return redirect(url_for('cart'))

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
@role_required(['parent', 'student'])
def checkout():
    
    if 'shopping_for_student_id' not in session:
        flash('Your shopping session has expired. Please select a student again.', 'error')
        return redirect(url_for('select_student'))
    student_id = session['shopping_for_student_id']        
    user = User.query.get(session['user_id'])
    cart = Cart.query.filter_by(user_id=user.id).first()
    
    if user.role == 'student':
        student_id = user.id

    if not student_id:
        flash('Your shopping session has expired. Please select a student again.', 'error')
        return redirect(url_for('select_student'))
    
    linked_students = User.query.filter_by(school_id=user.school_id, role='student').all()
    
    school_id = None
        # Determine the school based on the user's role and session
    if user.role == 'parent':
        student_id = session.get('shopping_for_student_id')
        if not student_id:
            flash("Your shopping session has expired. Please select a student.", "error")
            return redirect(url_for('select_student_for_shopping'))
        
        # Query the student from the database to get their school_id
        student = User.query.get(student_id)
        if student:
            school_id = student.school_id
    else: # The user is a student
        school_id = user.school_id

    # If school_id is STILL None, something is wrong. Bail out.
    if not school_id:
        flash("Error: Could not determine a school for this order.", "error")
        return redirect(url_for('dashboard'))
    
    if not cart or not cart.items:
        flash('Your cart is empty', 'error')
        return redirect(url_for('shop'))

    # Check compliance with school requirements
    non_compliant_items = check_compliance(cart.items, user.school_id)
    if non_compliant_items:
        flash('Some items in your cart do not comply with school requirements', 'error')
        return render_template('shop/checkout.html', cart=cart, non_compliant_items=non_compliant_items)

    if request.method == 'POST':       
        total = sum(item.product.price * item.quantity for item in cart.items)

        # Create order in pending state to generate ID
        order = Order(
            user_id=user.id,
            student_id=student_id,
            school_id=school_id,
            total_amount=total,
            status='pending'
        )
        db.session.add(order)
        db.session.flush()  # Order ID is now available

        try:
            wallet = user.get_or_create_wallet()
            donation_amount = float(request.form.get('donation_amount', 0))
            wallet_amount = total - donation_amount

            if donation_amount > 0:
                available_donations = DonationDistribution.query \
                    .filter_by(recipient_id=user.id) \
                    .filter(Donation.donation_type == 'monetary') \
                    .filter(Donation.status == 'approved') \
                    .join(Donation) \
                    .all()

                total_available = sum(d.amount for d in available_donations)
                if donation_amount > total_available:
                    raise Exception("Not enough donated funds available")

                remaining = donation_amount
                for donation in available_donations:
                    if remaining <= 0:
                        break

                    use_amount = min(donation.amount, remaining)
                    donation.amount -= use_amount
                    remaining -= use_amount

                    order_donation = DonationDistribution(
                        donation_id=donation.donation_id,
                        recipient_id=user.id,
                        amount=-use_amount,
                        order_id=order.id
                    )
                    db.session.add(order_donation)

            if wallet_amount > 0:
                if not wallet or wallet.balance < wallet_amount:
                    raise Exception("Insufficient wallet balance")

                wallet.balance -= wallet_amount
                transaction = WalletTransaction(
                    wallet_id=wallet.id,
                    amount=-wallet_amount,
                    transaction_type='payment',
                    reference=f'ORDER_{order.id}'
                )
                db.session.add(transaction)

            order.status = 'paid'
            
            order.payment_method = 'donation' if wallet_amount <= 0 else 'wallet' if donation_amount <= 0 else 'mixed'
            order.donation_used = donation_amount

            for cart_item in cart.items:
                order_item = OrderItem(
                    order_id=order.id,
                    product_id=cart_item.product.id,
                    quantity=cart_item.quantity,
                    price=cart_item.product.price
                )
                db.session.add(order_item)
                cart_item.product.quantity -= cart_item.quantity

            CartItem.query.filter_by(cart_id=cart.id).delete()


            db.session.commit()
            session.pop('shopping_for_student_id', None)
            session.pop('shopping_for_student_username', None)
                        
            flash('Order placed successfully!', 'success')
            return redirect(url_for('order_detail', order_id=order.id))

        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred during checkout. Your order was not placed. Error: {str(e)}', 'error')
            return redirect(url_for('cart'))
    
    total = sum(item.product.price * item.quantity for item in cart.items)
    return render_template('shop/checkout.html', cart=cart, total=total)

@app.route('/cart/clear')
@login_required
@role_required(['parent', 'student'])
def clear_cart():
    """Clears all items from the current user's shopping cart."""
    cart = Cart.query.filter_by(user_id=session['user_id']).first()
    
    if cart:
        # Efficiently delete all items associated with this cart
        CartItem.query.filter_by(cart_id=cart.id).delete()
        db.session.commit()
        
        session.pop('shopping_for_student_id', None)
        session.pop('shopping_for_student_username', None)
        flash('Your shopping cart has been cleared. You can now start a new session.', 'success')
    else:
        flash('Your cart was already empty.', 'info')
        
    # Redirect back to the main shop page to start fresh
    return redirect(url_for('select_student'))
      
@app.route('/api/add-to-cart', methods=['POST'])
@login_required
@role_required(['parent', 'student'])
def api_add_to_cart():
    data = request.get_json()
    product_id = data.get('productId')
    quantity = int(data.get('quantity', 1))

    if not product_id:
        return jsonify({'success': False, 'message': 'Product ID is missing.'}), 400

    try:
        user = User.query.get(session['user_id'])
        product = Product.query.get(product_id)

        if not product or product.quantity < quantity:
            return jsonify({'success': False, 'message': 'Product not available or not enough stock.'}), 404

        cart = Cart.query.filter_by(user_id=user.id).first()
        if not cart:
            cart = Cart(user_id=user.id)
            db.session.add(cart)

        cart_item = CartItem.query.filter_by(cart_id=cart.id, product_id=product.id).first()
        if cart_item:
            cart_item.quantity += quantity
        else:
            cart_item = CartItem(cart_id=cart.id, product_id=product.id, quantity=quantity)
            db.session.add(cart_item)

        db.session.commit()
        
        # Calculate total number of unique items in cart
        cart_item_count = len(cart.items)

        return jsonify({
            'success': True, 
            'message': f'Added {quantity} x {product.name} to cart.',
            'cartItemCount': cart_item_count
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/retailer/order/<int:order_id>', methods=['GET', 'POST'])
@login_required
@role_required(['retailer'])
def retailer_manage_order(order_id):
    # Ensure the order contains items from this retailer
    current_user = db.session.get(User, session['user_id'])
    order_items = OrderItem.query.join(Product).filter(
        OrderItem.order_id == order_id,
        Product.retailer_id == current_user.get_retailer().id
    ).all()

    if not order_items:
        flash('Order not found or you do not have permission to view it.', 'error')
        return redirect(url_for('retailer_orders'))

    order = Order.query.get_or_404(order_id)

    if request.method == 'POST':
        for item in order_items:
            new_status = request.form.get(f'status_{item.id}')
            if new_status and item.status != new_status:
                item.status = new_status
        
        # Optional: Update the overall order status based on item statuses
        all_statuses = {item.status for item in order.items}
        if len(all_statuses) == 1:
            order.status = all_statuses.pop()
        elif 'Shipped to School' in all_statuses:
            order.status = 'Partially Shipped'
        elif 'Processing' in all_statuses:
            order.status = 'Processing'

        db.session.commit()
        flash(f'Order #{order.id} has been updated.', 'success')
        return redirect(url_for('retailer_manage_order', order_id=order.id))

    return render_template('retailer/manage_order.html', order=order, items=order_items)
    
# ====================== SAVINGS WALLET ROUTES ======================
@app.route('/wallet')
@login_required
def wallet():
    user = User.query.get(session['user_id'])
    wallet = Wallet.query.filter_by(user_id=user.id).first()
    
    if not wallet:
        wallet = Wallet(user_id=user.id, balance=0.0)
        db.session.add(wallet)
        db.session.commit()
    
    transactions = WalletTransaction.query.filter_by(wallet_id=wallet.id)\
                                        .order_by(WalletTransaction.created_at.desc())\
                                        .all()
    
    return render_template('wallet/index.html', wallet=wallet, transactions=transactions)

@app.route('/wallet/deposit', methods=['GET', 'POST'])
@login_required
def wallet_deposit():
    if request.method == 'POST':
        amount = float(request.form.get('amount'))
        if amount <= 0:
            flash('Amount must be positive', 'error')
            return redirect(url_for('wallet_deposit'))
        
        user = User.query.get(session['user_id'])
        wallet = Wallet.query.filter_by(user_id=user.id).first()
        
        if not wallet:
            wallet = Wallet(user_id=user.id, balance=0.0)
            db.session.add(wallet)
        
        wallet.balance += amount
        transaction = WalletTransaction(
            wallet_id=wallet.id,
            amount=amount,
            transaction_type='deposit',
            reference='MANUAL_DEPOSIT'
        )
        db.session.add(transaction)
        db.session.commit()
        
        flash(f'Successfully deposited Kes{amount:.2f}', 'success')
        return redirect(url_for('wallet'))
    
    return render_template('wallet/deposit.html')

@app.route('/orders/<int:order_id>')
@login_required
def order_detail(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != session['user_id'] and session['role'] not in ['app_admin', 'school_admin']:
        flash('You cannot view this order', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('shop/order_detail.html', order=order)

# ====================== DONATIONS ROUTES ======================
@app.route('/donate', methods=['GET', 'POST'])
@login_required
@role_required(['donor'])
def donate():
    if request.method == 'POST':
        donation_type = request.form.get('donation_type')
        amount = float(request.form.get('amount', 0))
        description = request.form.get('description')
        
        donation = Donation(
            donor_id=session['user_id'],
            donation_type=donation_type,
            amount=amount if donation_type == 'monetary' else None,
            description=description,
            status='pending'
        )
        
        db.session.add(donation)
        db.session.commit()
        
        flash('Donation submitted successfully!', 'success')
        return redirect(url_for('donation_status', donation_id=donation.id))
    
    return render_template('donations/donate.html')

@app.route('/donations/<int:donation_id>')
@login_required
def donation_status(donation_id):
    donation = Donation.query.get_or_404(donation_id)
    if donation.donor_id != session['user_id'] and session['role'] != 'app_admin':
        flash('You cannot view this donation', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('donations/status.html', donation=donation)

@app.route('/my-donations')
@login_required
@role_required(['donor'])
def my_donations():
    donations = Donation.query.filter_by(donor_id=session['user_id'])\
                              .order_by(Donation.created_at.desc()).all()
    return render_template('donations/my_donations.html', donations=donations)

@app.route('/admin/donations')
@role_required(['app_admin', 'school_admin'])
def manage_donations():
    if session['role'] == 'school_admin':
        # School admins only see donations for their school
        user = User.query.get(session['user_id'])
        donations = Donation.query.join(DonationDistribution)\
                                .join(User, DonationDistribution.recipient_id == User.id)\
                                .filter(User.school_id == user.school_id)\
                                .distinct()\
                                .all()
    else:
        # App admins see all donations
        donations = Donation.query.all()

    return render_template('admin/donations.html', donations=donations)

@app.route('/admin/donations/approve/<int:donation_id>')
@role_required(['app_admin'])
def approve_donation(donation_id):
    donation = Donation.query.get_or_404(donation_id)
    donation.status = 'approved'
    db.session.commit()
    
    flash('Donation approved', 'success')
    return redirect(url_for('manage_donations'))

@app.route('/admin/donations/distribute/<int:donation_id>', methods=['GET', 'POST'])
@role_required(['app_admin', 'school_admin'])
def distribute_donation(donation_id):
    donation = Donation.query.get_or_404(donation_id)
    
    if request.method == 'POST':
        recipient_id = request.form.get('recipient_id')
        amount = float(request.form.get('amount', 0))
        item_id = request.form.get('item_id')
        
        distribution = DonationDistribution(
            donation_id=donation.id,
            recipient_id=recipient_id,
            amount=amount,
            item_id=item_id
        )
        
        # If monetary donation, add to recipient's wallet
        if donation.donation_type == 'monetary':
            recipient = User.query.get(recipient_id)
            wallet = recipient.wallet
            wallet.balance += amount
            
            # Create wallet transaction
            transaction = WalletTransaction(
                wallet_id=wallet.id,
                amount=amount,
                transaction_type='donation',
                reference=f'DONATION_{donation.id}'
            )
            db.session.add(transaction)
        
        db.session.add(distribution)
        db.session.commit()
        
        flash('Donation distributed successfully', 'success')
        return redirect(url_for('manage_donations'))
    
    # Get eligible recipients (students/parents in the same school for school admins)
    if session['role'] == 'school_admin':
        user = User.query.get(session['user_id'])
        recipients = User.query.filter_by(school_id=user.school_id)\
                              .filter(User.role.in_(['student', 'parent']))\
                              .all()
    else:
        recipients = User.query.filter(User.role.in_(['student', 'parent'])).all()
    
    return render_template('admin/distribute_donation.html', 
                         donation=donation, 
                         recipients=recipients)

# ====================== ORDER MANAGEMENT ROUTES ======================
@app.route('/orders')
@login_required
def order_list():
    if session['role'] in ['app_admin', 'school_admin']:
        if session['role'] == 'school_admin':
            user = User.query.get(session['user_id'])
            orders = Order.query.filter_by(school_id=user.school_id).all()
        else:
            orders = Order.query.all()
    else:
        orders = Order.query.filter_by(user_id=session['user_id']).all()
    
    return render_template('orders/list.html', orders=orders)

@app.route('/orders/<int:order_id>/update', methods=['POST'])
@role_required(['app_admin', 'school_admin'])
def update_order_status(order_id):
    order = Order.query.get_or_404(order_id)
    new_status = request.form.get('status')
    notes = request.form.get('notes')
    
    order.status = new_status
    tracking = OrderTracking(
        order_id=order.id,
        status=new_status,
        notes=notes
    )
    
    db.session.add(tracking)
    db.session.commit()
    
    flash('Order status updated', 'success')
    return redirect(url_for('order_detail', order_id=order.id))

@app.route('/order/<int:order_id>/tracking')
@login_required
def order_tracking(order_id):
    # Security check: ensure the user owns this order or is an admin
    current_user = db.session.get(User, session['user_id'])
    
    order = Order.query.get_or_404(order_id)
    
    if order.user_id != current_user.id and current_user.role not in ['app_admin', 'school_admin']:
        flash('You do not have permission to view this order.', 'error')
        return redirect(url_for('dashboard'))

    # Group items by their status
    grouped_items = {}
    for item in order.items:
        status = item.status
        if status not in grouped_items:
            grouped_items[status] = []
        grouped_items[status].append(item)
        
    return render_template('shop/order_tracking.html', order=order, grouped_items=grouped_items)

@app.route('/order_item/<int:item_id>/update_status', methods=['POST'])
@login_required
@role_required(['retailer', 'school_admin'])
def update_order_item_status(item_id):
    order_item = OrderItem.query.get_or_404(item_id)
    new_status = request.form.get('status')
    
    # Security Checks
    user = User.query.get(session['user_id'])
    if session['role'] == 'retailer':
        if order_item.product.retailer_id != user.get_retailer().id:
            flash('This item does not belong to your inventory.', 'error')
            return redirect(url_for('retailer_orders'))
    elif session['role'] == 'school_admin':
        if order_item.order.school_id != user.school_id:
            flash('This order is not for your school.', 'error')
            return redirect(url_for('dashboard'))
    
    # Update status and create tracking record
    order_item.status = new_status
    tracking = OrderTracking(
        order_id=order_item.order_id,
        order_item_id=order_item.id,
        status=new_status,
        notes=f"Status updated by {session['role']}: {user.username}"
    )
    db.session.add(tracking)
    db.session.commit()
    
    flash(f'Item status updated to "{new_status}".', 'success')
    # Redirect back to the appropriate management page
    if session['role'] == 'retailer':
        return redirect(url_for('retailer_orders'))
    else:
        # Potentially a school admin order view page
        return redirect(url_for('order_list'))

@app.route('/orders/<int:order_id>/apply-donation', methods=['POST'])
@login_required
@role_required(['parent', 'student'])
def apply_donation_to_order(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != session['user_id']:
        flash('You cannot modify this order', 'error')
        return redirect(url_for('dashboard'))
    
    donation_amount = float(request.form.get('donation_amount', 0))
    wallet_amount = order.total_amount - donation_amount
    
    if donation_amount > 0:
        # Check if user has available donations
        available_donations = DonationDistribution.query\
            .filter_by(recipient_id=session['user_id'])\
            .filter(Donation.donation_type == 'monetary')\
            .filter(Donation.status == 'approved')\
            .join(Donation)\
            .all()
        
        total_available = sum(d.amount for d in available_donations)
        
        if donation_amount > total_available:
            flash('Not enough donated funds available', 'error')
            return redirect(url_for('order_detail', order_id=order.id))
        
        # Apply donation to order
        order.donation_used = donation_amount
        order.payment_method = 'donation' if wallet_amount <= 0 else 'mixed'
        
        # Mark donations as used
        remaining = donation_amount
        for donation in available_donations:
            if remaining <= 0:
                break
            
            use_amount = min(donation.amount, remaining)
            donation.amount -= use_amount
            remaining -= use_amount
            
            # Create order-donation link
            order_donation = DonationDistribution(
                donation_id=donation.donation_id,
                recipient_id=session['user_id'],
                amount=-use_amount,
                order_id=order.id
            )
            db.session.add(order_donation)
    
    # Process wallet payment if needed
    if wallet_amount > 0:
        wallet = Wallet.query.filter_by(user_id=session['user_id']).first()
        if wallet.balance < wallet_amount:
            flash('Insufficient funds in wallet', 'error')
            return redirect(url_for('order_detail', order_id=order.id))
        
        wallet.balance -= wallet_amount
        transaction = WalletTransaction(
            wallet_id=wallet.id,
            amount=-wallet_amount,
            transaction_type='payment',
            reference=f'ORDER_{order.id}'
        )
        db.session.add(transaction)
        order.payment_method = 'wallet' if donation_amount <= 0 else 'mixed'
    
    order.status = 'paid'
    db.session.commit()
    
    flash('Payment processed successfully', 'success')
    return redirect(url_for('order_detail', order_id=order.id))

@app.route('/order/<int:order_id>/receipt')
@login_required
def order_receipt(order_id):
    order = Order.query.get_or_404(order_id)
    # Security check
    if order.user_id != session.get('user_id') and session.get('role') != 'app_admin':
        return redirect(url_for('dashboard'))
    return render_template('shop/receipt.html', order=order)


# ====================== RETAILER DASHBOARD ROUTES (New Section) ======================

@app.route('/retailer/orders')
@login_required
@role_required(['retailer'])
def retailer_orders():
    retailer = User.query.get(session['user_id']).get_retailer()
    
    # Fetch all order items linked to this retailer's products
    order_items = db.session.query(OrderItem).join(Product).filter(Product.retailer_id == retailer.id).order_by(OrderItem.id.desc()).all()
    
    # Group items by order for cleaner display
    orders_dict = {}
    for item in order_items:
        if item.order_id not in orders_dict:
            orders_dict[item.order_id] = {
                'order_info': item.order,
                'student_name': item.order.user.username,
                'school_name': item.order.school.name,
                'items': []
            }
        orders_dict[item.order_id]['items'].append(item)
        
    return render_template('retailer/orders.html', orders_dict=orders_dict)

@app.route('/retailer/products')
@login_required
@role_required(['retailer'])
def retailer_products():
    retailer = User.query.get(session['user_id']).get_retailer()
    products = Product.query.filter_by(retailer_id=retailer.id).all()
    return render_template('retailer/products.html', products=products)

@app.route('/retailer/product/add', methods=['GET', 'POST'])
@login_required
@role_required(['retailer'])
def add_product():
    categories = ProductCategory.query.all()
    if request.method == 'POST':
        retailer = User.query.get(session['user_id']).get_retailer()
        new_product = Product(
            retailer_id=retailer.id,
            name=request.form.get('name'),
            description=request.form.get('description'),
            price=float(request.form.get('price')),
            quantity=int(request.form.get('quantity')),
            category_id=int(request.form.get('category_id'))
        )
        db.session.add(new_product)
        db.session.commit()
        flash('Product added successfully.', 'success')
        return redirect(url_for('retailer_products'))
    return render_template('retailer/add_edit_product.html', categories=categories, form_title="Add New Product", product=None)


@app.route('/retailer/product/edit/<int:product_id>', methods=['GET', 'POST'])
@login_required
@role_required(['retailer'])
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)
    # Security: Ensure product belongs to the retailer
    if product.retailer_id != User.query.get(session['user_id']).get_retailer().id:
        flash('You do not have permission to edit this product.', 'error')
        return redirect(url_for('retailer_products'))

    categories = ProductCategory.query.all()
    if request.method == 'POST':
        product.name = request.form.get('name')
        product.description = request.form.get('description')
        product.price = float(request.form.get('price'))
        product.quantity = int(request.form.get('quantity'))
        product.category_id = int(request.form.get('category_id'))
        db.session.commit()
        flash('Product updated successfully.', 'success')
        return redirect(url_for('retailer_products'))
        
    return render_template('retailer/add_edit_product.html', product=product, categories=categories, form_title="Edit Product")

@app.route('/retailer/product/delete/<int:product_id>', methods=['POST'])
@login_required
@role_required(['retailer'])
def delete_product(product_id):
    # Add security checks as in edit_product
    product = Product.query.get_or_404(product_id)
    if product.retailer_id != User.query.get(session['user_id']).get_retailer().id:
        return redirect(url_for('retailer_products'))
    
    db.session.delete(product)
    db.session.commit()
    flash('Product deleted.', 'success')
    return redirect(url_for('retailer_products'))

# ====================== COMPLIANCE CHECKER ROUTES ======================
@app.route('/api/check-compliance', methods=['POST'])
@login_required
def api_check_compliance():
    user = User.query.get(session['user_id'])
    if not user.school_id:
        return jsonify({'error': 'No school associated'}), 400
    
    cart_items = []
    if 'cart_id' in request.json:
        cart = Cart.query.get(request.json['cart_id'])
        if cart and cart.user_id == user.id:
            cart_items = cart.items
    
    non_compliant = check_compliance(cart_items, user.school_id)
    return jsonify({
        'is_compliant': len(non_compliant) == 0,
        'non_compliant_items': [{
            'product_id': item['product'].id,
            'product_name': item['product'].name,
            'reason': item['reason']
        } for item in non_compliant]
    })

# ====================== PRICE COMPARISON ROUTES ======================
@app.route('/compare-prices')
@login_required
@role_required(['parent', 'student'])
def price_comparison():
    search_query = request.args.get('q', '')
    user = User.query.get(session['user_id'])
    
    if not user.school_id:
        flash('You need to be associated with a school to compare prices', 'error')
        return redirect(url_for('dashboard'))
    
    comparisons = []
    if search_query:
        comparisons = compare_prices(search_query, user.school_id)
    
    return render_template('price_comparison.html', 
                         comparisons=comparisons,
                         search_query=search_query)

# ====================== NOTIFICATIONS ROUTES ======================
# @app.route('/notifications')
# @login_required
# def notifications():
#     user = User.query.get(session['user_id'])
#     notifications = Notification.query.filter_by(user_id=user.id)\
#                                     .order_by(Notification.created_at.desc())\
#                                     .all()
#     return render_template('notifications/index.html', notifications=notifications)

# @app.route('/notifications/mark-read/<int:notification_id>')
# @login_required
# def mark_notification_read(notification_id):
#     notification = Notification.query.get_or_404(notification_id)
#     if notification.user_id != session['user_id']:
#         flash('Unauthorized', 'error')
#         return redirect(url_for('notifications'))
    
#     notification.is_read = True
#     db.session.commit()
    
#     # Redirect to relevant page if reference exists
#     if notification.notification_type == 'order' and notification.reference_id:
#         return redirect(url_for('order_detail', order_id=notification.reference_id))
#     elif notification.notification_type == 'donation' and notification.reference_id:
#         return redirect(url_for('donation_status', donation_id=notification.reference_id))
    
#     return redirect(url_for('notifications'))

# @app.route('/notifications/clear')
# @login_required
# def clear_notifications():
#     Notification.query.filter_by(user_id=session['user_id']).delete()
#     db.session.commit()
#     flash('Notifications cleared', 'success')
#     return redirect(url_for('notifications'))

# ===== ADD ERROR HANDLERS =====
@app.errorhandler(403)
def forbidden_error(error):
    return render_template('errors/403.html'), 403

@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('errors/500.html'), 500

def initialize_database():
    with app.app_context():
        db.create_all()         
        print("Database tables created successfully!")

# ====================== MAIN ======================
if __name__ == '__main__':
    initialize_database()
    create_admin_user()
    app.run(debug=True)