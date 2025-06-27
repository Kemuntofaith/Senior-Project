from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
from datetime import datetime
import random

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///back2school.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ====================== MODELS ======================
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
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    @property
    def wallet(self):
        return Wallet.query.filter_by(user_id=self.id).first() or Wallet(user_id=self.id, balance=0.0)
    
    def add_notification(self, title, message, notification_type, reference_id=None):
        notification = Notification(
            user_id=self.id,
            title=title,
            message=message,
            notification_type=notification_type,
            reference_id=reference_id
        )
        db.session.add(notification)
        db.session.commit()
        return notification
    
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
    category = db.Column(db.String(50))
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

class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cart_id = db.Column(db.Integer, db.ForeignKey('cart.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1)
    
    product = db.relationship('Product')

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
    
    user = db.relationship('User', backref='orders')
    school = db.relationship('School', backref='orders')
    items = db.relationship('OrderItem', backref='order', cascade='all, delete-orphan')
    donations = db.relationship('DonationDistribution', back_populates='order', foreign_keys=['DonationDistribution.order_id'], cascade='all, delete-orphan')

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    
    product = db.relationship('Product')

class Wallet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    balance = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    user = db.relationship('User', backref='wallet')
    transactions = db.relationship('WalletTransaction', backref='wallet', cascade='all, delete-orphan')

class WalletTransaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    wallet_id = db.Column(db.Integer, db.ForeignKey('wallet.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    transaction_type = db.Column(db.String(20))  # deposit, payment, donation
    reference = db.Column(db.String(100))  # order_id or donation_id
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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
    distributions = db.relationship('DonationDistribution', backref='donation', cascade='all, delete-orphan')

class DonationItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    donation_id = db.Column(db.Integer, db.ForeignKey('donation.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    quantity = db.Column(db.Integer)
    description = db.Column(db.Text)  # For non-product donations
    
    product = db.relationship('Product')

class DonationDistribution(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'))
    donation_id = db.Column(db.Integer, db.ForeignKey('donation.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float)  # For monetary donations
    item_id = db.Column(db.Integer, db.ForeignKey('donation_item.id'))  # For item donations
    distributed_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    recipient = db.relationship('User', foreign_keys=[recipient_id])
    donation_item = db.relationship('DonationItem', foreign_keys=[item_id])
    order = db.relationship('Order', back_populates='donations')

class OrderTracking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    status = db.Column(db.String(20))  # processing, packed, shipped, delivered
    location = db.Column(db.String(100))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    notes = db.Column(db.Text)
    
    order = db.relationship('Order', backref='tracking_updates')

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
    
    user = db.relationship('User', backref='notifications')

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
            print("Initial admin user created!")

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
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', user=user)

# ====================== USER MANAGEMENT ROUTES ======================
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        
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
    
    return render_template('register.html')

@app.route('/admin/approve-users')
@role_required(['app_admin'])
def approve_users():
    pending_users = User.query.filter_by(is_approved=False).filter(User.role.in_(['retailer', 'school_admin'])).all()
    pending_schools = School.query.filter_by(is_approved=False).all()
    return render_template('admin/approve_users.html', 
                         pending_users=pending_users, 
                         pending_schools=pending_schools)

@app.route('/admin/approve-user/<int:user_id>')
@role_required(['app_admin'])
def approve_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_approved = True
    db.session.commit()
    
    if user.role == 'retailer':
        retailer = Retailer(user_id=user.id, business_name=f"{user.username}'s Business")
        db.session.add(retailer)
        db.session.commit()
    
    flash(f'{user.role.capitalize()} account approved successfully', 'success')
    return redirect(url_for('approve_users'))

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
    user.add_notification(
        "Retailer Approved",
        "Your retailer account has been approved by admin",
        "admin"
    )
    
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

@app.route('/admin/reports')
@role_required(['app_admin'])
def admin_reports():
    # Generate report data
    schools = School.query.count()
    active_orders = Order.query.filter(Order.status.in_(['paid', 'shipped'])).count()
    recent_donations = Donation.query.order_by(Donation.created_at.desc()).limit(5).all()
    
    return render_template('admin/reports.html',
                         schools=schools,
                         active_orders=active_orders,
                         recent_donations=recent_donations)

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
        admin_user.add_notification(
            "School Approved",
            f"Your school '{school.name}' has been approved",
            "admin"
        )
    
    db.session.commit()
    flash(f'School "{school.name}" approved successfully', 'success')
    return redirect(url_for('admin_schools'))

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

# ====================== SCHOOL REQUIREMENTS ROUTES ======================
@app.route('/school/requirements')
@role_required(['school_admin'])
def manage_requirements():
    school = School.query.filter_by(id=session.get('school_id')).first()
    if not school:
        flash('School not found', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('school/requirements.html', requirements=school.requirements)

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
@app.route('/shop')
@login_required
@role_required(['parent', 'student'])
def shop():
    # Get user's school
    user = User.query.get(session['user_id'])
    if not user.school_id:
        flash('You need to be associated with a school to shop', 'error')
        return redirect(url_for('dashboard'))
    
    # Get approved products from retailers approved by the school
    products = Product.query.join(Retailer)\
                           .filter(Retailer.approved_schools.any(id=user.school_id))\
                           .filter(Product.quantity > 0)\
                           .all()
    
    # Get school requirements for compliance checking
    requirements = SchoolRequirement.query.filter_by(school_id=user.school_id).all()
    
    return render_template('shop/index.html', products=products, requirements=requirements)

@app.route('/cart', methods=['GET', 'POST'])
@login_required
@role_required(['parent', 'student'])
def cart():
    user = User.query.get(session['user_id'])
    cart = Cart.query.filter_by(user_id=user.id).first()
    
    if not cart:
        cart = Cart(user_id=user.id)
        db.session.add(cart)
        db.session.commit()
    
    if request.method == 'POST':
        product_id = request.form.get('product_id')
        quantity = int(request.form.get('quantity', 1))
        
        product = Product.query.get(product_id)
        if not product:
            flash('Product not found', 'error')
            return redirect(url_for('shop'))
        
        # Check if product already in cart
        cart_item = CartItem.query.filter_by(cart_id=cart.id, product_id=product.id).first()
        if cart_item:
            cart_item.quantity += quantity
        else:
            cart_item = CartItem(cart_id=cart.id, product_id=product.id, quantity=quantity)
            db.session.add(cart_item)
        
        db.session.commit()
        flash('Product added to cart', 'success')
        return redirect(url_for('cart'))
    
    return render_template('shop/cart.html', cart=cart)

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
    user = User.query.get(session['user_id'])
    cart = Cart.query.filter_by(user_id=user.id).first()
    
    if not cart or not cart.items:
        flash('Your cart is empty', 'error')
        return redirect(url_for('shop'))

    # Check compliance with school requirements
    non_compliant_items = check_compliance(cart.items, user.school_id)
    if non_compliant_items:
        user.add_notification(
            "Compliance Issues",
            f"Your cart has {len(non_compliant_items)} non-compliant items",
            "compliance"
        )
        flash('Some items in your cart do not comply with school requirements', 'error')
        return render_template('shop/checkout.html', cart=cart, non_compliant_items=non_compliant_items)

    if request.method == 'POST':
        # Process payment from wallet and/or donations
        total = sum(item.product.price * item.quantity for item in cart.items)
        wallet = Wallet.query.filter_by(user_id=user.id).first()
        donation_amount = float(request.form.get('donation_amount', 0))
        wallet_amount = total - donation_amount
        
        if donation_amount > 0:
            # Check if user has available donations
            available_donations = DonationDistribution.query\
                .filter_by(recipient_id=user.id)\
                .filter(Donation.donation_type == 'monetary')\
                .filter(Donation.status == 'approved')\
                .join(Donation)\
                .all()
            
            total_available = sum(d.amount for d in available_donations)
            
            if donation_amount > total_available:
                flash('Not enough donated funds available', 'error')
                return redirect(url_for('order_detail', order_id=order.id))

            # Apply donation to order
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
                    recipient_id=user.id,
                    amount=-use_amount,
                    order_id=order.id
                )
                db.session.add(order_donation)
        
        # Process wallet payment if needed
        if wallet_amount > 0:
            if not wallet or wallet.balance < wallet_amount:
                flash('Insufficient funds in your wallet', 'error')
                return redirect(url_for('wallet_deposit'))
            
            wallet.balance -= wallet_amount
            transaction = WalletTransaction(
                wallet_id=wallet.id,
                amount=-wallet_amount,
                transaction_type='payment',
                reference=f'ORDER_{order.id}'
            )
            db.session.add(transaction)
        
        # Create order
        order = Order(
            user_id=user.id,
            school_id=user.school_id,
            total_amount=total,
            status='paid',
            payment_method='donation' if wallet_amount <= 0 else 'wallet' if donation_amount <= 0 else 'mixed',
            donation_used=donation_amount
        )
        db.session.add(order)
        
        # Add order items
        for cart_item in cart.items:
            order_item = OrderItem(
                order_id=order.id,
                product_id=cart_item.product.id,
                quantity=cart_item.quantity,
                price=cart_item.product.price
            )
            db.session.add(order_item)
            
            # Update product quantity
            cart_item.product.quantity -= cart_item.quantity
        
        # Clear cart
        CartItem.query.filter_by(cart_id=cart.id).delete()
        
        # Send notifications
        user.add_notification(
            "Order Confirmed",
            f"Your order #{order.id} has been placed successfully",
            "order",
            order.id
        )
        
        if user.school:
            school_admin = User.query.filter_by(school_id=user.school_id, role='school_admin').first()
            if school_admin:
                school_admin.add_notification(
                    "New Order",
                    f"New order #{order.id} from {user.username}",
                    "order",
                    order.id
                )
        
        db.session.commit()
        
        flash('Order placed successfully!', 'success')
        return redirect(url_for('order_detail', order_id=order.id))
    
    total = sum(item.product.price * item.quantity for item in cart.items)
    return render_template('shop/checkout.html', cart=cart, total=total)

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
        
        flash(f'Successfully deposited ${amount:.2f}', 'success')
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
@app.route('/notifications')
@login_required
def notifications():
    user = User.query.get(session['user_id'])
    notifications = Notification.query.filter_by(user_id=user.id)\
                                    .order_by(Notification.created_at.desc())\
                                    .all()
    return render_template('notifications/index.html', notifications=notifications)

@app.route('/notifications/mark-read/<int:notification_id>')
@login_required
def mark_notification_read(notification_id):
    notification = Notification.query.get_or_404(notification_id)
    if notification.user_id != session['user_id']:
        flash('Unauthorized', 'error')
        return redirect(url_for('notifications'))
    
    notification.is_read = True
    db.session.commit()
    
    # Redirect to relevant page if reference exists
    if notification.notification_type == 'order' and notification.reference_id:
        return redirect(url_for('order_detail', order_id=notification.reference_id))
    elif notification.notification_type == 'donation' and notification.reference_id:
        return redirect(url_for('donation_status', donation_id=notification.reference_id))
    
    return redirect(url_for('notifications'))

@app.route('/notifications/clear')
@login_required
def clear_notifications():
    Notification.query.filter_by(user_id=session['user_id']).delete()
    db.session.commit()
    flash('Notifications cleared', 'success')
    return redirect(url_for('notifications'))

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
        db.drop_all()  # Safety measure - ensures no old tables exist
        db.create_all()  # Creates all tables based on my models
        
        print("Database tables created successfully!")

# ====================== MAIN ======================
if __name__ == '__main__':
    initialize_database()
    create_admin_user()
    app.run(debug=True)