from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://username:password@localhost/back2school'
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

# ====================== MAIN ======================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)