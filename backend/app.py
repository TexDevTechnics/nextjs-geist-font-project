from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_cors import CORS
from functools import wraps

app = Flask(__name__)
CORS(app, supports_credentials=True, origins=["http://localhost:3000"])
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///crm.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Session cookie settings for cross-origin
app.config['SESSION_COOKIE_SAMESITE'] = "None"
app.config['SESSION_COOKIE_SECURE'] = False  # Set True if using HTTPS

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # 'admin' or 'customer'
    email = db.Column(db.String(150), unique=True, nullable=True)
    full_name = db.Column(db.String(150), nullable=True)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Decorator for admin-only routes
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    full_name = data.get('full_name')
    role = 'customer'  # default role

    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already exists'}), 400

    user = User(username=username, email=email, full_name=full_name, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'})

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    # Special admin login
    if username == 'Admin' and password == 'Admin':
        admin_user = User.query.filter_by(username='Admin').first()
        if not admin_user:
            admin_user = User(username='Admin', role='admin')
            admin_user.set_password('Admin')
            db.session.add(admin_user)
            db.session.commit()
        login_user(admin_user)
        return jsonify({'message': 'Admin logged in successfully', 'role': 'admin'})

    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        login_user(user)
        return jsonify({'message': 'Logged in successfully', 'role': user.role})
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'})

@app.route('/profile', methods=['GET', 'PUT'])
@login_required
def profile():
    if request.method == 'GET':
        user_data = {
            'username': current_user.username,
            'email': current_user.email,
            'full_name': current_user.full_name,
            'role': current_user.role
        }
        return jsonify(user_data)
    elif request.method == 'PUT':
        data = request.json
        current_user.email = data.get('email', current_user.email)
        current_user.full_name = data.get('full_name', current_user.full_name)
        new_username = data.get('username', current_user.username)
        if new_username != current_user.username:
            if User.query.filter_by(username=new_username).first():
                return jsonify({'error': 'Username already exists'}), 400
            current_user.username = new_username
        new_password = data.get('password')
        if new_password:
            current_user.set_password(new_password)
        db.session.commit()
        return jsonify({'message': 'Profile updated successfully'})

# Placeholder routes for dashboards and feedback
@app.route('/customer/metrics', methods=['GET'])
@login_required
def customer_metrics():
    if current_user.role != 'customer':
        return jsonify({'error': 'Access denied'}), 403
    # Return dummy metrics for now
    metrics = {'geofence_hits': 123, 'active_devices': 45}
    return jsonify(metrics)

@app.route('/admin/metrics', methods=['GET'])
@admin_required
def admin_metrics():
    # Return dummy app performance metrics
    metrics = {'uptime': '99.9%', 'errors': 2, 'active_customers': 10}
    return jsonify(metrics)

@app.route('/feedback', methods=['POST'])
@login_required
def submit_feedback():
    data = request.json
    question = data.get('question')
    # For now, just acknowledge receipt
    return jsonify({'message': 'Feedback received', 'question': question})

@app.route('/admin/repair', methods=['POST'])
@admin_required
def repair():
    data = request.json
    issue = data.get('issue')
    # Placeholder for repair action
    return jsonify({'message': f'Repair action taken for issue: {issue}'})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
