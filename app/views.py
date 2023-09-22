from app import app,db,api
from app.models import *
from flask import jsonify,Response,request,flash,redirect,url_for
from flask_restful import Resource,reqparse
from functools import wraps
from datetime import timedelta
from flask_jwt_extended import jwt_required,create_access_token,get_jwt_identity
from flask_login import LoginManager, current_user,UserMixin,login_user,logout_user,login_required

#Authentication
login_manager = LoginManager(app)

login_manager.login_view = 'login'
def manager_required(view_func):
    @wraps(view_func)
    def decorated_func(*args, **kwargs):
        if current_user.role != "Manager":
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('home'))  # Redirect to the desired page
        return view_func(*args, **kwargs)
    return decorated_func
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route("/api/register",methods=['POST'])
def register():
    data=request.json
    username = data.get("username")
    email=data.get("email")
    password=data.get("password")
    if not all([username,email,password]):
        return jsonify({"message":"Incomplete Data"}),400
    if User.query.filter_by(email=email).first():
        return jsonify({"message":"User already registered"}),409
    password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
    new_user = User(username=username, email=email, password_hash=password_hash)

    try:
        db.session.add(new_user)
        db.session.commit()
        id = new_user.id
        access_token = create_access_token(identity=new_user.email,expires_delta=timedelta(hours=1))
        email = new_user.email
        username = new_user.username
        isAdmin = new_user.admin
        user_data = {
                "message": "Account created successfully",
                "access_token": access_token,
                "email": email,
                "username": username,
                "isAdmin": isAdmin,
                "id":id
        }
        return jsonify(user_data), 201
    except:
        db.session.rollback()
        return jsonify({"message": "Database error"}), 500
@app.route("/api/login", methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not all([email, password]):
        return jsonify({"message": "Incomplete data"}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"message": "Invalid email or password"}), 401
    access_token = create_access_token(identity=user.email,expires_delta=timedelta(hours=1))
    email = user.email
    id = user.id
    username = user.username
    isAdmin = user.admin
    user_data = {
            "message": "Account Logged successfully",
            "access_token": access_token,
            "email": email,
            "username": username,
            "isAdmin": isAdmin,
            "id":id,
    }
    return jsonify(user_data), 200

@app.route('/create/db')
def create_db():
    db.create_all()
    return "",200

