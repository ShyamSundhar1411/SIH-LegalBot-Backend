from app import db
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

class User(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    email = db.Column(db.String(100),nullable=False)
    password_hash = db.Column(db.String(128))
    admin = db.Column(db.Boolean,default = False)
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_is_active(self):
        return self.is_active
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    def is_admin(self):
        return self.admin
    def get_id(self):
        return self.id
    def __repr__(self):
        return self.username
class Message(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    user = db.Column(db.Integer,db.ForeignKey("user.id"),nullable=False)
    is_user = db.Column(db.Boolean,default = True)
    user = db.relationship('User', backref=db.backref('users', lazy='dynamic'))
    text = db.Column(db.String)
    user_id = db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False,info = {"label":"User"})
    timestamp = db.Column(db.DateTime,default=datetime.utcnow)
