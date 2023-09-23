import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_restful import Api
SECRET_KEY = os.urandom(32)
app = Flask(__name__)
cors = CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///legalbot.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = SECRET_KEY
api = Api(app)

jwt = JWTManager(app)
db = SQLAlchemy()
db.init_app(app)
migrate = Migrate(app,db)

from app import views,models
