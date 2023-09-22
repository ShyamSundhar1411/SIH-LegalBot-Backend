from app import app,db
from app.models import *
from flask_admin.contrib.sqla import ModelView
from flask_login import LoginManager, current_user,UserMixin,login_user,logout_user,login_required
from flask_admin import Admin

class MyModelView(ModelView):
    column_hide_backrefs = False
    column_display_pk = True
    def is_accessible(self):
        return current_user.is_authenticated and current_user.admin
    


if __name__ == '__main__':
    admin = Admin(app)
    admin.add_view(ModelView(User, db.session))
    admin.add_view(ModelView(Message,db.session))
    app.run(debug = True)