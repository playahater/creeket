from creek import db, app
from datetime import datetime
from flaskext.bcrypt import Bcrypt
from flask.ext.login import (LoginManager, current_user, login_required,
                            login_user, logout_user, UserMixin, AnonymousUser,
                            confirm_login, fresh_login_required)

#from flask_dashed.admin import Admin
#from flask_dashed.ext.sqlalchemy import ModelAdminModule, model_form

from flask.ext import admin, wtf
from flask.ext.admin.contrib import sqlamodel
from flask.ext.admin.contrib.sqlamodel import filters
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import aliased, contains_eager
from werkzeug import OrderedMultiDict
from  forms import AddServerForm, Form

bcrypt = Bcrypt()

class Users(db.Model, UserMixin):
    __tablename__ = 'users'
    uid = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(60))
    pwdhash = db.Column(db.String())
    email = db.Column(db.String(60))
    fb_id = db.Column(db.String(30), unique=True)
    activate = db.Column(db.Boolean)
    created = db.Column(db.DateTime)

    def __init__(self, username, password, email):
        self.username = username
        self.pwdhash = bcrypt.generate_password_hash(password)
        #self.pwdhash = password
        self.email = email
        self.activate = True
        self.created = datetime.utcnow()

    def check_password(self, password):
        return bcrypt.check_password_hash(self.pwdhash, password)

    def is_active(self):
        return self.activate

    def get_id(self):
        return  self.uid

    def __unicode__(self):
        return self.username

class Tasks(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    taskname = db.Column(db.Text, nullable=False)
    task = db.Column(db.Text, nullable=False)
    roles = db.Column(db.Text, nullable=False)
    parallel = db.Column(db.Boolean, nullable=True)
    sendmail = db.Column(db.Boolean, nullable=True)

    def __init__(self, taskname, task, roles, parallel, sendmail):
        self.taskname = taskname
        self.task = task
        self.roles = roles
        self.parallel = parallel
        self.sendmail = sendmail

    def __unicode__(self):
        return self.name

class Server(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text, nullable=False)
    match = db.Column(db.Text, nullable=True)
    ip  = db.Column(db.Text, nullable=True)
    url = db.Column(db.Text, nullable=True)
    enabled = db.Column(db.Boolean, nullable=True)

    def __init__(self, name, description, match, ip, url, enabled):
        self.name = name
        self.description = description
        self.match = match
        self.ip = ip
        self.url = url
        self.enabled = enabled

    def __unicode__(self):
        return self.name

# Customized Post model admin
class ServerAdmin(sqlamodel.ModelView):
    # List of columns that can be sorted. For 'user' column, use User.username as
    # a column.
    sortable_columns = ('name', 'uid','timestamp')

    # Rename 'title' columns in list view
    rename_columns = dict(title='Server name')

    searchable_columns = ('name', Server.name)

    column_filters = ('name',
                      filters.FilterLike(Server.name, 'Fixed Title', options=(('test1', 'Test 1'), ('test2', 'Test 2'))))

    # Pass arguments to WTForms. In this case, change label for text field to
    # be 'Big Text' and add required() validator.
    form_args = dict(
                    text=dict(label='Big Text', validators=[wtf.required()])
                )

    def __init__(self, session):
        # Just call parent class with predefined model.
        super(ServerAdmin, self).__init__(Server, session)

# Create admin
admin = admin.Admin(app, 'Creek Admin')

# Add views
admin.add_view(sqlamodel.ModelView(Users, db.session))
admin.add_view(ServerAdmin(db.session))
