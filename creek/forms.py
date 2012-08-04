from flask.ext.wtf import Form, TextField, DecimalField, TextAreaField, validators, PasswordField, BooleanField

class AddServerForm(Form):
    name = TextField('Server name', [validators.Required()])
    description = TextAreaField('Server description')
    match = TextField('HTML match string')
    ip = TextField('Server IP address')
    url = TextField('Server Url')
    enabled = BooleanField('Enable this server')

class TasksForm(Form):
    taskname = TextField('Task name', [validators.Required()])
    task = TextAreaField('Task content')
    roles = TextField('Add servers')
    parallel = BooleanField('Parallel execution')
    sendmail = BooleanField('Mail notification')

class SignupForm(Form):
    username = TextField('Username', [validators.Required()])
    password = PasswordField('Password', [validators.Required(), validators.EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Confirm Password', [validators.Required()])
    email = TextField('Email', [validators.Required(),validators.Email()])

class EmailAlerts(Form):
    alertmail = TextField('Email Address', [validators.Length(min=6, max=35)])

class LoginForm(Form):
    username = TextField('Username', [validators.Required()])
    password = PasswordField('Password', [validators.Required()])

class PasswordResetForm(Form):
    username = TextField('Username')
    email = TextField('email')

class PasswordChangeForm(Form):
    password = PasswordField('Password', [validators.Required()])
