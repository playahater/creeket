from flask import render_template, url_for, redirect, flash, request, session, g, json
from forms import AddServerForm, TasksForm, SignupForm, LoginForm, PasswordResetForm, PasswordChangeForm
from creek import app, db
from models import Server, Users, Tasks
import datetime
from itsdangerous import TimestampSigner, URLSafeSerializer
from flask.ext.login import (LoginManager, current_user, login_required,
                            login_user, logout_user, UserMixin, AnonymousUser,
                            confirm_login, fresh_login_required)
from flaskext.mail import Mail, Message
from flaskext.bcrypt import Bcrypt
from flask_debugtoolbar import DebugToolbarExtension
from sqlalchemy.orm import aliased, contains_eager
from datetime import datetime
from urlparse import urlparse

from fabric.api import *
from fabric.network import *
from fabric.contrib import *
from fabric.colors import *

toolbar = DebugToolbarExtension(app)

bcrypt = Bcrypt()
mail = Mail(app)

class Anonymous(AnonymousUser):
    name = u"Anonymous"

login_manager = LoginManager()
login_manager.anonymous_user = Anonymous
login_manager.login_view = "login"
login_manager.login_message = u"Please log in to access this page."
login_manager.refresh_view = "reauth"
login_manager.init_app(app)

@login_manager.user_loader
def load_user(uid):
    return Users.query.filter_by(uid=uid).first()

"""
Homepage - dashboard
"""
@app.route('/')
def dashboard():
    servers = Server.query.order_by(db.asc(Server.name))
    tasks = Tasks.query.order_by(db.asc(Tasks.taskname))
    return render_template('dashboard.html', servers=servers, tasks=tasks)

"""
Deploy to servers
"""
@app.route('/deploy')
def deploy():
    return render_template('deploy/deploy.html')

@app.route('/server/<server_id>/deploy')
def server_deploy(server_id):
    """
    Deploy latest git code to server.
    """

    server = Server.query.filter_by(id = server_id).first_or_404()

    #set start deploy time
    start = time.time()

    with cd(server_id.gitdir):
        #set latest project release path
        env.current_path = env.gitdir

        #pulling latest code to live
        pulled = run('git pull origin %(branch)s' % env)
        print (green('Pulled in latest changes on branch %(branch)s', bold=True) % env)

        if '10.10.29.11' in env.hosts:
            env.current_release = '%(releases_path)s/%(release_date)s' % env
            run('cp -rp %(gitdir)s %(current_release)s' % env)

            print (green('Completed mounting latest release', bold=True))
            pulled += "\n\n"
            pulled += "Latest release path: " + str(env.current_release)
            pulled += "\n\n"

            #make a symlink to a latest release and cleanup old releases.
            symlink()

    #run local rsync
    local_rsync()

    #clear drupal cache
    clear_cache()
    print(green('Finished drush cc all', bold=True))

    if not server.dev:
        #sync files from backoffice to web servers
        rsynced = rsync()

        pulled += "\n\n"
        pulled += "Rsync log dump:"
        pulled += "\n\n"
        pulled += str(rsynced)

        print(green('Finished remote rsync', bold=True))

        #get end deploy time
        end = time.time()
        #deploy run time
        deploy_time = end - start

        #send mail on success
        _send_mail(pulled, deploy_time, env.host)

    return render_template('deploy/deploy_server.html')

"""
Rollback
"""
@app.route('/server/<server_id>/rollback')
def server_rollback(server_id):
    """
    Rolls back to the previously deployed version.
    """
    #set start deploy time
    start = time.time()

    #set env and vars for rollback
    backoff()
    releases()

    if len(env.releases) >= 2:
        env.current_release = env.releases[-1]
        env.previous_revision = env.releases[-2]
        env.current_release = '%(releases_path)s/%(current_revision)s' % env
        env.previous_release = '%(releases_path)s/%(previous_revision)s' % env
        pulled  = "\n\n"
        pulled += run('rm %(current_path)s; ln -s %(previous_release)s %(current_path)s && rm -rf %(current_release)s' % env)
        pulled += "\n\n"


    #run local rsync
    local_rsync()

    #clear drupal cache
    clear_cache()
    print(green('Finished drush cc all', bold=True))

    #run remote sync from bo to web1/web2/web3
    rsynced = rsync()

    pulled += "\n\n"
    pulled += "Rsync log dump:"
    pulled += "\n\n"
    pulled += str(rsynced)

    print(green('Finished remote rsync', bold=True))

    #get end deploy time
    end = time.time()
    #deploy run time
    deploy_time = end - start

    #send mail on success
    _send_mail(pulled, deploy_time, env.host, 'rollback')

"""
Tasks
"""
@app.route('/tasks')
def tasks():
    tasks = Tasks.query.order_by(db.asc(Tasks.taskname))
    return render_template('tasks/tasks.html', tasks=tasks)

@app.route('/add-task', methods=['GET', 'POST'])
@login_required
def add_task():
    form = TasksForm()
    if form.validate_on_submit():
        task = Tasks(
            form.taskname.data,
            form.task.data,
            form.roles.data,
            form.parallel.data,
            form.sendmail.data,
        )
        db.session.add(task)
        db.session.commit()
        return redirect(url_for('tasks'))
    tasks = Tasks.query.order_by(db.desc(Tasks.taskname))
    return render_template('tasks/add_task.html', tasks=tasks, form=form)

@app.route('/view/task/<task_id>')
def view_task(task_id):
    task = Tasks.query.filter_by(id = task_id).first_or_404()
    return render_template('tasks/view_task.html', task=task)

@app.route('/edit/task/<task_id>', methods=['GET', 'POST'])
@login_required
def edit_task(task_id):
    form = TasksForm()
    entry = Tasks.query.filter_by(id = task_id).first_or_404()
    if form.validate_on_submit():
        tasks = Tasks(
            form.taskname.data,
            form.task.data,
            form.roles.data,
            form.parallel.data,
            form.sendmail.data,
        )
        entry.taskname = form.taskname.data
        entry.task = form.task.data
        entry.roles = form.roles.data
        entry.parallel = form.parallel.data
        entry.sendmail = form.sendmail.data
        db.session.commit()
        return redirect(url_for('tasks'))
    else:
        form = TasksForm(obj=entry)
        form.populate_obj(entry)
    return render_template('tasks/edit_task.html', entry=entry, form=form)

"""
Servers
"""
@app.route('/servers')
def servers():
    servers = Server.query.order_by(db.asc(Server.name))
    return render_template('servers/servers.html', servers=servers)

@app.route('/add-server', methods=['GET', 'POST'])
@login_required
def add_server():
    form = AddServerForm()
    if form.validate_on_submit():
        server = Server(
            form.name.data,
            form.description.data,
            form.match.data,
            form.ip.data,
            form.url.data,
            form.enabled.data,
        )
        db.session.add(server)
        db.session.commit()
        return redirect(url_for('servers'))
    server = Server.query.order_by(db.desc(Server.name))
    return render_template('servers/add_server.html', server=server, form=form)

@app.route('/view/server/<server_id>')
def view_server(server_id):
    entry = Server.query.filter_by(id = server_id).first_or_404()
    return render_template('servers/view_server.html', entry=entry)

@app.route('/edit/server/<server_id>', methods=['GET', 'POST'])
@login_required
def edit_server(server_id):
    form = AddServerForm()
    entry = Server.query.filter_by(id = server_id).first_or_404()
    if form.validate_on_submit():
        server = Server(
            form.name.data,
            form.description.data,
            form.match.data,
            form.ip.data,
            form.url.data,
            form.enabled.data,
        )
        entry.name = form.name.data
        entry.description = form.description.data
        entry.match = form.match.data
        entry.ip = form.ip.data
        entry.url = form.url.data
        entry.enabled = form.enabled.data
        db.session.commit()
        return redirect(url_for('dashboard'))
    else:
        form = AddServerForm(obj=entry)
        form.populate_obj(entry)
    return render_template('servers/edit_server.html', entry=entry, form=form)

"""
Login / Logout / Register / Password reset
"""
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = SignupForm()
    if form.validate_on_submit():
      user = Users(
          form.username.data,
          form.password.data,
          form.email.data,
      )
      db.session.add(user)
      db.session.commit()
      return redirect(url_for('dashboard'))
    return render_template('general/register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        admin = Users.query.filter_by(username=form.username.data).first()
        if admin:
          if admin.check_password(form.password.data):
            login_user(admin)
            flash(admin.username + ' logged in')
            return redirect(url_for('dashboard'))
          else:
            flash('wrong pass')
            return redirect(url_for('login'))
        else:
          flash('wrong username')
          return redirect(url_for('login'))
    return render_template('general/login.html', form=form)


@app.route('/passwordreset', methods=['GET', 'POST'])
def resetpassword():
    form = PasswordResetForm()
    if form.validate_on_submit():
        if form.username.data:
          user = Users.query.filter_by(username=form.username.data).first()
        elif form.email.data:
          user = Users.query.filter_by(email=form.email.data).first()
        else:
          flash("Username or password not in system")
        if user:
          if user.email:
            s = URLSafeSerializer('12fe454t')
            key = s.dumps([user.username, user.email])
            msg = Message("Password reset", sender="info@droopia.net", recipients=[user.email])
            msg.html = "<b>testing</b> \
                        #<a href='http://127.0.0.1:5000/passwordreset/" + key + "'>http://127.0.0.1:5000/passwordreset/" + key + "</a>"

            mail.send(msg)
            flash('Email sent to: ' + user.email)
            return redirect(url_for('resetpassword'))
          else:
            flash('No such user')
            return redirect(url_for('resetpassword'))
        else:
            flash('No such user')
            return redirect(url_for('resetpassword'))

    return render_template('general/reset_password.html', form=form)


@app.route('/passwordreset/<secretstring>', methods=['GET', 'POST'])
def changepassword(secretstring):
    form = PasswordChangeForm()
    if form.validate_on_submit():
        if form.password.data:
          s = URLSafeSerializer('12fe454t')
          uname, uemail = s.loads(secretstring)
          user = Users.query.filter_by(username=uname).first()
          db.session.add(user)
          user.pwdhash = bcrypt.generate_password_hash(form.password.data)
          db.session.commit()
          flash('succsessful password reset')
          return redirect(url_for('login'))
        else:
            flash('Try again')
            return redirect(url_for('resetpassword'))

    return render_template('general/change_password.html', form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.")
    return redirect(url_for("dashboard"))

"""
Ajax callback for task execution
"""
@app.route('/_execute')
@login_required
def execute_task():
    #get current task from db
    task = Tasks.query.filter_by(id = request.args.get('url', 0)).first_or_404()

    #execute a task
    with settings(hide('warnings', 'running', 'stdout', 'stderr'), user='root', host_string=task.roles):
        data = run('%s |column -tx' % task.task)

    return json.dumps({
           'data' : data,
           }, indent=0)

