from flask import url_for
from creek import app
import urlparse


def static(path):
    root = app.config.get('STATIC_ROOT')
    if root is None:
        return url_for('static', filename=path)
    else:
        return urlparse.urljoin(root, path)

@app.context_processor
def context_processor():
    return dict(static=static)

def symlink():
    """
    Updates the symlink to the most recently deployed version.
    """
    releases()
    env.current_path = '/root/your_project/current'
    run('rm %(current_path)s' % env)
    run('ln -s %(current_release)s %(current_path)s' % env)

def rsync():
    """
    Run remote rsync from backoff to WEB1/WEB2/WEB3.
    """
    rsynced = run('rsync/rsync-WWW-from-BO-to-WEB1-WEB2-WEB3.sh')
    return rsynced

def local_rsync():
    """
    Run local rsync from home to docroot.
    """
    with cd('%(current_path)s' % env):
        print(green('Running local rsync', bold=True))
        run('rm -f sites/default/settings.php')
        run('rsync -a sites/all/ %(docroot)s/sites/all/ --delete' % env)
        print(green('Finished local rsync', bold=True))

def cleanup():
    """Clean up old releases"""
    if len(env.releases) > 3:
        directories = env.releases
        directories.reverse()
        del directories[:3]
        env.directories = ' '.join([ '%(releases_path)s/%(release)s' % { 'releases_path':env.releases_path, 'release':release } for release in directories ])
        run('rm -rf %(directories)s' % env)

def releases():
    """
    List a releases made.
    """
    r = run('ls -x %(releases_path)s' % env)
    env.releases = sorted(r.split("\t"))
    if len(env.releases) >= 1:
        env.current_revision = env.releases[-1]
        env.current_release = '%(releases_path)s/%(current_revision)s' % env
    if len(env.releases) > 1:
        env.previous_revision = env.releases[-2]
        env.previous_release = '%(releases_path)s/%(previous_revision)s' % env

    #cleanup old releases. max 3 allowed.
    cleanup()

