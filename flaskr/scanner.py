from crypt import methods
from operator import methodcaller
from tabnanny import check
from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for
)
from werkzeug.exceptions import abort
import string
import secrets
from flask_cors import cross_origin
from flaskr.auth import login_required
from flaskr.db import get_db

bp = Blueprint('scanner', __name__)

@bp.route('/')
@login_required
def index():
    db = get_db()
    scanner = db.execute(
        'SELECT * FROM scanner WHERE user_id = ?', [g.user['id']]
    ).fetchone()
    
    if scanner:
        print(scanner['scanner_status'])
        return render_template('scanner/dashboard.html', status=scanner['scanner_status'] )
    else:
        return render_template('scanner/dashboard.html')

@bp.route('/add', methods=('GET', 'POST'))
@login_required
def add():
    if request.method == 'POST':
        username = request.form['username']
        org = request.form['organization']
        error = None

        if not username:
            error = "Username is required"

        if not org:
            error = "Organization is required"

        print(username)
        user_id = get_db().execute(
            'SELECT user.id FROM user WHERE username = ?', (username,)
        ).fetchone()


        print(user_id['id'])
        print(g.user['id'])

        if user_id['id'] != g.user['id']:
            error = "Users do not match"
        
        if error is not None:
            flash(error)
        else:
            auth_key = generate_auth_key()
            db = get_db()
            db.execute(
                'INSERT INTO scanner (auth_key, org, user_id)'
                'VALUES (?, ?, ?)',
                (auth_key, org, user_id['id'])
            )
            db.commit()

            return redirect(url_for('scanner.index'))
    return render_template('scanner/add.html')    

@bp.route('/scan', methods=('GET', 'POST'))
@login_required
def scan():
    if request.method == 'POST':
        title = request.form['title']
        body = request.form['body']
        error = None

        if not title:
            error = 'Title is required'

        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute(
                'INSERT INTO post (title, body, author_id)'
                'VALUES (?, ?, ?)',
                (title, body, g.user['id'])
            )
            db.commit()
            return redirect(url_for('blog.index'))
    
    return render_template('blog/create.html')    

@bp.route("/key", methods=['GET'])
@cross_origin(origin='localhost',headers=['Content- Type','Authorization'])
@login_required
def get_auth_key():
    auth_key = get_db().execute(
        'SELECT scanner.auth_key'
        ' FROM scanner'
        ' WHERE user_id = ?',
        (g.user['id'], )
    ).fetchone()

    if auth_key is None:
        abort(404, f"Auth key does not exist")
    
    print(str(auth_key['auth_key']))
    return { "auth_key" : str(auth_key['auth_key'])}

def get_post(id, check_author=True):
    pass

@bp.route('/<int:id>/update', methods=('GET', 'POST'))
@login_required
def update(id):
    post = get_post(id)

    if request.method == 'POST':
        title = request.form['title']
        body = request.form['body']
        error = None

        if not title:
            error = "Title is required"
        
        if not body:
            error = 'Body is required'

        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute(
                'UPDATE post SET title = ?, body = ?'
                ' WHERE id = ?',
                (title, body, id)
            )
            db.commit()
            
            return redirect(url_for('blog.index'))

    return render_template('blog/update.html', post=post)



@bp.route('/<int:id>/delete', methods=('POST',))
@login_required
def delete(id):
    get_post(id)
    db = get_db()
    db.execute('DELETE FROM post WHERE id = ? ', (id,))
    db.commit()
    
    return redirect(url_for('blog.index'))


def generate_auth_key():
    alphabet = string.ascii_letters + string.digits
    while True:
        password = ''.join(secrets.choice(alphabet) for i in range(15))
        if (any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and sum(c.isdigit() for c in password) >= 3):
            break  

    return password 

if __name__ == "__main__":
    generate_auth_key()