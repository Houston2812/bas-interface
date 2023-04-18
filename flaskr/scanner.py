from crypt import methods
import json
from operator import methodcaller
from tabnanny import check
from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for, jsonify
)
from werkzeug.exceptions import abort
import string
import secrets
from flask_cors import cross_origin, CORS
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
        print(f"Scanner status: {scanner['scanner_status']}")
    key = get_auth_key()
    if key is not None:
        g.key = key
    else:
        g.key = "Not initialized"
    if scanner is None:
        g.scanner_status = "Disconnected"
    elif scanner['scanner_status'] == 0:
        g.scanner_status = "Disconnected"
    elif scanner['scanner_status'] == 1:
        g.scanner_status = "Connected"

    session['scanner_status'] = g.scanner_status
    print(g.key)


    scans_data = db.execute(
        'SELECT id, scan_type'
        ' FROM scans'
        ' WHERE user_id = ? ',
        (g.user['id'], )
    ).fetchall()

    print(f"Scans data : {scans_data}")

    if scans_data is None:
        scans_data=[]

    if scanner:
        print(scanner['scanner_status'])
        status = session.get('scanner_status') or "Disconnected"

        return render_template('scanner/dashboard.html', status=status, key=g.key, scans = scans_data  )
    else:
        return render_template('scanner/dashboard.html', key=g.key, scans = scans_data)   

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
            print(f"Generated auth key: {auth_key}")
            db = get_db()
            db.execute(
                'INSERT INTO scanner (auth_key, org, user_id) '
                'VALUES (?, ?, ?)',
                (auth_key, org, user_id['id'])
            )
            db.commit()
            
            message = "Key was generated!"
            flash(message, "success")
            
            return redirect(url_for('scanner.index'))
    status = session.get('scanner_status') or "Disconnected"
    print(f"Scanner status: {status}")

    key = get_auth_key()
    if key is not None:
        g.key = key
    else:
        g.key = "None"
    return render_template('scanner/add.html', status=status, key=g.key)    

@bp.route('/scan', methods=['GET', 'POST'])
@login_required
def scan():

    if request.method == "POST":

        scan_category = request.form['scan_category']
        scan_type = request.form['scan_type']
        scan_speed = request.form['scan_speed']

        if scan_category == "Directory Traversal":
            
            if scan_type == "Basic" and scan_category == "Directory Traversal":
                scan_type = "DIRECTORY_TRAVERSAL_BASIC"
            elif scan_type == "Short" and scan_category == "Directory Traversal":
                scan_type = "DIRECTORY_TRAVERSAL_SHORT"
            elif scan_type == "Full" and scan_category == "Directory Traversal":
                scan_type = "DIRECTORY_TRAVERSAL_FULL"
            
            scan_category = "DIRECTORY_TRAVERSAL"
        
        elif scan_category == "SQL Injection":
            if scan_type == "Basic":
                scan_type = "SQL_INJECTION_BASIC"
            elif scan_type == "Short":
                scan_type = "SQL_INJECTION_SHORT"
            elif scan_type == "Full":
                scan_type = "SQL_INJECTION_FULL"

            scan_category = "SQL_INJECTION"

        elif scan_category == "XSS":
            if scan_type == "Basic":
                scan_type = "XSS_BASIC"
            elif scan_type == "Short":
                scan_type = "XSS_SHORT"
            elif scan_type == "Full":
                scan_type = "XSS_FULL"

            scan_category == "XSS"

        if scan_speed == "Slow":
            scan_speed = "SLOW"
        elif scan_speed == "Normal":
            scan_speed = "NORMAL"
        elif scan_speed == "FAST":
            scan_speed = "FAST"

        auth_key = get_auth_key()

        if auth_key == None:
            error = "Scan was not added"

            flash(error, "error")
            return redirect(url_for('scanner.index'))    

        db = get_db()

        db.execute(
            'INSERT INTO scans (user_id, auth_key, scan_category, scan_type, scan_speed)'
            ' VALUES (?, ?, ?, ?, ?)',
            (g.user['id'], auth_key, scan_category, scan_type, scan_speed)
        )       

        db.commit()

        db.close()

        return redirect(url_for('scanner.index'))
    status = session.get('scanner_status') or "Disconnected"
    key = get_auth_key()
    if key is not None:
        g.key = key
    else:
        g.key = "None"
    return render_template('scanner/scan.html', status=status, key=g.key    )    

@bp.route('/scans', methods=['POST'])
def scans():

    data = request.get_json()

    key = data['key']

    db = get_db()
    user_id = db.execute(
        'SELECT scanner.user_id'
        ' FROM scanner'
        ' WHERE auth_key = ?',
        (key, )
    ).fetchone()

    if user_id:
        db = get_db()
        scans = db.execute(
            'SELECT id, scan_category, scan_type, scan_speed '
            ' FROM scans'
            ' WHERE user_id = ? AND finished = 0',
            (user_id )
        ).fetchone()

        db.close()
        if scans:
            return jsonify(
                scan_id = scans['id'],
                scan_category = scans['scan_category'],
                scan_type = scans['scan_type'],
                scan_speed = scans['scan_speed']
            )
    
    return jsonify(
        scan_id = "none",
        scan_category = "none",
        scan_type = "none",
        scan_speed = "none"
    )

        
@bp.route('/clean', methods=['GET'])
def clean():
    db = get_db()

    db.execute(
        'DELETE '
        'FROM scans '
        'WHERE user_id = ?',
        (g.user['id'], )
    )

    db.commit()
    db.close()

    return redirect(url_for('scanner.index'))

        
@bp.route('/validate', methods=['POST'])
def validate():
    data = request.get_json()

    key = data['key']

    print(f"Key: {key}")
    user_id = get_user_id(key)

    if user_id:
        db = get_db()
        db.execute(
            'UPDATE scanner'
            ' SET scanner_status = 1'
            ' WHERE user_id = ?',
            (user_id, )
        )

        db.commit()
        db.close()

        return jsonify({ "valid" : "true"} )
    else:
        return jsonify({ "valid" : "false"} )

@bp.route('/report', methods=['POST'])
def report():
    data = request.get_json()

    print(f"Data: {data}")

    key = data['key']
    scan_id = data['scan_id']
    user_id = get_user_id(key)
    
    report = json.loads(data['report'])
    print(f"Key: {key}; Scan_id = {scan_id}; Report:\n{report}")
    if user_id:
        db = get_db()

        db.execute(
            'UPDATE scans'
            ' SET finished = 1'
            ' WHERE id = ?',
            (scan_id, )
        )

        db.commit()

        for el in report:

            db.execute(
                'INSERT INTO  report (user_id, scan_id, payload, status_)'
                ' VALUES (?, ?, ?, ?)',
                (user_id, scan_id, el['payload'], el['status'])
            )

            db.commit()
        
        db.close()

        return jsonify({ "status" : "ok"} )
    else:
        return jsonify({ "status" : "fail"} )

@bp.route('/report/<scan_id>', methods=['GET'])
def get_report(scan_id):

    db = get_db()

    reports = db.execute(
        'SELECT report.payload, report.status_ '
        ' FROM report '
        ' WHERE user_id = ? AND scan_id = ?',
        (g.user['id'], scan_id, )
    ).fetchall()

    # print(reports[0]['payload'])

    status = session.get('scanner_status') or "Disconnected"
    key = get_auth_key()
    if key is not None:
        g.key = key
    else:
        g.key = "None"
    return render_template('scanner/report.html', status = status, reports = reports, scan_id = scan_id ,key =g.key)    


@bp.route('/report/delete/<scan_id>', methods=['GET'])
def delete_report(scan_id):
    db = get_db()

    print(f"Delete requested for {scan_id}")
    db.execute(
        'DELETE '
        'FROM scans '
        'WHERE id = ? and user_id = ? ',
        (scan_id, g.user['id'])
    )

    db.commit()
    db.close()

    return redirect(url_for('scanner.index',))

def get_user_id(key):
    db = get_db()
    user_id = db.execute(
        'SELECT scanner.user_id'
        ' FROM scanner'
        ' WHERE auth_key = ?',
        (key, )
    ).fetchone()
    
    # db.close()
    if user_id:
        return str(user_id['user_id'])
    else:
        return None

def get_auth_key():
    db = get_db()
    auth_key = db.execute(
        'SELECT scanner.auth_key'
        ' FROM scanner'
        ' WHERE user_id = ?',
        (g.user['id'], )
    ).fetchone()
    
    # db.close()

    if auth_key:
        print(str(auth_key['auth_key']))
        return str(auth_key['auth_key'])
    else:
        print("Uninitialized")
        return None



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