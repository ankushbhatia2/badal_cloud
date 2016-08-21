""" Copyright 2016 Ankush Bhatia

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. """

#-------------------------------------------------------------------------------
# Name:        badal.py
# Purpose:     Badal the cloud hosts a cloud server to store photos and txt files
#
#
#
# Author:      Ankush Bhatia
#
# Created:     21/01/2016
# Copyright:   Copyright 2016 Ankush Bhatia
# Licence:     Apache License 2.0
#-------------------------------------------------------------------------------
# all the imports
import time
from sqlite3 import dbapi2 as sqlite3
from hashlib import md5
from datetime import datetime
import os
from contextlib import closing
from flask import Flask, request, session, url_for, redirect, \
     render_template, abort, g, flash, _app_ctx_stack, send_from_directory
from werkzeug import check_password_hash, generate_password_hash, secure_filename

# configuration
DATABASE = 'badal.db'
DEBUG = True
SECRET_KEY = 'development key'
USERNAME = 'asshat'
PASSWORD = 'password'
UPLOAD_FOLDER = 'C:\Users\coola_000\Desktop\Badal the Cloud\\'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif' ])

# create our little application :)
app = Flask(__name__)
app.config.from_object(__name__)
app.config.from_envvar('FLASKR_SETTINGS', silent=True)

def connect_db():
    return sqlite3.connect(app.config['DATABASE'])

def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    top = _app_ctx_stack.top
    if not hasattr(top, 'sqlite_db'):
        top.sqlite_db = sqlite3.connect(app.config['DATABASE'])
        top.sqlite_db.row_factory = sqlite3.Row
    return top.sqlite_db

def init_db():
    with closing(connect_db()) as db:
        with app.open_resource('badal.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

def query_db(query, args=(), one=False):
    """Queries the database and returns a list of dictionaries."""
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    return (rv[0] if rv else None) if one else rv

def get_user_id(username):
    """Convenience method to look up the id for a username."""
    rv = query_db('select user_id from user where username = ?',
                  [username], one=True)
    return rv[0] if rv else None

@app.before_request
def before_request():
    g.db = connect_db()
    g.user = None
    if 'user_id' in session:
        print session['user_id']
        g.user = query_db('select * from user where user_id = ?',
                          [session['user_id']], one=True)

@app.teardown_request
def teardown_request(exception):
    db = getattr(g, 'db', None)
    if db is not None:
        db.close()

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

def make_tree(path):
    tree = dict(name=os.path.basename(path), children=[])
    tree['name'] = str(path)
    try: lst = os.listdir(path)
    except OSError:
        pass #ignore errors
    else:
        for name in lst:
            fn = os.path.join(path, name)
            if os.path.isdir(fn):
                tree['children'].append(make_tree(fn))
            else:
                tree['children'].append(dict(name=name))
    print tree['name']
    return tree

@app.route('/')
def mainscreen():
    cur = g.db.execute('select * from user order by user_id desc')
    entries = [dict(title=row[0], text=row[1]) for row in cur.fetchall()]
    return render_template('badal.html', entries=entries)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER']+'\\'+str(g.user[0]),
                               filename)

@app.route('/<username>/download')
def download(username):
    user_id1 = get_user_id(username)
    path = os.getcwd()+'\\'+str(user_id1)+'\\'
    return render_template('download.html', tree=make_tree(path))

@app.route('/cloud', methods=['GET', 'POST'])
def cloud():
    if request.method == 'POST':
        if request.form['file1'] == 'Upload':
            file = request.files['file']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                print g.user[0], g.user
                file.save(os.path.join(os.getcwd()+'\\'+str(g.user[0]), filename))
                return redirect(url_for('uploaded_file',
                                    filename=filename))
        if request.form['file1'] == 'Download':
            print(str(g.user[1]))
            return  redirect(url_for('download', username=str(g.user[1])))

    error = None
    return render_template('cloud.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Logs the user in."""
    if g.user:
        return redirect(url_for('cloud'))
    error = None
    if request.method == 'POST':
        user = query_db('''select * from user where
            username = ?''', [request.form['username']], one=True)
        if user is None:
            error = 'Invalid username'
        elif not check_password_hash(user['pw_hash'],
                                     request.form['password']):
            error = 'Invalid password'
        else:
            flash('You were logged in')
            session['user_id'] = user['user_id']
            return redirect(url_for('cloud'))
    return render_template('login.html', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registers the user."""
    if g.user:
        return redirect(url_for('cloud'))
    error = None
    if request.method == 'POST':
        if not request.form['username']:
            error = 'You have to enter a username'
        elif not request.form['email'] or \
                 '@' not in request.form['email']:
            error = 'You have to enter a valid email address'
        elif not request.form['password']:
            error = 'You have to enter a password'
        elif request.form['password'] != request.form['password2']:
            error = 'The two passwords do not match'
        elif get_user_id(request.form['username']) is not None:
            error = 'The username is already taken'
        else:
            db = get_db()
            db.execute('''insert into user (
              username, email, pw_hash) values (?, ?, ?)''',
              [request.form['username'], request.form['email'],
               generate_password_hash(request.form['password'])])
            db.commit()
            flash('You were successfully registered and can login now')
            user_id = get_user_id(request.form['username'])
            os.mkdir(str(user_id))
            return redirect(url_for('login'))
    return render_template('register.html', error=error)


@app.route('/logout')
def logout():
    """Logs the user out."""
    flash('You were logged out')
    session.pop('user_id', None)
    return redirect(url_for('mainscreen'))

if __name__ == '__main__':
    app.run(host='192.168.10.197', port=8000)
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
