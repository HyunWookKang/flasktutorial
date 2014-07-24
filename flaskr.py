# all the imports
import os
import sqlite3
from flask import Flask, request, session, g, redirect, url_for, abort, \
render_template, flash
import re
import json

# create our little application :)
app = Flask(__name__)
app.config.from_object(__name__)

# Load default config and override config from an environment variable
app.config.update(dict(
	DATABASE=os.path.join(app.root_path, 'flaskr.db'),
	DEBUG=True,
	SECRET_KEY='development key',
	USERNAME='admin',
	PASSWORD='default'
))
app.config.from_envvar('FLASKR_SETTINGS', silent=True)

def connect_db():
	"""Connects to the specific database."""
	rv = sqlite3.connect(app.config['DATABASE'])
	rv.row_factory = sqlite3.Row
	return rv

def get_db():
	"""Opens a new database connection if there is none yet for the
	current application context.
	"""
	if not hasattr(g, 'sqlite_db'):
		g.sqlite_db = connect_db()
	return g.sqlite_db

@app.teardown_appcontext
def close_db(error):
	"""Closes the database again at the end of the request."""
	if hasattr(g, 'sqlite_db'):
		g.sqlite_db.close()

def init_db():
	with app.app_context():
		db = get_db()
		with app.open_resource('schema.sql', mode='r') as f:
			db.cursor().executescript(f.read())
		db.commit()

@app.route('/')
def show_entries():
	db = get_db()
	cur = db.execute('select title, text from entries order by id desc')
	entries = cur.fetchall()
	return render_template('show_entries.html', entries=entries)

@app.route('/add', methods=['POST'])
def add_entry():
	if not session.get('logged_in'):
		abort(401)
	db = get_db()
	db.execute('insert into entries (title, text) values (?, ?)', \
		[request.form['title'], request.form['text']])
	db.commit()
	flash('New entry was successfully posted')
	return redirect(url_for('show_entries'))

@app.route('/login', methods=['GET', 'POST'])
def login():
	error = None 
	f = open("users.txt")
	data = f.read()
	users = json.loads(data)
	f.close()
	if request.method == 'POST':
		for i in range(len(users)):
			login_test = users[i]
			login_id_choice = login_test["email"]
			login_pw_choice = login_test["password"]
			if request.form['username'] == login_id_choice and \
			request.form['password'] == login_pw_choice:
				session['logged_in'] = True
				flash('You were logged in')
				return redirect(url_for('show_entries'))
				break
 
		if request.form['username'] != login_id_choice or request.form['password'] != login_pw_choice:
			error = 'Invalid Id or Password'
	return render_template('login.html', error=error)

@app.route('/logout')
def logout():
	session.pop('logged_in', None)
	flash('You were logged out')
	return redirect(url_for('show_entries'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
	message = None
	users = []
	info = {}
	f = open("users.txt")
	data = f.read()
	users = json.loads(data)
	f.close()
	if request.method == 'POST':
		if bool(re.search('^[\w.]{1,}@[\dA-Za-z-]{1,}\.(com|net|ac\.kr)$',request.form['email'])) == True:
			for i in range(len(users)):
				id_test = users[i]
				id_choice = id_test["email"]
				if request.form['email'] == id_choice:
					message = "Another email"
					break
			if message != "Another email":
				if bool(re.search('\d',request.form['password'])) == True and \
				bool(re.search('[a-z]',request.form['password'])) == True and \
				bool(re.search('[A-Z]',request.form['password'])) == True and \
				bool(re.search('[\W]',request.form['password'])) == True and \
				len(request.form['password']) in range(8,21):
					if request.form['password'] != request.form['password_check']:
						message = "Password and password_check are different"
					else:
						message = "success"
						info["password"] = request.form['password']
						info["email"] = request.form['email']
						users.append(info)  
						f = open("users.txt", "w")
						f.write(json.dumps(users) + "\n")
						f.close()
				else:
					message = "Password should include one of digits, lower case, upper case and special letter between 8 and 20"
		else:
			message = "ID should be consist of numbers, alphabets, period and under-bar"
	return render_template('signup.html', message = message)



if __name__ == '__main__':
	init_db()
	app.run()
