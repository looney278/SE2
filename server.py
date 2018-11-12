from flask import *
import psycopg2
import re
import hashlib
import uuid

emailpattern = re.compile("^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
passpattern = re.compile("(?!^[0-9]*$)(?!^[a-zA-Z]*$)^([a-zA-Z0-9]{6,15})$")

app = Flask(__name__)


def getconn():
    connstr = "host='localhost' dbname='postgres' user='postgres' password='password'"
    conn = psycopg2.connect(connstr)
    return conn


@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')


@app.route('/registration')
def registration():
    return render_template('registration.html')


@app.route('/registerUser', methods=['POST'])
def registerUser():
    try:
        conn = None
        username = request.form['username']
        firstname = request.form['firstName']
        lastname = request.form['lastName']
        email = request.form['email']
        confemail = request.form['confEmail']
        password = request.form['password']
        confpassword = request.form['confPassword']

        if not emailpattern.match(email):
            return render_template('registration.html', emailError='Please use a valid email.')
        elif not email == confemail:
            return render_template('registration.html', emailError='Please ensure emails match.')
        elif not passpattern.match(password):
            return render_template('registration.html', passwordError='Password much contain at least 1 letter, '
                                                                      '1 number and be between 6-15 characters long')
        elif not password == confpassword:
            return render_template('registration.html', passwordError='Please ensure passwords match.')
        else:
            salt = uuid.uuid4().hex
            hashed_password = hashlib.sha512(password.encode() + salt.encode()).hexdigest()
            conn = getconn()
            cur = conn.cursor()
            cur.execute('SET search_path to assignment')

            cur.execute('INSERT INTO users VALUES (%s, %s, %s, %s, %s, %s)', \
                        [username, firstname, lastname, email, hashed_password, salt])
            conn.commit()
            return render_template('index.html')
    except Exception as e:
        return render_template('index.html')
    finally:
        if conn:
            conn.close()


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/loginUser', methods=['GET', 'POST'])
def loginUser():
    conn = None
    try:
        username = request.form['username']
        sub_pass = request.form['password']
        conn = getconn()
        cur = conn.cursor()
        cur.execute('SET search_path to assignment')

        stored_pass = cur.execute('SELECT password FROM users where username = \'{0}\''.format(username))
        salt = cur.execute('SELECT salt FROM users WHERE username = \'{0}\''.format(username))
        sub_hashed_password = hashlib.sha512(sub_pass.encode() + salt.encode()).hexdigest()
        if stored_pass == sub_hashed_password:
            x=1
            #CREATE COOKIE/TOKEN/LOGIN THINGY]
        else:
            return render_template('login.html', logerror = 'Username or Password is incorrect.')
        return render_template('index.html')
    except Exception as e:
        return render_template('ERROR.html', FUCK=e)
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    app.run(ssl_context=('cert.pem', 'key.pem'))
from flask import *
import psycopg2
import re
import hashlib
import uuid

emailpattern = re.compile("^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
passpattern = re.compile("(?!^[0-9]*$)(?!^[a-zA-Z]*$)^([a-zA-Z0-9]{6,15})$")

app = Flask(__name__)


def getconn():
    connstr = "host='localhost' dbname='postgres' user='postgres' password='password'"
    conn = psycopg2.connect(connstr)
    return conn


@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')


@app.route('/registration')
def registration():
    return render_template('registration.html')


@app.route('/registerUser', methods=['POST'])
def registerUser():
    try:
        conn = None
        username = request.form['username']
        firstname = request.form['firstName']
        lastname = request.form['lastName']
        email = request.form['email']
        confemail = request.form['confEmail']
        password = request.form['password']
        confpassword = request.form['confPassword']

        if not emailpattern.match(email):
            return render_template('registration.html', emailError='Please use a valid email.')
        elif not email == confemail:
            return render_template('registration.html', emailError='Please ensure emails match.')
        elif not passpattern.match(password):
            return render_template('registration.html', passwordError='Password much contain at least 1 letter, '
                                                                      '1 number and be between 6-15 characters long')
        elif not password == confpassword:
            return render_template('registration.html', passwordError='Please ensure passwords match.')
        else:
            salt = uuid.uuid4().hex
            hashed_password = hashlib.sha512(password.encode() + salt.encode()).hexdigest()
            conn = getconn()
            cur = conn.cursor()
            cur.execute('SET search_path to assignment')

            cur.execute('INSERT INTO users VALUES (%s, %s, %s, %s, %s, %s)', \
                        [username, firstname, lastname, email, hashed_password, salt])
            conn.commit()
            return render_template('index.html')
    except Exception as e:
        return render_template('index.html')
    finally:
        if conn:
            conn.close()


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/loginUser', methods=['GET', 'POST'])
def loginUser():
    conn = None
    try:
        username = request.form['username']
        sub_pass = request.form['password']
        conn = getconn()
        cur = conn.cursor()
        cur.execute('SET search_path to assignment')

        stored_pass = cur.execute('SELECT password FROM users where username = \'{0}\''.format(username))
        salt = cur.execute('SELECT salt FROM users WHERE username = \'{0}\''.format(username))
        sub_hashed_password = hashlib.sha512(sub_pass.encode() + salt.encode()).hexdigest()
        if stored_pass == sub_hashed_password:
            x=1
            #CREATE COOKIE/TOKEN/LOGIN THINGY]
        else:
            return render_template('login.html', logerror = 'Username or Password is incorrect.')
        return render_template('index.html')
    except Exception as e:
        return render_template('ERROR.html', FUCK=e)
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    app.run(ssl_context=('cert.pem', 'key.pem'))
