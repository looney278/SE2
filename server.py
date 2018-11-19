from flask import Flask, session, redirect, url_for, request, render_template
from flask_mail import Mail, Message
import psycopg2
import re
import hashlib
import uuid
import random
import string

# RegEx for email.
email_pattern = re.compile("^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
# RegEx for password 6-15 characters, 1 number, 1 letter.
pass_pattern = re.compile("(?!^[0-9]*$)(?!^[a-zA-Z]*$)^([a-zA-Z0-9]{6,15})$")
# RegEx for username 3-20 characters
user_pattern = re.compile("^(?=.{6,20}$)[A-Za-z0-9]+(?:[ _-][A-Za-z0-9]+)*$")

mail_settings = {
    "MAIL_SERVER": 'smtp.gmail.com',
    "MAIL_PORT": 465,
    "MAIL_USE_TLS": False,
    "MAIL_USE_SSL": True,
    "MAIL_USERNAME": 'TestForCoursework@gmail.com',
    "MAIL_PASSWORD": 'Potato555'
}
app = Flask(__name__)

app.config.update(mail_settings)
mail = Mail(app)


app.secret_key = 'mSMKW@Oa^8ingejvKj_<8Je1;_|Y&]n,J<^EK@!pupC=Mg.$;Df?query|`}a|FF_'

search_path = 'SET search_path TO assignment'


# creates initial connection to the database
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


# User registration
@app.route('/register_user', methods=['GET', 'POST'])
def register_user():
    try:
        conn = None
        # pulls data from web forms
        username = request.form['username']
        firstname = request.form['firstName']
        lastname = request.form['lastName']
        email = request.form['email']
        confemail = request.form['confEmail']
        password = request.form['password']
        confpassword = request.form['confPassword']

        # checks all RegEx matches
        if not email_pattern.match(email):
            return render_template('registration.html', emailError='Please use a valid email.')
        elif not email == confemail:
            return render_template('registration.html', emailError='Please ensure emails match.')
        elif not pass_pattern.match(password):
            return render_template('registration.html', passwordError='Password much contain at least 1 letter, '
                                                                      '1 number and be between 6-15 characters long')
        elif not user_pattern.match(username):
            return render_template('registration.html', usernameError='Username must be between 3-20 characters, '
                                                                      'consist of alphanumerics, -, _ and spaces.'
                                                                      'No more than 2 -, _ or spaces consecutively')
        elif not password == confpassword:
            return render_template('registration.html', passwordError='Please ensure passwords match.')
        else:
            conn = getconn()
            cur = conn.cursor()
            cur.execute(search_path)

            # duplicate username check
            # cur.execute("SELECT username FROM users where username = (%s)", (username,))
            cur.execute("SELECT username FROM users where username = '%s'" % username)
            if cur.fetchone() is not None:
                return render_template('registration.html', usernameError='Username already exists')

            # duplicate email check
            # cur.execute("SELECT email FROM users where email = (%s)", (email,))
            cur.execute("SELECT email FROM users where email = '%s'" % email)

            if cur.fetchone() is not None:
                return render_template('registration.html', emailError='Email already registered')

            # after all checks are done, password is salted and hashed.
            salt = uuid.uuid4().hex
            hashed_password = hashlib.sha512(password.encode() + salt.encode()).hexdigest()

            # cur.execute("INSERT INTO users VALUES (%s, %s, %s, %s, %s, %s)", \
            #           [username, firstname, lastname, email, hashed_password, salt])

            cur.execute("INSERT INTO users VALUES '%s', '%s','%s','%s','%s','%s'" %
                        (username, firstname, lastname, email, hashed_password, salt))
            conn.commit()
            return render_template('index.html')
    except Exception as e:
        print(e)
        return render_template('error.html', FUCK=e)
    finally:
        if conn:
            conn.close()


@app.route('/account', methods=['GET'])
def account():
    try:
        conn = getconn()
        cur = conn.cursor()
        cur.execute(search_path)
        username = session["username"]
        cur.execute("SELECT firstname, surname FROM users WHERE username = '%s'" % username)
        acc_username = username
        name = str(cur.fetchone())
        cur.execute("SELECT email FROM users WHERE username = '%s'" % username)
        email = str(cur.fetchone())
        return render_template('account.html', acc_username=acc_username, name=name, email=email)
    except Exception as e:
        return render_template('error.html', FUCK=e)
    finally:
        if conn:
            conn.close()


@app.route('/change_pass')
def change_pass():
    return render_template('password_change.html')


@app.route('/password_change', methods=['GET', 'POST'])
def password_change():
    try:
        conn = None
        conn = getconn()
        cur = conn.cursor()
        cur.execute(search_path)
        cur.execute("SELECT password FROM users WHERE username = '%s'" % session['username'])
        correct_old_pass = str(cur.fetchone()[0])
        entered_old_pass = request.form['old_pass']
        new_pass = request.form['new_pass']
        conf_new_pass = request.form['conf_new_pass']
        if new_pass is not conf_new_pass:
            render_template('password_change.html', pass_error="New passwords must match")
        cur.execute("SELECT salt FROM users WHERE username = '%s'" % session['username'])
        salt = str(cur.fetchone()[0])
        hashed_password = hashlib.sha512(entered_old_pass.encode() + salt.encode()).hexdigest()
        if hashed_password != correct_old_pass:
            return render_template('password_change.html', pass_error="incorrect password")
        salt = uuid.uuid4().hex
        new_hashed_password = hashlib.sha512(new_pass.encode() + salt.encode()).hexdigest()
        cur.execute("UPDATE users SET password = '%s' WHERE username = '%s'" %
                    (new_hashed_password, session['username']))
        cur.execute("UPDATE users SET salt = '%s' WHERE username = '%s'" % (salt, session['username']))
        return render_template('account.html')
    except Exception as e:
        return render_template('error.html', FUCK=e)
    finally:
        if conn:
            conn.close()


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))


@app.route('/password_reset', methods=['GET', 'POST'])
def password_reset():
    try:
        conn = None
        conn = getconn()
        cur = conn.cursor()
        cur.execute(search_path)
        new_password = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
        recipient = str(request.form['email'])
        msg = Message(subject="Password Reset",
                      sender="TestForCoursework@gmail.com",
                      recipients=[recipient],
                      body="New password : " + str(new_password))
        mail.send(msg)
        salt = uuid.uuid4().hex
        new_password_hashed = hashlib.sha512(new_password.encode() + salt.encode()).hexdigest()
        # DON'T KNOW WHY THESE WON'T EXECUTE
        # BUT WHEN THEY DO IT WILL SHOULD ALL WORK
        cur.execute("UPDATE users SET password = '%s' WHERE email = '%s'" % (new_password_hashed, recipient))
        cur.execute("UPDATE users SET salt = '%s' WHERE email = '%s'" % (salt, recipient))
        return render_template('password_reset_redirect.html', email=recipient)
    except Exception as e:
        return render_template('ERROR.html', FUCK=e)

    finally:
        if conn:
            conn.close()


@app.route('/login_user', methods=['GET', 'POST'])
def login_user():
    try:
        conn = None
        conn = getconn()
        cur = conn.cursor()
        username = request.form['username']
        entered_pass = request.form['password']
        cur.execute(search_path)
        # Takes the salt stored with the user name, adds and hashes the password provided then checks it against the
        # stored password
        # cur.execute("SELECT password FROM users WHERE username = (%s);", (username,))
        cur.execute("SELECT password FROM users WHERE username = '%s'" % username)
        stored_pass = str(cur.fetchone()[0])
        # cur.execute("SELECT salt FROM users WHERE username = (%s);", (username,))
        cur.execute("SELECT salt FROM users WHERE username = '%s'" % username)
        salt = str(cur.fetchone()[0])
        sub_hashed_password = hashlib.sha512(entered_pass.encode() + salt.encode()).hexdigest()
        if stored_pass == sub_hashed_password:
            session['username'] = username
            authorised = 1
        else:
            return render_template('login.html', logerror='Username or Password is incorrect.')
        return render_template('index.html')
    except Exception as e:
        return render_template('ERROR.html', FUCK=e)
    finally:
        if conn:
            conn.close()


if __name__ == "__main__":
    app.run(ssl_context=('cert.pem', 'key.pem'))
