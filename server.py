from flask import Flask, session, redirect, url_for, escape, request, render_template
import psycopg2
import re
import hashlib
import uuid

# RegEx for email.
emailpattern = re.compile("^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
# RegEx for password 6-15 characters, 1 number, 1 letter.
passpattern = re.compile("(?!^[0-9]*$)(?!^[a-zA-Z]*$)^([a-zA-Z0-9]{6,15})$")
# RegEx for username 3-20 characters
userpattern = re.compile("^(?=.{6,20}$)[A-Za-z0-9]+(?:[ _-][A-Za-z0-9]+)*$")

app = Flask(__name__)
app.secret_key = 'mSMKW@Oa^8ingejvKj_<8Je1;_|Y&]n,J<^EK@!pupC=Mg.$;Df?q|`}a|FF_'

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
        if not emailpattern.match(email):
            return render_template('registration.html', emailError='Please use a valid email.')
        elif not email == confemail:
            return render_template('registration.html', emailError='Please ensure emails match.')
        elif not passpattern.match(password):
            return render_template('registration.html', passwordError='Password much contain at least 1 letter, '
                                                                      '1 number and be between 6-15 characters long')
        elif not userpattern.match(username):
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
            #cur.execute("SELECT username FROM users where username = (%s)", (username,))
            q = "SELECT username FROM users where username = '"+username+"'"
            cur.execute(q)
            if cur.fetchone() is not None:
                return render_template('registration.html', usernameError='Username already exists')

            # duplicate email check
            #cur.execute("SELECT email FROM users where email = (%s)", (email,))
            q = "SELECT email FROM users where email = '"+email+"'"
            cur.execute(q)
            if cur.fetchone() is not None:
                return render_template('registration.html', emailError='Email already registered')

            # after all checks are done, password is salted and hashed.
            salt = uuid.uuid4().hex
            hashed_password = hashlib.sha512(password.encode() + salt.encode()).hexdigest()

            #cur.execute("INSERT INTO users VALUES (%s, %s, %s, %s, %s, %s)", \
             #           [username, firstname, lastname, email, hashed_password, salt])

            q = "INSERT INTO users VALUES ('"+username+"','"+firstname+"', '"+lastname+"', '"+email+"', '"+hashed_password+"', '"+salt+"')"
            cur.execute(q)
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
    conn = None
    conn = getconn()
    cur = conn.cursor()
    cur.execute(search_path)
    username = session["username"]
    cur.execute('SELECT firstname, surname FROM users WHERE username = (%s)', (username,))
    acc_username = username
    name = str(cur.fetchone())
    cur.execute('SELECT email FROM users WHERE username = (%s)', (username,))
    email = str(cur.fetchone())
    return render_template('account.html', acc_username=acc_username, name=name, email=email)


@app.route('/change_pass')
def change_pass():
    return render_template('password_change.html')


@app.route('/password_change', methods=['GET', 'POST'])
def password_change():
    try:
        conn = getconn()
        cur = conn.cursor()
        cur.execute(search_path)
        cur.execute('SELECT password FROM users WHERE username = (%s)', (session['username'],))
        correct_old_pass = str(cur.fetchone()[0])
        entered_old_pass = request.form['old_pass']
        new_pass = request.form['new_pass']
        conf_new_pass = request.form['conf_new_pass']
        if new_pass is not conf_new_pass:
            render_template('password_change.html', pass_error="New passwords must match")
        cur.execute('SELECT salt FROM users WHERE username = (%s)', (session['username'],))
        salt = str(cur.fetchone()[0])
        hashed_password = hashlib.sha512(entered_old_pass.encode() + salt.encode()).hexdigest()
        if hashed_password != correct_old_pass:
            return render_template('password_change.html', pass_error="incorrect password")

        new_hashed_password = hashlib.sha512(new_pass.encode() + salt.encode()).hexdigest()
        cur.execute('UPDATE users SET password = (%s) WHERE username = (%s)',
                    (new_hashed_password, session['username'],))
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
        #cur.execute("SELECT password FROM users WHERE username = (%s);", (username,))
        q = "SELECT password FROM users WHERE username = '"+username+"'"
        cur.execute(q)
        stored_pass = str(cur.fetchone()[0])
        #cur.execute("SELECT salt FROM users WHERE username = (%s);", (username,))
        q = "SELECT salt FROM users WHERE username = '"+username+"'"
        cur.execute(q)
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
