from flask import Flask, session, redirect, url_for, request, render_template
from flask_mail import Mail, Message
import psycopg2
import re
import hashlib
import uuid
import random
import string
import time
from datetime import datetime
# Please don't judge my spaghetti code :(

# RegEx for email.
email_pattern = re.compile("^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
# RegEx for password 6-15 characters, 1 number, 1 letter.
pass_pattern = re.compile("(?!^[0-9]*$)(?!^[a-zA-Z]*$)^([a-zA-Z0-9]{6,255})$")
# RegEx for username 3-20 characters
user_pattern = re.compile("^(?=.{3,20}$)[A-Za-z0-9]+(?:[ _-][A-Za-z0-9]+)*$")
#RegEx for First and Second name
name_pattern = re.compile("^[A-Za-z]+$") 

mail_settings = {
    "MAIL_SERVER": 'smtp.gmail.com',
    "MAIL_PORT": 465,
    "MAIL_USE_TLS": False,
    "MAIL_USE_SSL": True,
    "MAIL_USERNAME": 'TestForCoursework@gmail.com',
    "MAIL_PASSWORD": 'Potato555'
}
#Random list gen for enumeration delay
n = list()
while len(n) < 20:
    randomNo = random.uniform(0.1, 0.3)
    n.append(randomNo)

app = Flask(__name__)

app.config.update(mail_settings)
mail = Mail(app)

app.secret_key = 'mSMKW@Oa^8ingejvKj_<8Je1;_|Y&]n,J<^EK@!pupC=Mg.$;Df?query|`}a|FF_'

search_path = 'SET search_path TO assignment'

search_path = 'SET search_path TO assignment'



#some sql injection protection to be used in user posts
def encodeText(text):
    newstr = text.replace(";","%$MSVZO") #replacing semicolon
    newstr = newstr.replace("--","%$6SVA1") #replacing --
    newstr = newstr.replace("'","%$9XVAQ") #replacing '
    return newstr

def decodeText(text):
    newstr = text.replace("%$MSVZO",";")
    newstr = newstr.replace("%$6SVA1","--")
    newstr = newstr.replace("%$9XVAQ","'")
    return newstr

def sanitiseHTML(text):
    sanhtml = text.replace("<","&lt;")
    sanhtml = sanhtml.replace(">","&gt;")
    return sanhtml

# creates initial connection to the database
def getconn():
    connstr = "host='localhost' dbname='postgres' user='postgres' password='password'"
    conn = psycopg2.connect(connstr)
    return conn


@app.route('/')
@app.route('/index')
def index():
    conn = None

    q="select * from user_posts"
    conn = getconn()
    cur = conn.cursor()
    cur.execute(search_path)
    cur.execute(q)
    posts = cur.fetchall()
    decodedPosts = []
    for post in posts:
        #post[5] = decodeText(post[5])
        decodedText = decodeText(post[5])
        newarr = [post[0],post[1],post[2],post[3],post[4],decodedText]  
        decodedPosts.append(newarr)
    return render_template('index.html', posts=decodedPosts)


@app.route('/registration')
def registration():
    return render_template('registration.html')


# User registration
@app.route('/register_user', methods=['POST'])
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
            return render_template('registration.html', passwordError='Password much contain at least 1 letter, '                                                                      '1 number and be between 6-15 characters long')
        elif not user_pattern.match(username):
            return render_template('registration.html', usernameError='Username must be between 3-20 characters, '
                                                                      'consist of alphanumerics, -, _ and spaces.'
                                                                      'No more than 2 -, _ or spaces consecutively')
        elif not name_pattern.match(firstname): 
            return render_template('registration.html', nameError='Name should use English alphabet characters only')    
        elif not name_pattern.match(lastname): 
            return render_template('registration.html', nameError='Name should use English alphabet characters only')                                                           
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
            # session['username'] = username
            return redirect(url_for('index'))
    except Exception as e:
        return render_template('error.html', error_message=e)
    finally:
        if conn:
            conn.close()


@app.route('/tfa_update', methods=['POST'])
def tfa_update():
    try:
        conn = getconn()
        cur = conn.cursor()
        cur.execute(search_path)
        update = None
        if request.form.getlist('tfa'):
            update = str(request.form.getlist('tfa')[0])
        if update == 'on':
            #cur.execute("UPDATE users SET tfa = TRUE WHERE username = '%s'" % session['username'])
            cur.execute("UPDATE users SET tfa = TRUE WHERE username = ?", (session['username']))
        else:
            #cur.execute("UPDATE users SET tfa = FALSE WHERE username = '%s'" % session['username'])
            cur.execute("UPDATE users SET tfa = FALSE WHERE username = ?", (session['username']))
        conn.commit()
        return redirect(url_for('index'))
    except Exception as e:
        return render_template('error.html', error_message=e)


@app.route('/account', methods=['GET'])
def account():
    try:
        conn = getconn()
        cur = conn.cursor()
        cur.execute(search_path)
        username = session["username"]
        #cur.execute("SELECT firstname, lastname, email, tfa FROM users WHERE username = '%s'" % username)
        cur.execute("SELECT firstname, lastname, email, tfa FROM users WHERE username = ?", (username))
        details = cur.fetchone()
        name = str(details[0]) + " " + str(details[1])
        email = str(details[2])
        tfa = str(details[3])
        return render_template('account.html', acc_username=username, name=name, email=email, user_tfa=tfa)
    except Exception as e:
        return render_template('error.html', error_message=e)
    finally:
        if conn:
            conn.close()


@app.route('/change_pass')
def change_pass():
    return render_template('password_change.html')


@app.route('/password_change', methods=['POST'])
def password_change():
    try:
        conn = None
        conn = getconn()
        cur = conn.cursor()
        cur.execute(search_path)
        #cur.execute("SELECT password FROM users WHERE username = '%s'" % session['username'])
        cur.execute("SELECT password FROM users WHERE username = ?", (session['username']))
        correct_old_pass = str(cur.fetchone()[0])
        entered_old_pass = request.form['old_pass']
        new_pass = request.form['new_pass']
        conf_new_pass = request.form['conf_new_pass']
        if new_pass is not conf_new_pass:
            render_template('password_change.html', pass_error="New passwords must match")
        #cur.execute("SELECT salt FROM users WHERE username = '%s'" % session['username'])
        cur.execute("SELECT salt FROM users WHERE username = ?", (session['username']))
        salt = str(cur.fetchone()[0])
        hashed_password = hashlib.sha512(entered_old_pass.encode() + salt.encode()).hexdigest()
        if hashed_password != correct_old_pass:
            return render_template('password_change.html', pass_error="incorrect password")
        salt = uuid.uuid4().hex
        new_hashed_password = hashlib.sha512(new_pass.encode() + salt.encode()).hexdigest()
        #cur.execute("UPDATE users SET password = '%s' WHERE username = '%s'" %
                    #(new_hashed_password, session['username']))
        cur.execute("UPDATE users SET password = '%s' WHERE username = ?",
                     (new_hashed_password, session['username']))
        #cur.execute("UPDATE users SET salt = '%s' WHERE username = '%s'" % (salt, session['username']))
        cur.execute("UPDATE users SET salt = '%s' WHERE username = ?", (salt, session['username']))
        conn.commit()
        return redirect(url_for('account'))
    except Exception as e:
        return render_template('error.html', error_message=e)
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


@app.route('/newpost', methods=['POST']) 
def newpost(): 
    try:
        conn = None
        conn = getconn()
        cur = conn.cursor()
        cur.execute(search_path)
        text = request.form['post-text']
        sanhtml = sanitiseHTML(text) 
        santext = encodeText(sanhtml)
        dt = str(datetime.now().strftime('%d-%b-%Y %H:%M:%S '))
        q = "INSERT INTO posts (user_id,datetime,text) VALUES ("+session['id']+",'"+dt+"','"+santext+"')"
        cur.execute(q)
        conn.commit()
        return redirect(url_for('index'))  
    except Exception as e:
        print(e)
        return redirect(url_for('index'))  
    finally:
        if conn:
            conn.close()  

@app.route('/password_reset', methods=['POST'])
def password_reset():
    try:
        conn = None
        conn = getconn()
        cur = conn.cursor()
        cur.execute(search_path)
        new_password = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
        recipient = str(request.form['email'])
        if recipient:
            msg = Message(subject="Password Reset",
                          sender="TestForCoursework@gmail.com",
                          recipients=[recipient],
                          body="New password : " + str(new_password))
            mail.send(msg)
            salt = uuid.uuid4().hex
            new_password_hashed = hashlib.sha512(new_password.encode() + salt.encode()).hexdigest()
            #cur.execute("UPDATE users SET password = '%s' WHERE email = '%s'" % (new_password_hashed, recipient))
            cur.execute("UPDATE users SET password = '%s' WHERE email = ?", (new_password_hashed, recipient))
            #cur.execute("UPDATE users SET salt = '%s' WHERE email = '%s'" % (salt, recipient))
            cur.execute("UPDATE users SET salt = '%s' WHERE email = ?", (salt, recipient))
            conn.commit()
            return render_template('password_reset_redirect.html', email=recipient)
        else:
            return render_template('login.html', logerror='Invalid email')
    except Exception as e:
        return render_template('error.html', error_message=e)

    finally:
        if conn:
            conn.close()

@app.route('/pass_reset', methods=['GET'])
def pass_reset():
    return render_template('password_reset_page.html')


# @app.route('/new_post', methods=['POST'])
# def new_post():
#     try:
#         conn = None
#         conn = getconn()
#         cur = conn.cursor()
#         cur.execute(search_path)
#         contents = request.form['text']

#         cur.execute("INSERT INTO posts(username, content) VALUES ('%s', '%s')" % (session['username'], contents))
#         conn.commit()
#         return redirect(url_for('index'))
#     except Exception as e:
#         return render_template('error.html', error_message=e)
#     finally:
#         if conn:
#             conn.close()


@app.route('/login_user', methods=['POST'])
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
        if username and entered_pass:
            #cur.execute("SELECT password, salt, tfa, attempts, id FROM users WHERE username = '%s'" % username)
            cur.execute("SELECT password, salt, tfa, attempts, id FROM users WHERE username = ?", (username))
            data = cur.fetchone()
            stored_pass = str(data[0])
            salt = str(data[1])
            tfa = bool(data[2])
            attempts = int(data[3])
            userid = str(data[4])
            if attempts < 3:
                sub_hashed_password = hashlib.sha512(entered_pass.encode() + salt.encode()).hexdigest()
                if stored_pass == sub_hashed_password:
                    #cur.execute("UPDATE users SET attempts = 0 WHERE username = '%s'" % username)
                    cur.execute("UPDATE users SET attempts = 0 WHERE username = ?", (username))
                    conn.commit()
                    if tfa is True:
                        session['tempName'] = username
                        return redirect(url_for('two_factor_auth'))
                    else:
                        session['username'] = username
                        session['id'] = userid
                else:
                    #cur.execute("UPDATE users SET attempts = attempts + 1 WHERE username = '%s'" % username)
                    cur.execute("UPDATE users SET attempts = attempts + 1 WHERE username = ?", (username))
                    conn.commit()
                    time.sleep(random.choice(n))
                    return render_template('login.html', logerror='Invalid username or password')
                return redirect(url_for('index'))
            else:
                time.sleep(random.choice(n))
                return render_template('login.html', logerror='Account Locked Contact Administrator')
        else:
            time.sleep(random.choice(n))
            return render_template('login.html', logerror='Invalid username or password')
    except Exception as e:
        return render_template('error.html', error_message=e)
    finally:
        if conn:
            conn.close()
           



@app.route('/two_factor_auth', methods=['GET'])
def two_factor_auth():
    try:
        conn = getconn()
        cur = conn.cursor()
        cur.execute(search_path)
        tfa_code = ''.join(random.choices(string.digits, k=6))
        #cur.execute("SELECT email FROM users WHERE username = '%s'" % session['tempName'])
        cur.execute("SELECT email FROM users WHERE username = ?", (session['tempName']))
        recipient = str(cur.fetchone()[0])
        msg = Message(subject="Two Factor Authentication",
                      sender="TestForCoursework@gmail.com",
                      recipients=[recipient],
                      body="Enter this code on the site: " + str(tfa_code))
        mail.send(msg)
        session['tempCode'] = str(tfa_code)
        return render_template('two_factor_auth.html')
    except Exception as e:
        return render_template('error.html', error_message=e)


@app.route('/auth_check', methods=['POST'])
def auth_check():
    try:
        authorise_code = session['tempCode']
        entered_code = str(request.form['entered_code'])
        if entered_code == authorise_code:
            session['username'] = session['tempName']
            return redirect(url_for('index'))
        else:
            return render_template('two_factor_auth.html', code_error='Incorrect Code')
    except Exception as e:
        return render_template('error.html', error_message=e)


@app.after_request
def apply_caching(response):
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

def connection():
    conn = getconn()
    cur = conn.cursor()
    cur.execute(search_path)
    return cur


if __name__ == "__main__":
    app.run(ssl_context=('cert.pem', 'key.pem'))
