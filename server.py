from flask import *
import psycopg2
import re

emailpattern = re.compile("^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
passpattern = re.compile("(?!^[0-9]*$)(?!^[a-zA-Z]*$)^([a-zA-Z0-9]{6,15})$")

app = Flask(__name__)  # note there are two underscores


def getconn():
    connstr = "host='localhost' dbname= 'localhost' user ='postgre' password= 'password' "
    conn = psycopg2.connect(connstr)
    return conn


@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')


@app.route('/registerUser', methods=['POST'])
def registerUser():
    try:
        conn = None
        username = request.form['username']
        firstname = request.form['firstName']
        lastname = request.form['lastName']
        country = request.form['country']
        county = request.form['county']
        email = request.form['email']
        confemail = request.form['confEmail']
        password = request.form['password']
        confpassword = request.form['confPassword']

        if not emailpattern.match(email):
            return render_template('registration.html', emailError='Please use a valid email.')
        elif not email == confemail:
            return render_template('registration.html', emailError='Please ensure emails match.')
        elif not passpattern == password:
            return render_template('registration.html', passError='Password much contain at least 1 letter, 1 number'
                                                                  'and be between 6-15 characters long.')
        elif not password == confpassword:
            return render_template('registration.html', passError='Please ensure passwords match.')
        else:
            conn = getconn()
            cur = conn.cursor()
            cur.execute('SET search_path to project')

            cur.execute('INSERT INTO users VALUES (%s, %s, %s, %s, %s, %s, %s)', \
                        [username, firstname, lastname, country, county, email, password])
            conn.commit()
            return render_template('index.html', msg='Customer Added')
    except Exception as e:
        return render_template('index.html', msg='Customer NOT Added ', error=e)
    finally:
        if conn:
            conn.close()


if __name__ == "__main__":
    app.run(ssl_context=('cert.pem', 'key.pem'))
