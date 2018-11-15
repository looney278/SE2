from flask import Flask
from flask_mail import Mail, Message
import random

app = Flask(__name__)

mail_settings = {
    "MAIL_SERVER": 'smtp.gmail.com',
    "MAIL_PORT": 465,
    "MAIL_USE_TLS": False,
    "MAIL_USE_SSL": True,
    "MAIL_USERNAME": 'TestForCoursework@gmail.com',
    "MAIL_PASSWORD": 'Potato555'
}

app.config.update(mail_settings)
mail = Mail(app)

if __name__ == '__main__':
    with app.app_context():
        x = random.randint(1000, 10000)
        msg = Message(subject="Authentication Key",
                      sender="TestForCoursework@gmail.com",
                      recipients=["TestForCoursework@gmail.com"], # replace with your email for testing
                      body="Your authentication key is : " + str(x))
        mail.send(msg)

key = input("Input authentication key ")
if key == str(x):
    print('True')
else:
    print('False')
