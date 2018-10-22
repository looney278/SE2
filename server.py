from flask import *
app = Flask(__name__) # note there are two underscores
@app.route('/') 
@app.route('/index') 
def index():
     return render_template('index.html')

if __name__ == '__main__': app.run()