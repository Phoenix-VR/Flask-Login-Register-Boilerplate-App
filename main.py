from flask import Flask,render_template,request,flash,redirect,url_for,abort
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from forms import RegistrationForm,LoginForm
from flask_login import LoginManager, current_user, login_user,UserMixin,logout_user
#instaciating Flask app
app = Flask(__name__)

# Setting database session to your database to use flask-sessions
app.config['SESSION_TYPE'] = 'sqlalchemy'

app.secret_key = 'your secret key here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

bcrypt = Bcrypt(app)
db = SQLAlchemy(app)

# Database we are using for flask-sessions
app.config['SESSION_SQLALCHEMY'] = db

# instanciating flask-sessions to actual flask app
sess = Session(app)

# Instanciating flask-login
login_manager = LoginManager()
login_manager.init_app(app)

class User(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    pfp = db.Column(db.String(50),nullable=False, default='default.jpg')
    password = db.Column(db.String(60), nullable=False)

    def __repr__(self):
        return f'User({self.username},{self.email},{self.pfp})'

# Clear it after after execution of code
db.create_all()
#---------------------------------------

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():
        if User.query.filter_by(username=form.username.data).first():
            validation_error_message = 'Username already taken. Please choose different one.'
            return render_template('register.html', username_error=validation_error_message,form=form)
        
        if User.query.filter_by(email=form.email.data).first():
            validation_error_message = 'Email Already Registered. Please Log in.'
            return render_template('register.html', email_error=validation_error_message,form=form)
        else:
            user_hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = User(username=form.username.data,email=form.email.data,password=user_hashed_password)
            db.session.add(user)
            db.session.commit()
            flash(f'Account created successfully, {form.username.data}. Login Now!','success')
            return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login',methods=['GET','POST'])
def login():
    form = LoginForm(request.form)
    if request.method=='POST' and form.validate():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password,form.password.data):
            login_user(user,remember=form.remember.data)
            flash(f'Logged in Successfully as {user.username}!','success')
            return redirect(url_for('home'))
        if user==None:
            flash('Email not registered with us. Join us now!','info')
            return redirect(url_for('register'))
        else:
            flash('Incorrect Password. Click on Forgot Password to change.')
            return redirect(url_for('login'))

        
    return render_template('login.html',form=form)

@app.route('/logout')
def logout():
    logout_user()
    flash('Successfully logged out','info')
    return redirect(url_for('home'))

@app.route('/account')
def user_account():
    user_pfp = url_for('static',filename='pfps/'+current_user.pfp)
    return render_template('account.html',pic = user_pfp)

    
if __name__ == '__main__':
    app.run(debug=True,port='8000')