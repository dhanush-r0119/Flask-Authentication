from flask import Flask, render_template, redirect, url_for, request,flash,session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import timedelta
import random
import smtplib
from flask_session import Session
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

app= Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY']='authentication'

app.config['SESSION_TYPE']='filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['PERMANENT_SESSION_LIFETIME']= timedelta(minutes=30)
Session(app)

db=SQLAlchemy(app)
bcrypt= Bcrypt(app)

class User(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    username=db.Column(db.String(150),nullable=False)
    email=db.Column(db.String(150),unique=True,nullable=False)
    password=db.Column(db.String(150),nullable=False)

with app.app_context():
    db.create_all()


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/signup',methods=['GET','POST'])
def signup():
    if request.method=='POST':
        username=request.form.get('username')
        email=request.form.get('email')
        password=request.form.get('password')

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email id is already registered")
            return redirect(url_for("signup"))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username,email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("Account Created Succesfully!","success")
        return redirect(url_for("login"))
    
    return render_template('signup.html')

@app.route('/login',methods=['POST','GET'])
def login():
    if request.method=='POST':
        email=request.form.get('email')
        password=request.form.get('password')
        user=User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password,password):
            session['user_id'] =user.id
            session['username']=user.username
            session['logged_in']=True
            flash("Logged in succesfully!","success")
            return redirect(url_for("dashboard"))
        else:
            flash("Login failed. check your email and password","danger")

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'logged_in' in session:
        return render_template('dashboard.html',username=session['username'])
    else:
        flash("you need to login","warning")
        return render_template('login.html')
    
@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out. signin to continue","info")
    return redirect(url_for('login'))

def is_logged_in():
    return 'logged_in' in session

@app.route('/forgot_password',methods=['GET','POST'])
def forgot_password():
    if request.method=='POST':
        email=request.form.get('email')
        new_password=request.form.get('new_password')
        confirm_password=request.form.get('confirm_password')

        user =User.query.filter_by(email=email).first()

        if not user:
            flash('Email is not registered','danger')
            return render_template('signup.html')
        
        if new_password!=confirm_password:
            flash('password do not match','danger')
            return redirect(url_for("forgot_password"))

        hashed_password=bcrypt.generate_password_hash(new_password).decode('utf-8')
        user.password=hashed_password
        db.session.commit()

        flash('Password changed succesfully','success')
        return redirect(url_for("login"))

    return render_template('forgot_password.html')

if __name__=='__main__':
    app.run(debug=True) 
