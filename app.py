import sqlite3
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy

# Bootstrap for the app
from flask_bootstrap import Bootstrap

# For Using in signup and logins
from flask_wtf import FlaskForm

from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length

from sqlalchemy import ForeignKey, create_engine
from sqlalchemy.sql import func
from sqlalchemy.ext.declarative import declarative_base

app = Flask(__name__)
app.config['SECRET_KEY'] = 'SecretKey'
# Link to my database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
Bootstrap(app)
database = SQLAlchemy(app)
db = database
Base = declarative_base()


engine = create_engine('sqlite:///database.db')


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired()])
    password = PasswordField('password', validators=[InputRequired(), Length(min=5, max=80)])
    remember = BooleanField('remember me')


class SignupForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=5, max=80)])
    firstname = StringField('First Name', validators=[InputRequired()])
    lastname = StringField('Last Name', validators=[InputRequired()])
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid Email')])
    phone = StringField('Phone', validators=[InputRequired()])
    profile = StringField('Profile(A short Description)', validators=[InputRequired()])
    city = StringField('City', validators=[InputRequired()])
    state = StringField('State', validators=[InputRequired()])
    country = StringField('Country', validators=[InputRequired()])


class Users(db.Model):
    # __tablename__ = 'users'
    userid = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String, unique=True)
    firstname = db.Column(db.String)
    lastname = db.Column(db.String)
    email = db.Column(db.String)
    phone = db.Column(db.String)
    profile = db.Column(db.Text)
    rating = db.Column(db.Integer, default=0)
    city = db.Column(db.String)
    state = db.Column(db.String)
    country = db.Column(db.String)


class Tags(db.Model):
    # __tablename__ = 'tags'
    tagid = db.Column(db.Integer, primary_key=True, autoincrement=True)
    tagname = db.Column(db.String)
    parenttagid = db.Column(db.Integer)


class LoginDetails(db.Model):
    # __tablename__ = 'logindetails'
    userid = db.Column(db.Integer, ForeignKey(Users.userid), primary_key=True)
    username = db.Column(db.Integer, ForeignKey(Users.userid), primary_key=True)
    passwordhash = db.Column(db.String(128))


class Questions(db.Model):
    # __tablename__ = 'questions'
    questionid = db.Column(db.Integer, autoincrement=True, primary_key=True)
    userid = db.Column(db.Integer, ForeignKey(Users.userid))
    tagid = db.Column(db.Integer, ForeignKey(Tags.tagid))
    title = db.Column(db.Text)
    question = db.Column(db.Text)
    timeposted = db.Column(db.DateTime, server_default=func.now())
    resolved = db.Column(db.Boolean, default=False)


class Answers(db.Model):
    # __tablename__ = 'answers'
    answerid = db.Column(db.Integer, autoincrement=True, primary_key=True)
    userid = db.Column(db.Integer, ForeignKey(Users.userid))
    questionid = db.Column(db.Integer, ForeignKey(Questions.questionid))
    timeposted = db.Column(db.DateTime, server_default=func.now())
    upvotes = db.Column(db.Integer, default=0)
    downvotes = db.Column(db.Integer, default=0)
    bestanswer = db.Column(db.Boolean, default=False)


class Upvotes(db.Model):
    # __tablename__ = 'upvotes'
    userid = db.Column(db.Integer, ForeignKey(Users.userid), primary_key=True)
    answerid = db.Column(db.Integer, ForeignKey(Answers.answerid), primary_key=True)


class Downvotes(db.Model):
    # __tablename__ = 'downvotes'
    userid = db.Column(db.Integer, ForeignKey(Users.userid), primary_key=True)
    answerid = db.Column(db.Integer, ForeignKey(Answers.answerid), primary_key=True)


# This if for the landing page
@app.route('/')
def hello_world():
    return render_template('index.html')
#     It knows where to find the templates


@app.route('/login', methods=['GET', 'POST'])
def login():
    # We send the LoginForm to login.html
    # After we receive the data, we can take action(Same with Signup)
    form = LoginForm()

    # If the form is submitted correctly
    if form.validate_on_submit():
        # This is when the form is submitted correctly
        return '<h1>' + form.username.data + " " + form.password.data + '</h1>'
    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        new_user = Users()
        new_user.username = form.username
        new_user.firstname = form.firstname
        new_user.lastname = form.lastname
        new_user.email = form.email
        new_user.phone = form.phone
        new_user.profile = form.profile
        new_user.city = form.city
        new_user.state = form.state
        new_user.country = form.country
        db.session.add(new_user)
        db.session.commit()
        result = db.engine.execute("select max(userid) from users")
        print(result)
        new_user_login_details = LoginDetails()
        new_user_login_details.userid = result
        new_user_login_details.username = form.username
        # new_user_login_details.passwordhash =
        # todo: generate password hash, write method for verifying the passwords with hashes
        db.session.add(new_user_login_details)
        db.session.commit()
        # todo: Enclose this in a try-except block

        return '<h1>' + form.username.data + form.firstname.data + '</h1>'
    return render_template('signup.html', form=form)


if __name__ == '__main__':
    # Base.metadata.create_all(engine)
    app.run(debug=True)
