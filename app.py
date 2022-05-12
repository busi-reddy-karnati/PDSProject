import sqlite3
from flask import Flask, render_template, flash, url_for, redirect, session
from flask_sqlalchemy import SQLAlchemy
from bcrypt import hashpw, checkpw, gensalt

# Bootstrap for the app
from flask_bootstrap import Bootstrap

# For Using in signup and logins
from flask_wtf import FlaskForm

from wtforms import StringField, PasswordField, BooleanField, SelectField
from wtforms import TextAreaField
from wtforms.validators import InputRequired, Email, Length, ValidationError
from wtforms.validators import NumberRange

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


# engine = create_engine('sqlite:///database.db')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=5, max=80)])
    remember = BooleanField('Remember me')


class SignupForm(FlaskForm):
    # todo: validate phone number
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=5, max=80)])
    firstname = StringField('First Name', validators=[InputRequired()])
    lastname = StringField('Last Name', validators=[InputRequired()])
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid Email')])
    phone = StringField('Phone', validators=[InputRequired(), Length(min=10, max=10)])
    profile = StringField('Profile(A short Description)', validators=[InputRequired()])
    city = StringField('City', validators=[InputRequired()])
    state = StringField('State', validators=[InputRequired()])
    country = StringField('Country', validators=[InputRequired()])

    def validate_username(self, username):
        user = Users.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username in Use, try another')


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
    answer = db.Column(db.Text)
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


class QuestionForm(FlaskForm):
    title = TextAreaField('Title', validators=[InputRequired()])
    question = TextAreaField('Question', validators=[InputRequired()])
    tag = SelectField('Tag', choices=[], validators=[InputRequired()])


# This if for the landing page
@app.route('/')
def landing_page():
    return render_template('index.html')


@app.route('/home')
def home():
    return render_template('index.html')


@app.route('/ask_question', methods=['GET', 'POST'])
def ask_question():
    form = QuestionForm()
    form.tag.choices = [(tag.tagid, tag.tagname) for tag in Tags.query.all()]
    if form.validate_on_submit():
        title = form.title.data
        question = form.question.data
        tagid = form.tag.data
        # todo: Because of session information while testing, we are hard coding this, change later
        userid = session.get('userid')
        # userid = 12
        resolved = False
        new_question = Questions()
        new_question.question = question
        new_question.userid = userid
        new_question.tagid = tagid
        new_question.title = title
        new_question.resolved = False
        db.session.add(new_question)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('ask_question.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    # We send the LoginForm to login.html
    # After we receive the data, we can take action(Same with Signup)
    form = LoginForm()
    if session.get('userid'):
        session.pop('userid')

    # If the form is submitted correctly
    if form.validate_on_submit():
        user = LoginDetails.query.filter_by(username=form.username.data).first()
        if user:
            password = form.password.data
            if checkpw(password.encode('utf-8'), user.passwordhash):
                session['userid'] = user.userid
                session['username'] = user.username
                return redirect(url_for('home'))
                # return '<h1>' + "Correct and Matching" + '</h1>'
        # Instead of this, do an error message
        # todo: show an error message instead of incorrect
        return '<h1> Incorrect </h1>'

    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        new_user = Users()
        new_user.username = form.username.data
        new_user.firstname = form.firstname.data
        new_user.lastname = form.lastname.data
        new_user.email = form.email.data
        new_user.phone = form.phone.data
        new_user.profile = form.profile.data
        new_user.city = form.city.data
        new_user.state = form.state.data
        new_user.country = form.country.data
        # result = list(db.engine.execute("select max(userid) from users"))
        userid = 0
        result = db.session.execute('select max(userid) from users').fetchall()
        if not result:
            result = 0
        else:
            result = result[0][0]
        if not result:
            result = 0
        userid = result + 1
        new_user_login_details = LoginDetails()
        new_user_login_details.userid = userid
        new_user_login_details.username = form.username.data
        password = form.password.data
        password_hash = hashpw(password.encode('utf-8'), gensalt())
        new_user_login_details.passwordhash = password_hash
        db.session.add(new_user)
        db.session.add(new_user_login_details)
        db.session.commit()
        # flash('Signup Successful')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)


@app.route('/show_questions', methods=['GET', 'POST'])
def show_questions():
    search_string = "What is"
    # todo: replace the search_string with actual string
    questions = Questions.query.all()
    index = 0
    usernames = []
    for question in questions:
        if search_string not in question.question:
            print(index)
            questions.pop(index)
        else:
            index += 1
    for question in questions:
        user = Users.query.filter_by(userid=question.userid).first()
        usernames.append(user.username)
    # print(questions)
    return render_template('questions.html', questions=questions, usernames=usernames)


@app.route('/show_answers', methods=['GET', 'POST'])
def show_answers():
    # todo: replace the question_id with actual question_id that was asked
    question_id = 1
    answers = Answers.query.filter_by(questionid=question_id).all()
    usernames = []
    for answer in answers:
        user = Users.query.filter_by(userid=answer.userid).first()
        usernames.append(user.username)

    # print(data) data is an array of objects with answerid, userid, questionid and timeposted
    return render_template('answers.html', answers=answers, usernames=usernames)


if __name__ == '__main__':
    app.run(debug=True)
