import sqlite3
from flask import Flask, render_template, flash, url_for, redirect, session, request
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


class UpdateProfileForm(FlaskForm):
    firstname = StringField('First Name', validators=[InputRequired()])
    lastname = StringField('Last Name', validators=[InputRequired()])
    email = StringField('Email', validators=[InputRequired()])
    phone = StringField('Phone', validators=[InputRequired()])
    city = StringField('City', validators=[InputRequired()])
    state = StringField('State', validators=[InputRequired()])
    country = StringField('Country', validators=[InputRequired()])
    profile = TextAreaField('Profile', validators=[InputRequired()])


class SearchQuestionForm(FlaskForm):
    search_string = StringField('', validators=[InputRequired()])


# This if for the landing page
@app.route('/')
def landing_page():
    return render_template('index.html')


@app.route('/home')
def home():
    return render_template('index.html')


@app.route('/edit-profile', methods=['POST', 'GET'])
def edit_profile():
    user = Users.query.filter_by(userid=session.get('userid')).first()
    form = UpdateProfileForm()
    if form.validate_on_submit():
        user.firstname = form.firstname.data
        user.lastname = form.lastname.data
        user.email = form.email.data
        user.phone = form.phone.data
        user.city = form.city.data
        user.state = form.state.data
        user.country = form.country.data
        user.profile = form.profile.data
        # print(form.profile.data)
        db.session.commit()
        return redirect(url_for('home'))
    form.firstname.data = user.firstname
    form.lastname.data = user.lastname
    form.email.data = user.email
    form.phone.data = user.phone
    form.city.data = user.city
    form.state.data = user.state
    form.country.data = user.country
    form.profile.data = user.profile
    return render_template('edit_profile.html', form=form)


@app.route('/profile/<userid>', methods=['POST', 'GET'])
def profile(userid):
    user = Users.query.filter_by(userid=userid).first()
    return render_template('show_profile.html', user=user)


@app.route('/ask_question', methods=['GET', 'POST'])
def ask_question():
    form = QuestionForm()
    form.tag.choices = [(tag.tagid, tag.tagname) for tag in Tags.query.all()]
    if form.validate_on_submit():
        title = form.title.data
        question = form.question.data
        tagid = form.tag.data
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

        return render_template('error.html', messages=["Login details wrong. Try again"])

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
    search_string = session.get('search_string')
    questions = Questions.query.all()
    ind = 0
    usernames = []
    questions = [question for question in questions if search_string in question.question]
    # for question in questions:
    #     if search_string not in question.question:
    #         questions.pop(question)
    #         # print(index)
    #         # questions.pop(ind)
    #     # else:
    #     #     ind += 1
    for question in questions:
        user = Users.query.filter_by(userid=question.userid).first()
        usernames.append(user.username)
    # print(questions)
    return render_template('questions.html', questions=questions, usernames=usernames)




@app.route('/show_answers/<question_id>', methods=['GET', 'POST'])
def show_answers(question_id):
    session['question_id'] = question_id
    question_id = int(question_id)
    answers = Answers.query.filter_by(questionid=question_id).all()
    usernames = []
    list_of_upvotes = []
    list_of_downvotes = []
    for answer in answers:
        user = Users.query.filter_by(userid=answer.userid).first()
        user_upvote = Upvotes.query.filter_by(userid=session.get('userid'), answerid=answer.answerid).first()
        if user_upvote:
            list_of_upvotes.append(True)
        else:
            list_of_upvotes.append(False)
        user_downvote = Downvotes.query.filter_by(userid=session.get('userid'), answerid=answer.answerid).first()
        if user_downvote:
            list_of_downvotes.append(True)
        else:
            list_of_downvotes.append(False)
        usernames.append(user.username)

    question = Questions.query.filter_by(questionid=question_id).first()
    # print(data) data is an array of objects with answerid, userid, questionid and timeposted
    return render_template('answers.html',
                           answers=answers,
                           usernames=usernames,
                           list_of_upvotes=list_of_upvotes,
                           list_of_downvotes=list_of_downvotes,
                           question=question)


# This is similar to show_answers but without a get parameter
@app.route('/show_answers2', methods=['GET', 'POST'])
def show_answers2():
    question_id = int(session.get('question_id'))
    answers = Answers.query.filter_by(questionid=question_id).all()
    usernames = []
    list_of_upvotes = []
    list_of_downvotes = []
    for answer in answers:
        user = Users.query.filter_by(userid=answer.userid).first()
        user_upvote = Upvotes.query.filter_by(userid=session.get('userid'), answerid=answer.answerid).first()
        if user_upvote:
            list_of_upvotes.append(True)
        else:
            list_of_upvotes.append(False)
        user_downvote = Downvotes.query.filter_by(userid=session.get('userid'), answerid=answer.answerid).first()
        if user_downvote:
            list_of_downvotes.append(True)
        else:
            list_of_downvotes.append(False)
        usernames.append(user.username)

    question = Questions.query.filter_by(questionid=question_id).first()
    # print(data) data is an array of objects with answerid, userid, questionid and timeposted
    return render_template('answers.html',
                           answers=answers,
                           usernames=usernames,
                           list_of_upvotes=list_of_upvotes,
                           list_of_downvotes=list_of_downvotes,
                           question=question)


@app.route('/upvote-answer/<answerid>', methods=['POST', 'GET'])
def upvote_answer(answerid):
    answer = Answers.query.filter_by(answerid=answerid).first()
    upvote_exists = Upvotes.query.filter_by(userid=session.get('userid'), answerid=answerid).first()
    if upvote_exists:
        db.session.delete(upvote_exists)
        answer.upvotes -= 1
        user = Users.query.filter_by(userid=answer.userid).first()
        user.rating -= 2
        db.session.commit()
    else:
        new_upvote = Upvotes()
        new_upvote.userid = session.get('userid')
        new_upvote.answerid = answerid
        db.session.add(new_upvote)
        answer.upvotes += 1
        user = Users.query.filter_by(userid=answer.userid).first()
        user.rating += 2
        db.session.commit()
    return redirect(url_for('show_answers2'))


@app.route('/downvote-answer/<answerid>', methods=['POST', 'GET'])
def downvote_answer(answerid):
    downvote_exists = Downvotes.query.filter_by(userid=session.get('userid'), answerid=answerid).first()
    answer = Answers.query.filter_by(answerid=answerid).first()
    if downvote_exists:
        db.session.delete(downvote_exists)
        answer.downvotes -= 1
        user = Users.query.filter_by(userid=answer.userid).first()
        user.rating += 2
        db.session.commit()
    else:
        new_downvote = Downvotes()
        new_downvote.userid = session.get('userid')
        new_downvote.answerid = answerid
        db.session.add(new_downvote)
        user = Users.query.filter_by(userid=answer.userid).first()
        user.rating -= 2
        answer.downvotes += 1
        db.session.commit()
    return redirect(url_for('show_answers2'))


@app.route('/best-answer/<answerid>', methods=['POST', 'GET'])
def best_answer(answerid):
    answer = Answers.query.filter_by(answerid=answerid).first()
    best_answer_before = Answers.query.filter_by(bestanswer=True).first()

    question = Questions.query.filter_by(questionid=answer.questionid).first()
    question.resolved = True
    if best_answer_before:
        '''If there is a best answer already, then remove it's best answer status'''
        best_answer_before.bestanswer = False
        old_user = Users.query.filter_by(userid=best_answer_before.userid).first()
        old_user.rating -= 5
    new_user = Users.query.filter_by(userid=answer.userid).first()
    new_user.rating += 5
    answer.bestanswer = True
    db.session.commit()
    return redirect(url_for('show_answers2'))


@app.route('/search_question', methods=['GET', 'POST'])
def search_question():
    form = SearchQuestionForm()
    if form.validate_on_submit():
        string_data = form.search_string.data
        # string_data = string_data.replace(" ", "%20")
        session['search_string'] = string_data
        return redirect(url_for('show_questions'))
    return render_template('search_question.html', form=form)


class AnswerForm(FlaskForm):
    answer = TextAreaField("", validators=[InputRequired()])


@app.route('/answer_question2', methods=['GET', 'POST'])
def answer_question2():
    question_id = session.get('answer_question_id')
    form = AnswerForm()
    question_id = int(question_id)
    question = Questions.query.filter_by(questionid=question_id).first()
    if form.validate_on_submit():
        answer = Answers()
        answer.upvotes = 0
        answer.downvotes = 0
        answer.questionid = question_id
        answer.userid = session.get('userid')
        answer.bestanswer = False
        answer.answer = form.answer.data
        db.session.add(answer)
        db.session.commit()
        session['question_id'] = question_id
        return redirect(url_for('show_answers2'))
    question_text = question.question
    return render_template('answer_question.html', form=form, question_text=question_text)


@app.route('/answer_question/<question_id>', methods=['GET', 'POST'])
def answer_question(question_id):
    session['answer_question_id'] = question_id
    return redirect(url_for('answer_question2'))




if __name__ == '__main__':
    app.run(debug=True)
