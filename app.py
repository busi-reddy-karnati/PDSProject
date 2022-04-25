import sqlite3
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy

# Bootstrap for the app
from flask_bootstrap import Bootstrap

# For Using in signup and logins
from flask_wtf import FlaskForm

from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length

from classes import LoginForm
from classes import SignupForm

app = Flask(__name__)
app.config['SECRET_KEY'] = 'SecretKey'
# Link to my database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
Bootstrap(app)
database = SQLAlchemy(app)








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
        return '<h1>' + form.username.data + form.firstname.data + '</h1>'
    return render_template('signup.html', form=form)


if __name__ == '__main__':
    app.run(debug=True)
