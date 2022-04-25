# This is for showing in login page
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Length, Email
from sqlalchemy import ForeignKey
from sqlalchemy.sql import func
from app import database as db

