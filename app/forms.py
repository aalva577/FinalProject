from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo
from app.models import *
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')

class ItemForm(FlaskForm):
    type = StringField('Type of clothing:', validators=[DataRequired()])
    size = StringField('size', validators=[DataRequired()])
    price = StringField('Price in $$:', validators=[DataRequired()])
    submit = SubmitField('Submit Item')

class ForgotPasswordForm(FlaskForm):
    user = StringField('Enter username', validators=[DataRequired()])
    submit = SubmitField('Send Email')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Enter new password', validators=[DataRequired()])
    password2 = PasswordField('Repeat new password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Change password')

class DeleteItemForm(FlaskForm):
    type = StringField('Enter Item type to delete', validators=[DataRequired()])
    submit = SubmitField('Delete')

class EditProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    about_me = TextAreaField('About me', validators=[Length(min=0, max=140)])
    submit = SubmitField('Submit')
