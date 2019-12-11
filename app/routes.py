from flask import render_template, flash, redirect, url_for, request
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.urls import url_parse
from app import app, db
from app.models import User
from app.forms import *
from app.models import *
from app.forms import EditProfileForm


@app.route('/')
@app.route('/index')
@login_required
def index():
    posts = [
        {
            'body': 'Thanks for shopping on Gee-Sell!\n Please use the navigation links up top'
        },
    ]
    return render_template('index.html', title='Home', posts=posts)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)

def GenerateRandomPassword():
    string.ascii_letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    temp_password = ''
    for i in [1, 2, 3, 4]:
        temp_password += random.choice(string.ascii_letters)
    return temp_password

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route('/user/<username>')
@login_required
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    posts = [
        {'author': user, 'body': 'Yankees Hat, S, $40'},
        {'author': user, 'body': 'Nike Shoes, 8.5, $80'}
    ]
    return render_template('user.html', user=user, posts=posts)

@app.route('/add_item', methods=['GET', 'POST'])
@login_required
def add_item():
    form = ItemForm()
    if form.validate_on_submit():
        item = Item(type=form.type.data, size=form.size.data, price=form.price.data)
        db.session.add(item)
        db.session.commit()
        flash('You have added an Item to your profile!')
        return redirect(url_for('index'))
    return render_template('add_item.html', title='Add Item', form=form)

@app.route('/forgotPassword', methods=['GET', 'POST'])
def ForgotPassword():
    form = ForgotPasswordForm()
    users = User.query.all()
    if form.validate_on_submit():
        for x in users:
            if x.user == form.user.data:
                temp_password = GenerateRandomPassword()
                x.set_password(temp_password)
                db.session.commit()
                msg = Message('Forgot Password', recipients=[x.email])
                msg.body = ' '
                msg.html = 'Here is your temporary password: ' + temp_password
                mail.send(msg)
    return render_template('forgot_password.html', title='Forgot Password', form=form)

@app.route('/resetPassword', methods=['GET', 'POST'])
def ResetPassword():
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(user=current_user.user).first()
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been changed')
        return redirect(url_for('login'))
    return render_template('reset_password.html', title='Reset Password', form=form)

@app.route('/DeleteItem/<int:id>', methods=['GET', 'POST'])
def deleteItem(id):
    Item.query.filter_by(id=id).delete()
    db.session.commit()

    return redirect(url_for('index'))

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.about_me = form.about_me.data
        db.session.commit()
        flash('Your changes have been saved.')
        return redirect(url_for('edit_profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', title='Edit Profile',form=form)
