from flask import Flask, render_template, request, redirect, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, DateField
from wtforms.validators import DataRequired, Length, EqualTo, Email, NumberRange
from flask_login import current_user, login_user, login_required, logout_user
from wtforms.validators import ValidationError
from wikki import findBirths
from models import db, login, UserModel
from datetime import date


class LoginForm(FlaskForm):
    username = StringField(label="Enter username", validators=[DataRequired()])
    password = PasswordField(label="Enter password",validators=[DataRequired(), Length(min=8,max=20)])
    submit = SubmitField(label="Login")


class Signup(FlaskForm):
    email = StringField(label="Enter email", validators=[DataRequired(), Email()])
    username = StringField(label="Enter username", validators=[DataRequired(), Length(min=6, max=20)])
    password = PasswordField(label="Enter password", validators=[DataRequired(), Length(min=8, max=20)])
    confirm_password = PasswordField(label='Confirm Password', validators=[DataRequired(), EqualTo('password', message='Both password fields must be equal!')])
    submit = SubmitField(label="Signup")


class Search(FlaskForm):

    digit = IntegerField(label="Number of results", default=10, validators=[DataRequired(), NumberRange(min=1, max=20)])
    submit = SubmitField(label="Search")
    birthday = DateField(label="Enter your birthday", default=date.today(), validators=[DataRequired()])

    def validate_birthday(self, field):
        if field.data > date.today():
            flash("Choose a past or present date")
            raise ValidationError("Choose a past or present date")

app = Flask(__name__)
app.secret_key="a secret"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db/login.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
login.init_app(app)


def addUser(email, username, password):
    # check if email or username exits
    user = UserModel()
    user.set_password(password)
    user.username = username
    user.email = email
    db.session.add(user)
    db.session.commit()


@app.before_first_request
def create_table():
    db.create_all()
    user = UserModel.query.filter_by(username="test123").first()
    if user is None:
        addUser("test@testuser.com", "test123", "test12345")


@app.route('/birthday', methods=["POST", "GET"])
def same_birthday():
    form = Search()
    if form.validate_on_submit():
        if current_user.is_authenticated:
            if request.method == "POST":
                birthday = request.form["birthday"]
                birthday = birthday.split("-")
                digits = request.form["digit"]
                return render_template("search_result.html", form=form, myData=findBirths(f"{birthday[1]}/{birthday[2]}", birthday[0], digits))
            elif request.method == "GET":
                return render_template("home.html", form=form)
        flash("You have to login to see the results!!")
        return redirect("/")
    return render_template("home.html", form=form)

@app.route("/")
def root():
    form = Search()
    if current_user.is_authenticated:
        return render_template("home.html",form=form)

    return redirect("/login")


@app.route('/home')
def home():
    return redirect("/birthday")


@app.route('/login', methods=["POST", "GET"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        if request.method == "POST":
            username = request.form["username"]
            pw = request.form["password"]
            user = UserModel.query.filter_by(username=username).first()
            if user is not None and user.check_password(pw):
                login_user(user)
                flash(f"Welcome back {username}. Logged in successfully", "info")
                return redirect('/home')
    return render_template("login.html", form=form)

@app.route('/logout')
def logout():
    logout_user()
    flash("You have been logged out","info")
    return redirect('/login')


@app.route('/signup', methods=["POST", "GET"])
def signup():
    form = Signup()
    if form.validate_on_submit():
        if request.method == "POST":
            email = request.form["email"]
            pw = request.form["password"]
            username = request.form["username"]
            user = UserModel.query.filter_by(email=email).first()
            if user is not None:
                flash("Existing user... please log in!")
                return redirect('/login')
            else:
                addUser(email, username, pw)
                flash(f"Registered successfully... Logging in as {username}!")
                user = UserModel.query.filter_by(username=username).first()
                login_user(user)
                return redirect('/home')
    return render_template('signup.html', form=form)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
