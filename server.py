from flask import Flask, render_template, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, BooleanField
from wtforms.validators import InputRequired, Email, EqualTo, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user




app = Flask(__name__)
app.config["SECRET_KEY"] = "thisisasecret"

app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///C:\\sqlite\\user.db'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    gender = db.Column(db.String(10))
    phone = db.Column(db.String(20))


    def __init__(self,  username, email ,password, gender, phone):

        self.username = username
        self.email = email
        self.password = password
        self.gender = gender
        self.phone = phone








@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(int(user_id))




@app.route("/")
def index():
    return render_template("index.html")


class signupform(FlaskForm):

    username = StringField("Username", validators=[InputRequired("Username required"), Length(min=4 ,max=10,message="username should between 5 to 8 characters")])
    email = StringField("Email", validators=[InputRequired(message="Enter your email"), Email(message="an Invalid Email account name!")])
    password = PasswordField("Password", validators=[InputRequired(message="Enter your password"), Length(min=5, max=10,message="password is not strong!")])
    confirm = PasswordField("Confirm Password", validators=[InputRequired("confirm your password"),EqualTo("password",message="Your password did not match!")])
    gender = SelectField("Gender",choices=[("Male", "Male"),("Female", "Female")])
    phone = StringField("Phone Number", validators=[InputRequired(message="Enter your phone number"), Length(min=10, max=10, message="Invalid phone number length should be 10")])



class loginform(FlaskForm):
    username = StringField("Username", validators=[InputRequired(message="Enter username")])
    password = PasswordField("password", validators=[InputRequired(message="password is reqiuired")])
    remember = BooleanField('remember me')


@app.route("/signup", methods=["POST", "GET"])
def signup():
    if current_user.is_authenticated:
        # if user is logged in we get out of here
        return redirect(url_for('index'))
    form = signupform()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None:
            flash('Username already exists.')
            return redirect(url_for('signup'))
        mail = User.query.filter_by(email=form.email.data).first()
        if mail is not None:
            flash(' email already exists.')
            return redirect(url_for('signup'))
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(form.username.data, form.email.data, hashed_password,  form.gender.data, form.phone.data)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("welcome"))

    return render_template("signup.html", form=form)


@app.route("/welcome")
def welcome():

    flash("You Have Successfully registered! ")
    return render_template("welcome.html")


@app.route("/login", methods=["POST", "GET"])
def login():
    form = loginform()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if not user:
            flash('Username not found !')
        if user:
            if not check_password_hash(user.password, form.password.data):
                flash('Wrong Password typed!')
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))

    return render_template("login.html", form=form)



@app.route("/logout")
@login_required
def logout():
    flash("You have sucessfully Logged out!")
    logout_user()
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", name=current_user.username)



db.create_all()

if __name__ == "__main__":
    app.run(debug=True)
