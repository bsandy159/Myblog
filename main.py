from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_gravatar import Gravatar
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, NewRegister, Loginform, comment_box
from flask_gravatar import Gravatar
from functools import wraps
from flask_login import LoginManager
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
import os

Base=declarative_base()

login_manager = LoginManager()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager.init_app(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)

def adminonly(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(404)
        return f(*args, **kwargs)
    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # Create reference to the User object, the "posts" refers to the posts protperty in the User class.
    author = relationship("Users", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    comments=relationship("Comment", back_populates="parent_post")


class Users(UserMixin, db.Model):
    __tablename__="users"
    id=db.Column(db.Integer, primary_key=True)
    email=db.Column(db.String(250), unique=True)
    name=db.Column(db.String(250), nullable=False)
    password=db.Column(db.String(250), nullable=False)
    posts=relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")

class Comment(db.Model):
    __tablename__="comments"
    id=db.Column(db.Integer, primary_key=True)
    text=db.Column(db.String(500), nullable=False)
    author_id=db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author=relationship("Users", back_populates="comments")

    post_id=db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post=relationship("BlogPost", back_populates="comments")
    text = db.Column(db.Text, nullable=False)

db.create_all()


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, cuser=current_user)


@app.route('/register', methods=["POST", "GET"])
def register():
    form=NewRegister()
    if form.validate_on_submit():
        user=Users.query.filter_by(email=form.email.data).first()
        if user:
            flash("Email already in use, Please login")
            return redirect(url_for('login'))
        else:

            newuser=Users(
                email=form.email.data,
                name=form.name.data,
                password=generate_password_hash(form.password.data, method='pbkdf2:sha256',salt_length=8)
            )
            db.session.add(newuser)
            db.session.commit()
            login_user(newuser)
            return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form, cuser=current_user)


@app.route('/login', methods=["POST", "GET"])
def login():
    form=Loginform()
    if form.validate_on_submit():
        email=form.email.data
        user=Users.query.filter_by(email=email).first()
        if not user:
            flash("No users found, please register")
            return redirect(url_for('register'))
        elif not check_password_hash(user.password, form.password.data):
            flash("Wrong Password, Please try again")
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))
    return render_template("login.html", form=form, cuser=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    form=comment_box()
    requested_post = BlogPost.query.get(post_id)
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("Please login to continue")
            return redirect(url_for("login"))
        if form.comment.data:
            new_comment=Comment(
                text=form.comment.data,
                comment_author=current_user,
                parent_post=requested_post
            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for('show_post', post_id=post_id))
    return render_template("post.html", post=requested_post, cuser=current_user, form=form)


@app.route("/about")
def about():
    return render_template("about.html", cuser=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html", cuser=current_user)


@app.route("/new-post", methods=["POST", "GET"])
@adminonly
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, cuser=current_user)


@app.route("/edit-post/<int:post_id>",methods=["POST", "GET"])
@adminonly
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, cuser=current_user)


@app.route("/delete/<int:post_id>")
@adminonly
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))



if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000, debug=True)
