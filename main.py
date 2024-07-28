import json
import os
from datetime import datetime, timedelta

from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView

import requests
from flask import Flask, render_template, redirect, url_for, flash, abort, request, current_app, jsonify, make_response, \
    Response, send_from_directory, send_file
from sqlalchemy.orm import joinedload

from werkzeug.security import generate_password_hash, check_password_hash
import logging
from flask_sqlalchemy import SQLAlchemy

from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

from flask_babel import Babel
from werkzeug.utils import secure_filename
from datetime import datetime

app = Flask(__name__)
babel = Babel(app)
login_manager = LoginManager(app)
login_manager.init_app(app)

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


@login_manager.user_loader
def load_user(user_id):
    user = Users.query.get(int(user_id))
    return user



app.config['SECRET_KEY'] = 'any-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class MyModelView(ModelView):
    def is_accessible(self):
        return True


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))



class Users(db.Model, UserMixin):
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(20), unique=True, nullable=False)
        email = db.Column(db.String(120), unique=True, nullable=False)
        password = db.Column(db.String(60), nullable=False)
        phone_number = db.Column(db.String(60), nullable=False)
        posts = db.relationship('Post', backref='author', lazy=True)
        comments = db.relationship('Comment', backref='author', lazy=True)
        likes = db.relationship('Like', backref='user', lazy=True)


class Post(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        title = db.Column(db.String(100), nullable=False)
        date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
        content = db.Column(db.Text, nullable=False)
        user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
        comments = db.relationship('Comment', backref='post', lazy=True)
        likes = db.relationship('Like', backref='post', lazy=True)

class Comment(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        content = db.Column(db.Text, nullable=False)
        date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
        user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
        post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
        likes = db.relationship('Like', backref='comment', lazy=True)

class Like(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
        post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=True)
        comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=True)




with app.app_context():
    db.create_all()

# Admin setup
admin = Admin(app)
admin.add_view(MyModelView(Users, db.session))
admin.add_view(MyModelView(Post, db.session))
admin.add_view(MyModelView(Comment, db.session))
admin.add_view(MyModelView(Like, db.session))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('name')
        email = request.form.get('email')
        phone_number = request.form.get('phone')
        password = request.form.get('password')

        new_user = Users(
            username=username,
            email=email,
            phone_number=phone_number,
            password=password,
        )

        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        flash('Registration successful!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = Users.query.filter_by(email=email).first()
        if user and user.password:
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    posts = Post.query.all()
    return render_template('dashboard.html', posts=posts)

@app.route('/create_post', methods=['POST'])
@login_required
def create_post():
    title = request.form.get('title')
    content = request.form.get('content')
    new_post = Post(title=title, content=content, author=current_user)
    db.session.add(new_post)
    db.session.commit()
    flash('Post created successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/create_comment/<int:post_id>', methods=['POST'])
@login_required
def create_comment(post_id):
    content = request.form.get('content')
    post = Post.query.get_or_404(post_id)
    new_comment = Comment(content=content, author=current_user, post=post)
    db.session.add(new_comment)
    db.session.commit()
    flash('Comment added successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/like_post/<int:post_id>')
@login_required
def like_post(post_id):
    post = Post.query.get_or_404(post_id)
    like = Like.query.filter_by(user_id=current_user.id, post_id=post.id).first()
    if like:
        db.session.delete(like)
        db.session.commit()
        flash('Like removed.', 'success')
    else:
        new_like = Like(user_id=current_user.id, post_id=post.id)
        db.session.add(new_like)
        db.session.commit()
        flash('Post liked!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/like_comment/<int:comment_id>')
@login_required
def like_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    like = Like.query.filter_by(user_id=current_user.id, comment_id=comment.id).first()
    if like:
        db.session.delete(like)
        db.session.commit()
        flash('Like removed.', 'success')
    else:
        new_like = Like(user_id=current_user.id, comment_id=comment.id)
        db.session.add(new_like)
        db.session.commit()
        flash('Comment liked!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(debug=True)
