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
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

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

followers = db.Table('followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('users.id')),
    db.Column('followed_id', db.Integer, db.ForeignKey('users.id'))
)

class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    phone_number = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    verified = db.Column(db.Boolean, nullable=False, default=False)
    posts = db.relationship('Post', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)
    likes = db.relationship('Like', backref='user', lazy=True)
    followed = db.relationship(
        'Users', secondary=followers,
        primaryjoin=(followers.c.follower_id == id),
        secondaryjoin=(followers.c.followed_id == id),
        backref=db.backref('followers', lazy='dynamic'), lazy='dynamic')

    def is_following(self, user):
        return self.followed.filter(followers.c.followed_id == user.id).count() > 0

    def follow(self, user):
        if not self.is_following(user):
            self.followed.append(user)

    def unfollow(self, user):
        if self.is_following(user):
            self.followed.remove(user)



class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    content = db.Column(db.Text, nullable=False)
    images = db.Column(db.Text)  # Store comma-separated filenames
    video = db.Column(db.String(255))  # Store the filename of the uploaded video
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    comments = db.relationship('Comment', backref='post', lazy=True, cascade="all, delete-orphan")
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

class PostImage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)




with app.app_context():
    db.create_all()

# Admin setup
admin = Admin(app)
admin.add_view(MyModelView(Users, db.session))
admin.add_view(MyModelView(Post, db.session))
admin.add_view(MyModelView(PostImage, db.session))
admin.add_view(MyModelView(Comment, db.session))
admin.add_view(MyModelView(Like, db.session))


# Serializer for generating and verifying tokens
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

def send_email(to_email, subject, body):
    from_email = 'zyadwael2009@gmail.com'
    password = 'vglf vbhn yxuc jilg'

    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(from_email, password)
        text = msg.as_string()
        server.sendmail(from_email, to_email, text)
        server.quit()
        print(f'Email sent to {to_email}')
    except Exception as e:
        print(f'Failed to send email to {to_email}. Error: {e}')





@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('name')
        email = request.form.get('email')
        phone_number = request.form.get('phone')
        password = request.form.get('password')
        role = "user"
        verified = False


        new_user = Users(
            username=username,
            email=email,
            phone_number=phone_number,
            password=password,
            role=role,
            verified=verified
        )

        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        flash('Registration successful! Please check your email to verify your account.', 'success')

        token = s.dumps(email, salt='email-confirm')
        link = url_for('confirm_email', token=token, _external=True)
        send_email(new_user.email, 'Welcome To Our Blog', f'Please verify your account by clicking on the link: {link}')

        return redirect(url_for('dashboard'))
    return render_template('register.html')


@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except SignatureExpired:
        return '<h1>The token is expired!</h1>'
    except BadSignature:
        return '<h1>The token is invalid!</h1>'

    user = Users.query.filter_by(email=email).first_or_404()
    if user.verified:
        flash('Account already verified.', 'success')
    else:
        user.verified = True
        db.session.commit()
        flash('Account verified successfully!', 'success')

    return redirect(url_for('dashboard'))

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
    posts = Post.query.order_by(Post.date_posted.desc()).all()
    users = Users.query.all()  # Get all users
    return render_template('dashboard.html', posts=posts, users=users)



@app.route('/follow/<username>')
@login_required
def follow(username):
    user = Users.query.filter_by(username=username).first()
    if user is None:
        flash('User not found.', 'danger')
        return redirect(url_for('dashboard'))
    if user == current_user:
        flash('You cannot follow yourself!', 'danger')
        return redirect(url_for('dashboard'))
    current_user.follow(user)
    db.session.commit()
    flash(f'You are now following {username}!', 'success')
    return redirect(url_for('user_profile', username=username))

@app.route('/unfollow/<username>')
@login_required
def unfollow(username):
    user = Users.query.filter_by(username=username).first()
    if user is None:
        flash('User not found.', 'danger')
        return redirect(url_for('dashboard'))
    if user == current_user:
        flash('You cannot unfollow yourself!', 'danger')
        return redirect(url_for('dashboard'))
    current_user.unfollow(user)
    db.session.commit()
    flash(f'You have unfollowed {username}.', 'success')
    return redirect(url_for('user_profile', username=username))
@app.route('/user/<username>')
@login_required
def user_profile(username):
    user = Users.query.filter_by(username=username).first_or_404()
    print(user)  # Debug print
    return render_template('user_profile.html', user=user)

@app.route('/post')
@login_required
def post():
    return render_template("create_post.html")


@app.route('/create_post', methods=['POST'])
@login_required
def create_post():
    title = request.form.get('title')
    content = request.form.get('content')

    # Handle image uploads
    images = request.files.getlist('images')
    image_filenames = []
    for image in images:
        if image and image.filename != '':
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            image_filenames.append(filename)

    images_filenames_str = ','.join(image_filenames)

    # Handle video upload
    video = request.files.get('video')
    video_filename = None
    if video and video.filename != '':
        video_filename = secure_filename(video.filename)
        video.save(os.path.join(app.config['UPLOAD_FOLDER'], video_filename))

    new_post = Post(
        title=title,
        content=content,
        images=images_filenames_str,
        video=video_filename,
        author=current_user
    )
    db.session.add(new_post)
    db.session.commit()
    flash('Post created successfully!', 'success')
    return redirect(url_for('dashboard'))


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)




@app.route('/create_comment/<int:post_id>', methods=['POST'])
@login_required
def create_comment(post_id):
    content = request.form.get('content')
    post = Post.query.get_or_404(post_id)
    new_comment = Comment(content=content, author=current_user, post=post)
    db.session.add(new_comment)
    db.session.commit()

    response = {
        'content': new_comment.content,
        'author': new_comment.author.username,
        'date_posted': new_comment.date_posted.strftime('%Y-%m-%d %H:%M:%S')
    }
    return jsonify(response)

@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    if request.method == 'POST':
        post.title = request.form.get('title')
        post.content = request.form.get('content')

        # Handle image uploads
        images = request.files.getlist('images')
        if images:
            image_filenames = []
            for image in images:
                if image and image.filename != '':
                    filename = secure_filename(image.filename)
                    image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    image_filenames.append(filename)
            post.images = ','.join(image_filenames)

        # Handle video upload
        video = request.files.get('video')
        if video and video.filename != '':
            video_filename = secure_filename(video.filename)
            video.save(os.path.join(app.config['UPLOAD_FOLDER'], video_filename))
            post.video = video_filename

        db.session.commit()
        flash('Post updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('edit_post.html', post=post)


@app.route("/post/<int:post_id>/delete", methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        flash('You do not have permission to delete this post', 'danger')
        return redirect(url_for('post', post_id=post.id))

    # All associated comments will be deleted automatically due to cascade
    db.session.delete(post)
    db.session.commit()
    flash('The post has been deleted!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/edit_comment/<int:comment_id>', methods=['GET', 'POST'])
@login_required
def edit_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if comment.author != current_user:
        abort(403)
    if request.method == 'POST':
        comment.content = request.form.get('content')
        db.session.commit()
        flash('Comment updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('edit_comment.html', comment=comment)


@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if comment.author != current_user:
        abort(403)
    db.session.delete(comment)
    db.session.commit()
    flash('Comment deleted successfully!', 'success')
    return redirect(url_for('dashboard'))


@app.route('/like_post/<int:post_id>', methods=['POST'])
@login_required
def like_post(post_id):
    post = Post.query.get_or_404(post_id)
    like = Like.query.filter_by(user_id=current_user.id, post_id=post.id).first()

    if like:
        db.session.delete(like)
        db.session.commit()
        like_status = 'removed'
    else:
        new_like = Like(user_id=current_user.id, post_id=post.id)
        db.session.add(new_like)
        db.session.commit()
        like_status = 'added'

    # Return updated like count and status as JSON
    updated_like_count = Like.query.filter_by(post_id=post.id).count()
    return jsonify({'likes': updated_like_count, 'status': like_status})

@app.route('/like_comment/<int:comment_id>', methods=['POST'])
@login_required
def like_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    like = Like.query.filter_by(user_id=current_user.id, comment_id=comment.id).first()
    if like:
        db.session.delete(like)
        db.session.commit()
        action = 'removed'
    else:
        new_like = Like(user_id=current_user.id, comment_id=comment.id)
        db.session.add(new_like)
        db.session.commit()
        action = 'added'
    return jsonify({'likes': comment.likes.count(), 'action': action})


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


@app.route('/settings', methods=['GET'])
@login_required
def settings():
    return render_template('settings.html')

@app.route('/update_email', methods=['POST'])
@login_required
def update_email():
    new_email = request.form.get('new_email')
    password = request.form.get('password')

    user = Users.query.get(current_user.id)

    if user and user.password :
        user.email = new_email
        user.verified = False
        db.session.commit()

        # Send verification email
        token = s.dumps(new_email, salt='email-confirm')
        link = url_for('confirm_email', token=token, _external=True)
        send_email(new_email, 'Confirm your new email address', f'Please verify your new email by clicking on the link: {link}')

        flash('Email updated! Please verify your new email address.', 'success')
    else:
        flash('Incorrect password. Please try again.', 'danger')

    return redirect(url_for('settings'))

@app.route('/update_password', methods=['POST'])
@login_required
def update_password():
    old_password = request.form.get('old_password')
    new_password = request.form.get('new_password')

    user = Users.query.get(current_user.id)

    if user and old_password:
        user.password = new_password
        db.session.commit()
        flash('Password updated successfully!', 'success')
    else:
        flash('Incorrect old password. Please try again.', 'danger')

    return redirect(url_for('settings'))

if __name__ == "__main__":
    app.run(debug=True)
