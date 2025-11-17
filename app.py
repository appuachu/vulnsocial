from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import jwt
import secrets
import random   # Add this import
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response
import string
import random


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key_here'  # Add JWT secret key

db = SQLAlchemy(app)
# Create upload directory if it doesn't exist
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    mobile = db.Column(db.String(15), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    bio = db.Column(db.String(500), default='')
    profile_pic = db.Column(db.String(200), default='default.jpg')
    is_private = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    reset_otp = db.Column(db.String(6), nullable=True)  # New field for OTP
    reset_otp_expiry = db.Column(db.DateTime, nullable=True)  # New field for OTP expiry
    followers = db.relationship('Follow',
                               foreign_keys='Follow.following_id',
                               backref='following_user',
                               lazy='dynamic')
    following = db.relationship('Follow',
                               foreign_keys='Follow.follower_id',
                               backref='follower_user',
                               lazy='dynamic')

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_uid = db.Column(db.String(8), unique=True, nullable=False, default=lambda: generate_alphanumeric_id())  # New field
    image_path = db.Column(db.String(200), nullable=False)
    caption = db.Column(db.String(500))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    user = db.relationship('User', backref=db.backref('posts', lazy=True))
    likes = db.relationship('Like', backref='post', lazy=True, cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='post', lazy=True, cascade='all, delete-orphan')

class Follow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    follower_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    following_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    like_uid = db.Column(db.String(8), unique=True, nullable=False, default=lambda: generate_alphanumeric_id())  # New field
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('likes', lazy=True))

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    comment_uid = db.Column(db.String(8), unique=True, nullable=False, default=lambda: generate_alphanumeric_id())  # New field
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    text = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('comments', lazy=True))

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    text = db.Column(db.String(1000), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    deleted_for_sender = db.Column(db.Boolean, default=False)
    deleted_for_receiver = db.Column(db.Boolean, default=False)
    deleted_for_everyone = db.Column(db.Boolean, default=False)
    is_read = db.Column(db.Boolean, default=False)

class ProfileView(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    viewer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    profile_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    viewed_at = db.Column(db.DateTime, default=datetime.utcnow)

@app.context_processor
def inject_user():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            pending_requests_count = Follow.query.filter_by(following_id=user.id, status='pending').count()
            unread_messages_count = Message.query.filter_by(receiver_id=user.id, is_read=False).count()
            return dict(current_user=user,
                       pending_requests_count=pending_requests_count,
                       unread_messages_count=unread_messages_count)
    return dict(current_user=None, pending_requests_count=0, unread_messages_count=0)


def encode_user_id(user_id):
    """Encode user ID to base64 for URLs"""
    return base64.b64encode(str(user_id).encode()).decode()

def decode_user_id(encoded_id):
    """Decode base64 user ID from URL"""
    try:
        decoded_bytes = base64.b64decode(encoded_id)
        return int(decoded_bytes.decode('utf-8'))
    except (ValueError, base64.binascii.Error, UnicodeDecodeError):
        return None

def generate_alphanumeric_id(length=8):
    """Generate a random 8-character alphanumeric ID"""
    characters = string.ascii_letters + string.digits  # A-Z, a-z, 0-9
    return ''.join(random.choice(characters) for _ in range(length))
# Routes
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect(url_for('login'))

    # Get posts for feed: posts from public accounts or from followed private accounts
    following_ids = [f.following_id for f in Follow.query.filter_by(follower_id=user.id, status='accepted').all()]

    # Include user's own posts and posts from followed users or public accounts
    feed_posts = Post.query.filter(
        (Post.user_id == user.id) |
        ((Post.user_id.in_(following_ids)) & (Post.is_active == True)) |
        ((Post.user_id.notin_(following_ids)) & (User.is_private == False) & (Post.is_active == True))
    ).join(User).order_by(Post.created_at.desc()).all()

    # Add like counts and comment counts to each post
    posts_with_counts = []
    for post in feed_posts:
        like_count = Like.query.filter_by(post_id=post.id).count()
        comment_count = Comment.query.filter_by(post_id=post.id).count()

        posts_with_counts.append({
            'post': post,
            'like_count': like_count,
            'comment_count': comment_count
        })

    return render_template('index.html',
                         user=user,
                         posts_with_counts=posts_with_counts,
                         session=session)

# @app.route('/create_post', methods=['POST'])
# def create_post():
#     if 'user_id' not in session:
#         return jsonify({'success': False, 'error': 'Not logged in'})
#
#     caption = request.form.get('caption', '')
#
#     if 'image' not in request.files:
#         return jsonify({'success': False, 'error': 'No image selected'})
#
#     file = request.files['image']
#     if file.filename == '':
#         return jsonify({'success': False, 'error': 'No image selected'})
#
#     if not file.content_type.startswith('image/'):
#         return jsonify({'success': False, 'error': 'Please upload an image file'})
#
#     filename = f"post_{session['user_id']}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{file.filename}"
#     file_path = os.path.join(app.config['UPLOAD_FOLDER'], filenfame)
#
#     try:
#         file.save(file_path)
#         post = Post(image_path=filename, caption=caption, user_id=session['user_id'])
#         db.session.add(post)
#         db.session.commit()
#         return jsonify({'success': True, 'message': 'Post created successfully!'})
#     except Exception as e:
#         return jsonify({'success': False, 'error': str(e)})

def get_post_by_uid(post_uid):
    return Post.query.filter_by(post_uid=post_uid).first()

def get_like_by_uid(like_uid):
    return Like.query.filter_by(like_uid=like_uid).first()

def get_comment_by_uid(comment_uid):
    return Comment.query.filter_by(comment_uid=comment_uid).first()



@app.route('/toggle_post/<string:post_uid>', methods=['POST'])
def toggle_post(post_uid):
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not logged in'})

    post = get_post_by_uid(post_uid)
    if post:
        # REMOVE THIS CHECK - Allow toggle of any post (vulnerability preserved)
        # if post.user_id != session['user_id']:
        #     return jsonify({'success': False, 'error': 'You can only modify your own posts'})

        post.is_active = not post.is_active
        db.session.commit()
        status = "enabled" if post.is_active else "disabled"
        return jsonify({'success': True, 'message': f'Post {status} successfully'})

    return jsonify({'success': False, 'error': 'Post not found'})

@app.route('/view_comments/<string:post_uid>')
def view_comments(post_uid):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    post = get_post_by_uid(post_uid)
    if not post:
        flash('Post not found')
        return redirect(url_for('index'))

    return render_template('comments.html', post=post, user=User.query.get(session['user_id']))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        mobile = request.form['mobile']
        password = request.form['password']

        # FIX: Use default method or specify pbkdf2:sha256
        hashed_password = generate_password_hash(password)  # Remove method parameter

        user = User(username=username, email=email, mobile=mobile, password=hashed_password)
        db.session.add(user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('register.html')

@app.context_processor
def inject_user():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            pending_requests_count = Follow.query.filter_by(following_id=user.id, status='pending').count()
            unread_messages_count = Message.query.filter_by(receiver_id=user.id, is_read=False).count()
            return dict(current_user=user,
                       pending_requests_count=pending_requests_count,
                       unread_messages_count=unread_messages_count)
    return dict(current_user=None, pending_requests_count=0, unread_messages_count=0)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # VULNERABILITY 1: Classic SQL Injection - String concatenation
        # This is extremely vulnerable to SQL injection
        query1 = f"SELECT * FROM user WHERE username = '{username}' AND password = '{password}'"

        # VULNERABILITY 2: OR 1=1 injection
        # This allows bypassing authentication with ' OR '1'='1
        query2 = f"SELECT * FROM user WHERE username = '{username}'"

        # VULNERABILITY 3: Comment-based injection
        # This allows bypassing with: admin' --
        query3 = f"SELECT * FROM user WHERE username = '{username}' -- AND password = '{password}'"

        # VULNERABILITY 4: Union-based injection
        query4 = f"SELECT id, username, password FROM user WHERE username = '{username}' UNION SELECT 1, 'admin', 'password' -- "

        try:
            # VULNERABILITY: Direct SQL execution (most dangerous)
            # This executes raw SQL without any sanitization
            from sqlalchemy import text
            dangerous_query = text(f"SELECT * FROM user WHERE username = '{username}' AND password = '{password}'")
            result = db.session.execute(dangerous_query).fetchone()

            if result:
                user_dict = dict(result)
                session['user_id'] = user_dict['id']
                return redirect(url_for('index'))

        except Exception as e:
            print(f"SQL Injection attempt detected: {e}")

        # VULNERABILITY 5: Blind SQL Injection
        # Check if user exists without proper validation
        user_exists_query = text(f"SELECT id FROM user WHERE username = '{username}'")
        user_exists = db.session.execute(user_exists_query).fetchone()

        if user_exists:
            # VULNERABILITY: Timing attack - check password character by character
            flash('User login!', 'info')

        # VULNERABILITY 6: Second-order SQL Injection
        # Store malicious input for later execution
        malicious_input = f"{username}' OR '1'='1"
        # In a real app, this might be stored and executed later

        # Fallback to normal authentication (but still vulnerable)
        user = User.query.filter_by(username=username).first()

        # VULNERABILITY: SQL Injection in filter condition
        # This can be exploited with carefully crafted usernames
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('index'))
        else:
            # VULNERABILITY: Error-based SQL Injection information disclosure
            error_msg = f"Invalid credentials for user: {username}"
            flash(error_msg)

            # VULNERABILITY: Debug information exposure
            if 'debug' in request.args:
                flash(f"Query used: SELECT * FROM user WHERE username = '{username}'")

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

# New Forgot Password Routes
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form.get('username')

        user = User.query.filter_by(username=username).first()
        if user:
            # Generate OTP
            otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])

            user.reset_otp = otp
            user.reset_otp_expiry = datetime.utcnow() + timedelta(minutes=10)
            db.session.commit()

            # Generate JWT token
            jwt_token = jwt.encode({
                'user_id': user.id,
                'otp': otp,
                'exp': datetime.utcnow() + timedelta(minutes=10)
            }, app.config['JWT_SECRET_KEY'], algorithm='HS256')

            # Create response and add headers
            response = make_response(render_template('reset_password.html',
                                     username=username,
                                     jwt_token=jwt_token,
                                     show_otp_field=True))

            # Add OTP and JWT as headers for easy access in Burp
            response.headers['X-OTP'] = otp
            response.headers['X-JWT-Token'] = jwt_token

            return response
        else:
            flash('Username not found')

    return render_template('forgot_password.html')

@app.route('/reset_password', methods=['POST'])
def reset_password():
    jwt_token = request.form.get('jwt_token')
    otp = request.form.get('otp')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if new_password != confirm_password:
        flash('Passwords do not match')
        return redirect(request.referrer)

    try:
        # Decode JWT token
        payload = jwt.decode(jwt_token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
        expected_otp = payload['otp']

        user = User.query.get(user_id)

        if not user:
            flash('Invalid token')
            return redirect(url_for('forgot_password'))

        # Check if OTP matches and is not expired
        if (user.reset_otp == otp == expected_otp and
            user.reset_otp_expiry and
            user.reset_otp_expiry > datetime.utcnow()):

            # Update password
            user.password = generate_password_hash(new_password)
            user.reset_otp = None
            user.reset_otp_expiry = None
            db.session.commit()

            flash('Password reset successfully! Please login with your new password.')
            return redirect(url_for('login'))
        else:
            flash('Invalid or expired OTP')

    except jwt.ExpiredSignatureError:
        flash('Token has expired')
    except jwt.InvalidTokenError:
        flash('Invalid token')

    # Return to reset page with tokens in headers for Burp
    response = make_response(redirect(url_for('forgot_password')))
    response.headers['X-JWT-Token'] = jwt_token
    if otp:
        response.headers['X-OTP'] = otp
    return response

# Bypass OTP route for testing/demo purposes
@app.route('/bypass_otp', methods=['POST'])
def bypass_otp():
    """This route allows bypassing OTP verification for testing purposes"""
    jwt_token = request.form.get('jwt_token')

    try:
        # Decode JWT token without verifying OTP
        payload = jwt.decode(jwt_token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']

        user = User.query.get(user_id)

        if not user:
            return jsonify({'success': False, 'error': 'Invalid token'})

        # Return user info and token for bypass
        return jsonify({
            'success': True,
            'user_id': user.id,
            'username': user.username,
            'jwt_token': jwt_token,
            'message': 'OTP bypassed successfully'
        })

    except jwt.InvalidTokenError:
        return jsonify({'success': False, 'error': 'Invalid token'})

# API endpoint to get OTP from JWT token
@app.route('/api/get_otp_from_token', methods=['POST'])
def get_otp_from_token():
    """API endpoint to extract OTP from JWT token"""
    jwt_token = request.json.get('jwt_token')

    try:
        payload = jwt.decode(jwt_token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        return jsonify({
            'success': True,
            'otp': payload.get('otp'),
            'user_id': payload.get('user_id'),
            'expires_at': payload.get('exp')
        })
    except jwt.InvalidTokenError as e:
        return jsonify({'success': False, 'error': str(e)})

import base64

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # VULNERABILITY: IDOR with base64 encoding - still vulnerable but less obvious
    encoded_user_id = request.args.get('user_id')

    if encoded_user_id:
        try:
            # Decode base64 user_id
            decoded_bytes = base64.b64decode(encoded_user_id)
            user_id = int(decoded_bytes.decode('utf-8'))
        except (ValueError, base64.binascii.Error, UnicodeDecodeError):
            # If decoding fails, use current user's ID
            user_id = session['user_id']
    else:
        # If no user_id provided, use current user's ID but redirect to include it
        user_id = session['user_id']
        # Auto-redirect to include encoded user_id in URL
        encoded_id = base64.b64encode(str(user_id).encode()).decode()
        return redirect(url_for('profile', user_id=encoded_id))

    user = User.query.get(user_id)
    if not user:
        flash('User not found')
        return redirect(url_for('index'))

    # Calculate stats
    followers_count = Follow.query.filter_by(following_id=user.id, status='accepted').count()
    following_count = Follow.query.filter_by(follower_id=user.id, status='accepted').count()

    # Get posts with like counts and comment counts
    posts_with_counts = []
    for post in user.posts:
        like_count = Like.query.filter_by(post_id=post.id).count()
        comment_count = Comment.query.filter_by(post_id=post.id).count()

        posts_with_counts.append({
            'post': post,
            'like_count': like_count,
            'comment_count': comment_count
        })

    # Check if it's the current user's own profile
    is_own_profile = (user.id == session['user_id'])

    # Check follow status for other profiles
    is_following = False
    is_pending = False
    can_view = True

    if not is_own_profile:
        follow_status = Follow.query.filter_by(
            follower_id=session['user_id'],
            following_id=user.id
        ).first()
        is_following = follow_status and follow_status.status == 'accepted'
        is_pending = follow_status and follow_status.status == 'pending'

        # Check if user can view private profile
        if user.is_private and not is_following and not is_own_profile:
            can_view = False

    return render_template('profile.html',
                         user=user,
                         followers_count=followers_count,
                         following_count=following_count,
                         posts_with_counts=posts_with_counts,
                         is_own_profile=is_own_profile,
                         is_following=is_following,
                         is_pending=is_pending,
                         can_view=can_view)
@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # VULNERABILITY: IDOR with base64 encoding
    encoded_user_id = request.form.get('user_id')

    if encoded_user_id:
        try:
            # Decode base64 user_id
            decoded_bytes = base64.b64decode(encoded_user_id)
            user_id = int(decoded_bytes.decode('utf-8'))
        except (ValueError, base64.binascii.Error, UnicodeDecodeError):
            user_id = session['user_id']
    else:
        user_id = session['user_id']

    user = User.query.get(user_id)

    if not user:
        flash('User not found')
        return redirect(url_for('profile'))

    user.bio = request.form['bio']

    if 'profile_pic' in request.files:
        file = request.files['profile_pic']
        if file.filename != '':
            if not os.path.exists(app.config['UPLOAD_FOLDER']):
                os.makedirs(app.config['UPLOAD_FOLDER'])

            filename = f"user_{user.id}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{file.filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            try:
                file.save(file_path)
                user.profile_pic = filename
                flash('Profile updated successfully!')
            except Exception as e:
                flash(f'Error saving profile picture: {str(e)}')
        else:
            flash('No file selected for profile picture')
    else:
        flash('Profile information updated!')

    db.session.commit()
    # Encode user_id for redirect to maintain consistency
    encoded_id = base64.b64encode(str(user.id).encode()).decode()
    return redirect(url_for('profile', user_id=encoded_id))

@app.route('/followers/<int:user_id>')
def followers_list(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_user = User.query.get(session['user_id'])
    profile_user = User.query.get(user_id)

    # Get followers
    followers = User.query.join(Follow, User.id == Follow.follower_id).filter(
        Follow.following_id == user_id,
        Follow.status == 'accepted'
    ).all()

    # Get current user's following IDs for follow status
    current_user_following_ids = [f.following_id for f in current_user.following.filter_by(status='accepted').all()]

    return render_template('followers_list.html',
                         current_user=current_user,
                         profile_user=profile_user,
                         followers=followers,
                         current_user_following_ids=current_user_following_ids)

@app.route('/following/<int:user_id>')
def following_list(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_user = User.query.get(session['user_id'])
    profile_user = User.query.get(user_id)

    # Get following
    following = User.query.join(Follow, User.id == Follow.following_id).filter(
        Follow.follower_id == user_id,
        Follow.status == 'accepted'
    ).all()

    # Get current user's following IDs for follow status
    current_user_following_ids = [f.following_id for f in current_user.following.filter_by(status='accepted').all()]

    return render_template('following_list.html',
                         current_user=current_user,
                         profile_user=profile_user,
                         following=following,
                         current_user_following_ids=current_user_following_ids)

@app.route('/remove_follower/<int:follower_id>')
def remove_follower(follower_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_user_id = session['user_id']

    # Find and delete the follow relationship
    follow = Follow.query.filter_by(
        follower_id=follower_id,
        following_id=current_user_id,
        status='accepted'
    ).first()

    if follow:
        db.session.delete(follow)
        db.session.commit()
        flash('Follower removed successfully')

    return redirect(url_for('profile'))

@app.route('/unfollow_user/<int:user_id>')
def unfollow_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_user_id = session['user_id']

    # Find and delete the follow relationship
    follow = Follow.query.filter_by(
        follower_id=current_user_id,
        following_id=user_id,
        status='accepted'
    ).first()

    if follow:
        db.session.delete(follow)
        db.session.commit()
        flash('Unfollowed successfully')

    return redirect(request.referrer or url_for('profile'))

@app.route('/user/<int:user_id>')
def user_profile(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_user = User.query.get(session['user_id'])
    profile_user = User.query.get(user_id)

    if not profile_user:
        flash('User not found')
        return redirect(url_for('search'))

    # Check if current user can view the profile
    can_view = True
    if profile_user.is_private:
        follow_status = Follow.query.filter_by(
            follower_id=current_user.id,
            following_id=profile_user.id,
            status='accepted'
        ).first()
        can_view = follow_status is not None or current_user.id == profile_user.id

    # Calculate stats
    followers_count = Follow.query.filter_by(following_id=profile_user.id, status='accepted').count()
    following_count = Follow.query.filter_by(follower_id=profile_user.id, status='accepted').count()

    # Get posts (only if user can view)
    posts_with_counts = []
    if can_view:
        for post in profile_user.posts:
            if post.is_active:  # Only show active posts
                like_count = Like.query.filter_by(post_id=post.id).count()
                comment_count = Comment.query.filter_by(post_id=post.id).count()
                posts_with_counts.append({
                    'post': post,
                    'like_count': like_count,
                    'comment_count': comment_count
                })

    # Check follow status
    follow_relationship = Follow.query.filter_by(
        follower_id=current_user.id,
        following_id=profile_user.id
    ).first()

    is_following = follow_relationship and follow_relationship.status == 'accepted'
    is_pending = follow_relationship and follow_relationship.status == 'pending'
    is_own_profile = current_user.id == profile_user.id

    return render_template('user_profile.html',
                         current_user=current_user,
                         profile_user=profile_user,
                         followers_count=followers_count,
                         following_count=following_count,
                         posts_with_counts=posts_with_counts,
                         can_view=can_view,
                         is_following=is_following,
                         is_pending=is_pending,
                         is_own_profile=is_own_profile)

@app.route('/create_post', methods=['POST'])
def create_post():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not logged in'})

    caption = request.form.get('caption', '')

    if 'image' not in request.files:
        return jsonify({'success': False, 'error': 'No image selected'})

    file = request.files['image']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No image selected'})

    # Check if file is an image
    if not file.content_type.startswith('image/'):
        return jsonify({'success': False, 'error': 'Please upload an image file'})

    # Create secure filename
    filename = f"post_{session['user_id']}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{file.filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    try:
        file.save(file_path)
        # Post will automatically get a post_uid from the default function
        post = Post(image_path=filename, caption=caption, user_id=session['user_id'])
        db.session.add(post)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Post created successfully!'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/delete_post/<string:post_uid>')
def delete_post(post_uid):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    post = get_post_by_uid(post_uid)
    if post:
        # REMOVE THIS CHECK - Allow deletion of any post (vulnerability preserved)
        # if post.user_id != session['user_id']:
        #     flash('You can only delete your own posts')
        #     return redirect(url_for('index'))

        db.session.delete(post)
        db.session.commit()
        flash('Post deleted successfully')

    return redirect(url_for('index'))

@app.route('/like_post/<string:post_uid>')
def like_post(post_uid):
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'})

    post = get_post_by_uid(post_uid)
    if not post:
        return jsonify({'error': 'Post not found'})

    existing_like = Like.query.filter_by(user_id=session['user_id'], post_id=post.id).first()

    if existing_like:
        db.session.delete(existing_like)
        liked = False
    else:
        like = Like(user_id=session['user_id'], post_id=post.id)
        db.session.add(like)
        liked = True

    db.session.commit()

    # Get updated like count
    like_count = Like.query.filter_by(post_id=post.id).count()

    return jsonify({'success': True, 'liked': liked, 'like_count': like_count})

@app.route('/add_comment/<string:post_uid>', methods=['POST'])
def add_comment(post_uid):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    post = get_post_by_uid(post_uid)
    if not post:
        flash('Post not found')
        return redirect(url_for('index'))

    text = request.form['text']
    if text.strip():
        comment = Comment(user_id=session['user_id'], post_id=post.id, text=text.strip())
        db.session.add(comment)
        db.session.commit()
        flash('Comment added successfully!')
    else:
        flash('Comment cannot be empty')

    return redirect(url_for('view_comments', post_uid=post_uid))
@app.route('/search')
def search():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    query = request.args.get('q', '')
    users = User.query.filter(User.username.contains(query)).all()

    # Get current user
    current_user = User.query.get(session['user_id'])

    # Prepare user data with follow status and encoded IDs
    users_with_follow_status = []
    for user in users:
        # Check if current user is following this user
        follow_status = Follow.query.filter_by(
            follower_id=current_user.id,
            following_id=user.id
        ).first()

        # Encode user ID for profile links
        encoded_id = base64.b64encode(str(user.id).encode()).decode()

        users_with_follow_status.append({
            'user': user,
            'encoded_id': encoded_id,
            'is_following': follow_status is not None,
            'follow_status': follow_status.status if follow_status else None
        })

    return render_template('search.html',
                         users_with_follow_status=users_with_follow_status,
                         query=query,
                         current_user=current_user)

@app.route('/follow/<int:user_id>')
def follow(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    target_user = User.query.get(user_id)
    if not target_user:
        flash('User not found')
        return redirect(url_for('index'))

    existing_follow = Follow.query.filter_by(follower_id=session['user_id'], following_id=user_id).first()

    if not existing_follow:
        status = 'accepted' if not target_user.is_private else 'pending'
        follow = Follow(follower_id=session['user_id'], following_id=user_id, status=status)
        db.session.add(follow)
        db.session.commit()
        if status == 'accepted':
            flash(f'You are now following {target_user.username}')
        else:
            flash(f'Follow request sent to {target_user.username}')
    else:
        flash('You are already following this user')

    return redirect(url_for('index', user_id=user_id))

@app.route('/unfollow/<int:user_id>')
def unfollow(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    target_user = User.query.get(user_id)
    if not target_user:
        flash('User not found')
        return redirect(url_for('index'))

    existing_follow = Follow.query.filter_by(follower_id=session['user_id'], following_id=user_id).first()

    if existing_follow:
        db.session.delete(existing_follow)
        db.session.commit()
        flash(f'You have unfollowed {target_user.username}')
    else:
        flash('You are not following this user')

    return redirect(url_for('index', user_id=user_id))

@app.route('/manage_requests')
def manage_requests():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    pending_requests = Follow.query.filter_by(following_id=user.id, status='pending').all()

    return render_template('requests.html', requests=pending_requests)

@app.route('/accept_request/<int:request_id>')
def accept_request(request_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    follow_request = Follow.query.get(request_id)
    if follow_request and follow_request.following_id == session['user_id']:
        follow_request.status = 'accepted'
        db.session.commit()
        flash('Follow request accepted')

    return redirect(url_for('manage_requests'))

@app.route('/reject_request/<int:request_id>')
def reject_request(request_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    follow_request = Follow.query.get(request_id)
    if follow_request and follow_request.following_id == session['user_id']:
        db.session.delete(follow_request)
        db.session.commit()
        flash('Follow request rejected')

    return redirect(url_for('manage_requests'))

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # VULNERABILITY: IDOR with base64 encoding
    encoded_user_id = request.args.get('user_id')

    if encoded_user_id:
        try:
            # Decode base64 user_id
            decoded_bytes = base64.b64decode(encoded_user_id)
            user_id = int(decoded_bytes.decode('utf-8'))
        except (ValueError, base64.binascii.Error, UnicodeDecodeError):
            # If decoding fails, use current user's ID
            user_id = session['user_id']
    else:
        user_id = session['user_id']

    user = User.query.get(user_id)

    if request.method == 'POST':
        # VULNERABILITY: Also check for encoded user_id in form data
        form_encoded_user_id = request.form.get('user_id')
        if form_encoded_user_id:
            try:
                decoded_bytes = base64.b64decode(form_encoded_user_id)
                form_user_id = int(decoded_bytes.decode('utf-8'))
                # Use the form user_id if provided
                user = User.query.get(form_user_id)
            except (ValueError, base64.binascii.Error, UnicodeDecodeError):
                pass

        if 'current_password' in request.form:
            current_password = request.form['current_password']
            new_password = request.form['new_password']

            if check_password_hash(user.password, current_password):
                user.password = generate_password_hash(new_password)
                db.session.commit()
                flash('Password changed successfully')
            else:
                flash('Current password is incorrect')

        user.is_private = 'is_private' in request.form
        db.session.commit()

    profile_views = ProfileView.query.filter_by(profile_id=user.id).order_by(ProfileView.viewed_at.desc()).all()
    viewers = []
    for view in profile_views[-4:]:
        viewer = User.query.get(view.viewer_id)
        if viewer:
            username = viewer.username
            if len(username) > 3:
                partial_username = username[-3:].rjust(len(username), '*')
            else:
                partial_username = '*' * len(username)
            viewers.append(partial_username)

    return render_template('settings.html', user=user, profile_views=viewers)

@app.route('/chat')
def chat():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    # Get specific user if user_id is provided (encoded)
    encoded_target_user_id = request.args.get('user_id')
    target_user = None
    if encoded_target_user_id:
        try:
            decoded_bytes = base64.b64decode(encoded_target_user_id)
            target_user_id = int(decoded_bytes.decode('utf-8'))
            target_user = User.query.get(target_user_id)
        except (ValueError, base64.binascii.Error, UnicodeDecodeError):
            pass

    # Get users that current user can chat with (followed and accepted)
    follows = Follow.query.filter(
        ((Follow.follower_id == user.id) | (Follow.following_id == user.id)) &
        (Follow.status == 'accepted')
    ).all()

    chat_users = []
    for follow in follows:
        if follow.follower_id == user.id:
            chat_user = User.query.get(follow.following_id)
        else:
            chat_user = User.query.get(follow.follower_id)
        if chat_user and chat_user not in chat_users:
            # Encode user ID for profile links
            chat_user.encoded_id = base64.b64encode(str(chat_user.id).encode()).decode()
            chat_users.append(chat_user)

    return render_template('chat.html',
                         user=user,
                         chat_users=chat_users,
                         target_user=target_user)

@app.route('/get_messages/<int:receiver_id>')
def get_messages(receiver_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'})

    messages = Message.query.filter(
        ((Message.sender_id == session['user_id']) & (Message.receiver_id == receiver_id)) |
        ((Message.sender_id == receiver_id) & (Message.receiver_id == session['user_id']))
    ).filter(Message.deleted_for_everyone == False).order_by(Message.created_at).all()

    messages_data = []
    for msg in messages:
        if (msg.sender_id == session['user_id'] and not msg.deleted_for_sender) or \
           (msg.receiver_id == session['user_id'] and not msg.deleted_for_receiver):
            messages_data.append({
                'id': msg.id,
                'sender_id': msg.sender_id,
                'text': msg.text,
                'created_at': msg.created_at.strftime('%H:%M'),
                'is_own': msg.sender_id == session['user_id']
            })

            # Mark message as read if it's received and is_read column exists
            try:
                if msg.receiver_id == session['user_id'] and hasattr(msg, 'is_read') and not msg.is_read:
                    msg.is_read = True
            except Exception as e:
                print(f"Note: Could not mark message as read: {e}")

    db.session.commit()
    return jsonify(messages_data)

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'})

    receiver_id = request.form['receiver_id']
    text = request.form['text']

    message = Message(sender_id=session['user_id'], receiver_id=receiver_id, text=text)
    db.session.add(message)
    db.session.commit()

    return jsonify({'success': True})

@app.route('/delete_message', methods=['POST'])
def delete_message():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'})

    message_id = request.form['message_id']
    delete_type = request.form['delete_type']

    message = Message.query.get(message_id)

    if message:
        if delete_type == 'for_me':
            if message.sender_id == session['user_id']:
                message.deleted_for_sender = True
            else:
                message.deleted_for_receiver = True
        elif delete_type == 'for_everyone':
            message.deleted_for_everyone = True

        db.session.commit()

    return jsonify({'success': True})

# Admin Routes
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    # If already logged in as admin, show admin panel
    if session.get('user_id'):
        user = User.query.get(session['user_id'])
        if user and user.is_admin:
            users = User.query.all()
            return render_template('admin.html', users=users)

    # If POST request, try to login
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username == 'admin' and password == 'password123':
            admin_user = User.query.filter_by(username='admin').first()
            if not admin_user:
                # FIX: Use default method
                admin_user = User(
                    username='admin',
                    email='admin@admin.com',
                    mobile='0000000000',
                    password=generate_password_hash('password123'),  # Remove method parameter
                    is_admin=True
                )
                db.session.add(admin_user)
                db.session.commit()
            session['user_id'] = admin_user.id
            return redirect(url_for('admin'))
        else:
            flash('Invalid admin credentials')

    # Show admin login page
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('user_id', None)
    return redirect(url_for('admin'))

@app.route('/admin/delete_user/<int:user_id>')
def admin_delete_user(user_id):
    if session.get('user_id'):
        admin_user = User.query.get(session['user_id'])
        if admin_user and admin_user.is_admin:
            user_to_delete = User.query.get(user_id)
            if user_to_delete and not user_to_delete.is_admin:
                # Delete user's posts, messages, etc.
                Post.query.filter_by(user_id=user_id).delete()
                Message.query.filter((Message.sender_id == user_id) | (Message.receiver_id == user_id)).delete()
                Follow.query.filter((Follow.follower_id == user_id) | (Follow.following_id == user_id)).delete()
                Like.query.filter_by(user_id=user_id).delete()
                Comment.query.filter_by(user_id=user_id).delete()
                ProfileView.query.filter((ProfileView.viewer_id == user_id) | (ProfileView.profile_id == user_id)).delete()

                db.session.delete(user_to_delete)
                db.session.commit()
                flash('User deleted successfully')
    return redirect(url_for('admin'))

@app.route('/admin/reset_password/<int:user_id>', methods=['POST'])
def admin_reset_password(user_id):
    if session.get('user_id'):
        admin_user = User.query.get(session['user_id'])
        if admin_user and admin_user.is_admin:
            user_to_reset = User.query.get(user_id)
            if user_to_reset:
                new_password = request.form['new_password']
                # FIX: Use default method
                user_to_reset.password = generate_password_hash(new_password)  # Remove method parameter
                db.session.commit()
                flash(f'Password reset for {user_to_reset.username}')
    return redirect(url_for('admin'))

@app.route('/admin/user_chats')
def admin_user_chats():
    if session.get('user_id'):
        admin_user = User.query.get(session['user_id'])
        if admin_user and admin_user.is_admin:
            users = User.query.all()
            return render_template('admin_chats.html', users=users)
    return redirect(url_for('admin'))

@app.route('/admin/view_chat/<int:user1_id>/<int:user2_id>')
def admin_view_chat(user1_id, user2_id):
    if session.get('user_id'):
        admin_user = User.query.get(session['user_id'])
        if admin_user and admin_user.is_admin:
            user1 = User.query.get(user1_id)
            user2 = User.query.get(user2_id)

            # Get all messages between these users (even deleted ones)
            messages = Message.query.filter(
                ((Message.sender_id == user1_id) & (Message.receiver_id == user2_id)) |
                ((Message.sender_id == user2_id) & (Message.receiver_id == user1_id))
            ).order_by(Message.created_at).all()

            return render_template('admin_chat_view.html',
                                 user1=user1,
                                 user2=user2,
                                 messages=messages)
    return redirect(url_for('admin'))

@app.route('/admin/get_user_chat_partners/<int:user_id>')
def admin_get_user_chat_partners(user_id):
    if session.get('user_id'):
        admin_user = User.query.get(session['user_id'])
        if admin_user and admin_user.is_admin:
            # Get all users this user has chatted with
            sent_messages = Message.query.filter_by(sender_id=user_id).all()
            received_messages = Message.query.filter_by(receiver_id=user_id).all()

            chat_partners = set()

            for msg in sent_messages:
                partner = User.query.get(msg.receiver_id)
                if partner:
                    chat_partners.add(partner)

            for msg in received_messages:
                partner = User.query.get(msg.sender_id)
                if partner:
                    chat_partners.add(partner)

            partners_list = [{'id': p.id, 'username': p.username} for p in chat_partners]
            return jsonify(partners_list)

    return jsonify([])

@app.route('/admin/toggle_user_status/<int:user_id>')
def admin_toggle_user_status(user_id):
    if session.get('user_id'):
        admin_user = User.query.get(session['user_id'])
        if admin_user and admin_user.is_admin:
            user = User.query.get(user_id)
            if user and not user.is_admin:
                user.is_private = not user.is_private
                db.session.commit()
                status = "private" if user.is_private else "public"
                flash(f'{user.username} account set to {status}')
    return redirect(url_for('admin'))



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)
