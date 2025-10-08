from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'

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
    image_path = db.Column(db.String(200), nullable=False)
    caption = db.Column(db.String(500))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)  # New field to disable posts
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
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('likes', lazy=True))

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
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

    return render_template('index.html', user=user, posts=feed_posts)

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
#     file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
#
#     try:
#         file.save(file_path)
#         post = Post(image_path=filename, caption=caption, user_id=session['user_id'])
#         db.session.add(post)
#         db.session.commit()
#         return jsonify({'success': True, 'message': 'Post created successfully!'})
#     except Exception as e:
#         return jsonify({'success': False, 'error': str(e)})

@app.route('/toggle_post/<int:post_id>', methods=['POST'])
def toggle_post(post_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not logged in'})

    post = Post.query.get(post_id)
    if post and post.user_id == session['user_id']:
        post.is_active = not post.is_active
        db.session.commit()
        status = "enabled" if post.is_active else "disabled"
        return jsonify({'success': True, 'message': f'Post {status} successfully'})

    return jsonify({'success': False, 'error': 'Post not found'})

@app.route('/view_comments/<int:post_id>')
def view_comments(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    post = Post.query.get(post_id)
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

        # VULNERABILITY: Weak password hashing (should use stronger hashing)
        hashed_password = generate_password_hash(password, method='sha256')

        user = User(username=username, email=email, mobile=mobile, password=hashed_password)
        db.session.add(user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        # VULNERABILITY: SQL Injection vulnerable code (for educational purposes)
        # In real app, use parameterized queries
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

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

    return render_template('profile.html',
                         user=user,
                         followers_count=followers_count,
                         following_count=following_count,
                         posts_with_counts=posts_with_counts)
@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect(url_for('login'))

    user.bio = request.form['bio']

    # Handle profile picture upload
    if 'profile_pic' in request.files:
        file = request.files['profile_pic']
        if file.filename != '':
            # Ensure upload directory exists
            if not os.path.exists(app.config['UPLOAD_FOLDER']):
                os.makedirs(app.config['UPLOAD_FOLDER'])

            # Secure filename and save
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
    return redirect(url_for('profile'))

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
        post = Post(image_path=filename, caption=caption, user_id=session['user_id'])
        db.session.add(post)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Post created successfully!'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/delete_post/<int:post_id>')
def delete_post(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # VULNERABILITY: Insecure Direct Object Reference - No ownership check
    post = Post.query.get(post_id)
    if post:
        db.session.delete(post)
        db.session.commit()
        flash('Post deleted successfully')

    return redirect(url_for('index'))

@app.route('/like_post/<int:post_id>')
def like_post(post_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'})

    existing_like = Like.query.filter_by(user_id=session['user_id'], post_id=post_id).first()

    if existing_like:
        db.session.delete(existing_like)
        liked = False
    else:
        like = Like(user_id=session['user_id'], post_id=post_id)
        db.session.add(like)
        liked = True

    db.session.commit()

    # Get updated like count
    like_count = Like.query.filter_by(post_id=post_id).count()

    return jsonify({'success': True, 'liked': liked, 'like_count': like_count})

@app.route('/add_comment/<int:post_id>', methods=['POST'])
def add_comment(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    text = request.form['text']
    comment = Comment(user_id=session['user_id'], post_id=post_id, text=text)
    db.session.add(comment)
    db.session.commit()

    return redirect(url_for('index', user_id=request.form.get('profile_user_id')))

@app.route('/search')
def search():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    query = request.args.get('q', '')
    users = User.query.filter(User.username.contains(query)).all()

    # Get current user
    current_user = User.query.get(session['user_id'])

    # Prepare user data with follow status
    users_with_follow_status = []
    for user in users:
        # Check if current user is following this user
        follow_status = Follow.query.filter_by(
            follower_id=current_user.id,
            following_id=user.id
        ).first()

        users_with_follow_status.append({
            'user': user,
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

    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        if 'current_password' in request.form:
            # Change password
            current_password = request.form['current_password']
            new_password = request.form['new_password']

            if check_password_hash(user.password, current_password):
                user.password = generate_password_hash(new_password, method='sha256')
                db.session.commit()
                flash('Password changed successfully')
            else:
                flash('Current password is incorrect')

        # Update privacy settings
        user.is_private = 'is_private' in request.form

        db.session.commit()

    # VULNERABILITY: Exposing profile views without proper filtering
    profile_views = ProfileView.query.filter_by(profile_id=user.id).order_by(ProfileView.viewed_at.desc()).all()
    viewers = []
    for view in profile_views[-4:]:  # Show last 4 views
        viewer = User.query.get(view.viewer_id)
        if viewer:
            # Show partial username
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

    # Get specific user if user_id is provided
    target_user_id = request.args.get('user_id')
    target_user = None
    if target_user_id:
        target_user = User.query.get(target_user_id)

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
                admin_user = User(
                    username='admin',
                    email='admin@admin.com',
                    mobile='0000000000',
                    password=generate_password_hash('password123', method='sha256'),
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
                user_to_reset.password = generate_password_hash(new_password, method='sha256')
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
