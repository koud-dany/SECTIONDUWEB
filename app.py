from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
from datetime import datetime
import stripe
from functools import wraps

app = Flask(__name__)
import os
# Generate secure secret key if not provided
import secrets
flask_secret = os.environ.get('FLASK_SECRET')
if not flask_secret:
    # Use a consistent key for development to maintain sessions across restarts
    flask_secret = 'dev_key_video_tournament_2025_do_not_use_in_production'
    print("Warning: FLASK_SECRET not set, using development key. Set FLASK_SECRET environment variable for production!")
app.config['SECRET_KEY'] = flask_secret

# Security configuration
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# Enable secure cookies in production (when running with HTTPS)
if os.environ.get('REPLIT_DEPLOYMENT') or os.environ.get('HTTPS', '').lower() == 'true':
    app.config['SESSION_COOKIE_SECURE'] = True
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# Stripe configuration from environment variables
stripe_secret = os.environ.get('STRIPE_SECRET_KEY')
if not stripe_secret:
    raise ValueError("STRIPE_SECRET_KEY environment variable must be set for payment processing!")
stripe.api_key = stripe_secret
STRIPE_PUBLISHABLE_KEY = os.environ.get('STRIPE_PUBLISHABLE_KEY')

# Get domain for Stripe redirects
repl_domains = os.environ.get('REPLIT_DOMAINS', 'localhost:5000')
YOUR_DOMAIN = os.environ.get('REPLIT_DEV_DOMAIN') if os.environ.get('REPLIT_DEPLOYMENT') else repl_domains.split(',')[0]

# Ensure required directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(os.path.dirname(__file__), 'static', 'thumbnails'), exist_ok=True)
os.makedirs(os.path.join(os.path.dirname(__file__), 'static'), exist_ok=True)

# Database setup
def init_db():
    conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), 'tournament.db'))
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_paid BOOLEAN DEFAULT FALSE,
        registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Videos table
    c.execute('''CREATE TABLE IF NOT EXISTS videos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        title TEXT NOT NULL,
        description TEXT,
        filename TEXT NOT NULL,
        upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        total_votes INTEGER DEFAULT 0,
        average_rating REAL DEFAULT 0.0,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Votes table
    c.execute('''CREATE TABLE IF NOT EXISTS votes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        video_id INTEGER,
        rating INTEGER CHECK(rating >= 1 AND rating <= 5),
        vote_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, video_id),
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (video_id) REFERENCES videos (id)
    )''')
    
    # Comments table
    c.execute('''CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        video_id INTEGER,
        comment TEXT NOT NULL,
        comment_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (video_id) REFERENCES videos (id)
    )''')
    
    conn.commit()
    conn.close()

# Helper functions
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def payment_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), 'tournament.db'))
        c = conn.cursor()
        c.execute('SELECT is_paid FROM users WHERE id = ?', (session['user_id'],))
        user = c.fetchone()
        conn.close()
        
        if not user or not user[0]:
            flash('Please complete your registration payment to access this feature.')
            return redirect(url_for('payment'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'mp4', 'avi', 'mov', 'wmv', 'flv', 'webm'}

# Routes
@app.route('/')
def index():
    conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), 'tournament.db'))
    c = conn.cursor()
    
    # Get top videos
    c.execute('''SELECT v.id, v.title, v.filename, v.total_votes, v.average_rating, u.username 
                 FROM videos v JOIN users u ON v.user_id = u.id 
                 ORDER BY v.average_rating DESC, v.total_votes DESC LIMIT 5''')
    top_videos = c.fetchall()
    
    # Get total participants
    c.execute('SELECT COUNT(*) FROM users WHERE is_paid = 1')
    total_participants = c.fetchone()[0]
    
    # Get total videos
    c.execute('SELECT COUNT(*) FROM videos')
    total_videos = c.fetchone()[0]
    
    conn.close()
    
    return render_template('base.html', 
                         top_videos=top_videos,
                         total_participants=total_participants,
                         total_videos=total_videos)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long.')
            return render_template('register.html')
        
        password_hash = generate_password_hash(password)
        
        conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), 'tournament.db'))
        c = conn.cursor()
        
        try:
            c.execute('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                     (username, email, password_hash))
            conn.commit()
            user_id = c.lastrowid
            
            session['user_id'] = user_id
            session['username'] = username
            
            flash('Registration successful! Please complete your payment to participate.')
            return redirect(url_for('payment'))
            
        except sqlite3.IntegrityError:
            flash('Username or email already exists.')
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), 'tournament.db'))
        c = conn.cursor()
        c.execute('SELECT id, username, password_hash FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            flash('Login successful!')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('index'))

@app.route('/payment')
@login_required
def payment():
    return render_template('payment.html', stripe_publishable_key=STRIPE_PUBLISHABLE_KEY)

@app.route('/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    try:
        checkout_session = stripe.checkout.Session.create(
            line_items=[
                {
                    'price_data': {
                        'currency': 'usd',
                        'product_data': {
                            'name': 'Video Tournament Entry Fee',
                            'description': 'Entry fee for participating in the video tournament',
                        },
                        'unit_amount': 2500,  # $25 in cents
                    },
                    'quantity': 1,
                },
            ],
            mode='payment',
            success_url=url_for('payment_success', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=url_for('payment', _external=True),
            metadata={'user_id': str(session['user_id'])},
        )
    except Exception as e:
        flash(f'Error creating payment session: {str(e)}')
        return redirect(url_for('payment'))
    
    return redirect(checkout_session.url or url_for('payment'), code=303)

@app.route('/payment-success')
@login_required
def payment_success():
    session_id = request.args.get('session_id')
    if session_id:
        try:
            # Verify the payment session
            checkout_session = stripe.checkout.Session.retrieve(session_id)
            
            # Verify the session belongs to the current user and payment is complete
            metadata = checkout_session.metadata or {}
            if (checkout_session.payment_status == 'paid' and 
                metadata.get('user_id') == str(session['user_id'])):
                
                # Mark user as paid
                conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), 'tournament.db'))
                c = conn.cursor()
                c.execute('UPDATE users SET is_paid = 1 WHERE id = ?', (session['user_id'],))
                conn.commit()
                conn.close()
                
                flash('Payment successful! You can now participate in the tournament.')
                return redirect(url_for('dashboard'))
            else:
                flash('Payment verification failed - session mismatch or payment incomplete.')
        except Exception as e:
            flash(f'Error verifying payment: {str(e)}')
    
    flash('Payment verification failed. Please contact support.')
    return redirect(url_for('payment'))

# Demo route for testing - bypass payment
@app.route('/demo-activate')
@login_required  
def demo_activate():
    conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), 'tournament.db'))
    c = conn.cursor()
    c.execute('UPDATE users SET is_paid = 1 WHERE id = ?', (session['user_id'],))
    conn.commit()
    conn.close()
    
    flash('Demo mode: Account activated! You can now access all features.')
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
@login_required
@payment_required
def dashboard():
    conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), 'tournament.db'))
    c = conn.cursor()
    
    # Get user's videos
    c.execute('''SELECT id, title, filename, total_votes, average_rating, upload_date 
                 FROM videos WHERE user_id = ? ORDER BY upload_date DESC''', (session['user_id'],))
    user_videos = c.fetchall()
    
    conn.close()
    return render_template('dashboard.html', user_videos=user_videos)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
@payment_required
def upload_video():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        
        if 'video' not in request.files:
            flash('No video file selected.')
            return redirect(request.url)
        
        file = request.files['video']
        if file.filename == '':
            flash('No video file selected.')
            return redirect(request.url)
        
        if file and file.filename and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # Add timestamp to avoid conflicts
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
            filename = timestamp + filename
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), 'tournament.db'))
            c = conn.cursor()
            c.execute('INSERT INTO videos (user_id, title, description, filename) VALUES (?, ?, ?, ?)',
                     (session['user_id'], title, description, filename))
            conn.commit()
            conn.close()
            
            flash('Video uploaded successfully!')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid file type. Please upload a video file.')
    
    return render_template('upload.html')

@app.route('/videos')
@login_required
@payment_required
def videos():
    conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), 'tournament.db'))
    c = conn.cursor()
    
    # Get all videos with user info and vote counts
    c.execute('''SELECT v.id, v.title, v.description, v.filename, v.total_votes, 
                        v.average_rating, u.username, v.upload_date
                 FROM videos v JOIN users u ON v.user_id = u.id 
                 ORDER BY v.average_rating DESC, v.total_votes DESC''')
    videos = c.fetchall()
    
    conn.close()
    return render_template('videos.html', videos=videos)

@app.route('/video/<int:video_id>')
@login_required
@payment_required
def video_detail(video_id):
    conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), 'tournament.db'))
    c = conn.cursor()
    
    # Get video details
    c.execute('''SELECT v.id, v.title, v.description, v.filename, v.total_votes, 
                        v.average_rating, u.username, v.upload_date, v.user_id
                 FROM videos v JOIN users u ON v.user_id = u.id 
                 WHERE v.id = ?''', (video_id,))
    video = c.fetchone()
    
    if not video:
        flash('Video not found.')
        return redirect(url_for('videos'))
    
    # Get user's vote for this video
    c.execute('SELECT rating FROM votes WHERE user_id = ? AND video_id = ?', 
              (session['user_id'], video_id))
    user_vote = c.fetchone()
    
    # Get comments
    c.execute('''SELECT c.comment, c.comment_date, u.username 
                 FROM comments c JOIN users u ON c.user_id = u.id 
                 WHERE c.video_id = ? ORDER BY c.comment_date DESC''', (video_id,))
    comments = c.fetchall()
    
    conn.close()
    
    return render_template('video_detail.html', 
                         video=video, 
                         user_vote=user_vote[0] if user_vote else None,
                         comments=comments)

@app.route('/vote', methods=['POST'])
@login_required
@payment_required
def vote():
    video_id = int(request.form['video_id'])
    rating = int(request.form['rating'])
    
    if rating < 1 or rating > 5:
        flash('Invalid rating.')
        return redirect(url_for('video_detail', video_id=video_id))
    
    # Check if user owns this video
    conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), 'tournament.db'))
    c = conn.cursor()
    c.execute('SELECT user_id FROM videos WHERE id = ?', (video_id,))
    video_owner = c.fetchone()
    
    if video_owner and video_owner[0] == session['user_id']:
        flash('You cannot vote on your own video.')
        conn.close()
        return redirect(url_for('video_detail', video_id=video_id))
    
    try:
        # Insert or update vote
        c.execute('''INSERT OR REPLACE INTO votes (user_id, video_id, rating) 
                     VALUES (?, ?, ?)''', (session['user_id'], video_id, rating))
        
        # Update video statistics
        c.execute('''UPDATE videos SET 
                     total_votes = (SELECT COUNT(*) FROM votes WHERE video_id = ?),
                     average_rating = (SELECT AVG(rating) FROM votes WHERE video_id = ?)
                     WHERE id = ?''', (video_id, video_id, video_id))
        
        conn.commit()
        flash('Vote submitted successfully!')
        
    except sqlite3.Error as e:
        flash('Error submitting vote.')
        
    finally:
        conn.close()
    
    return redirect(url_for('video_detail', video_id=video_id))

@app.route('/comment', methods=['POST'])
@login_required
@payment_required
def add_comment():
    video_id = int(request.form['video_id'])
    comment_text = request.form['comment'].strip()
    
    if not comment_text:
        flash('Comment cannot be empty.')
        return redirect(url_for('video_detail', video_id=video_id))
    
    conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), 'tournament.db'))
    c = conn.cursor()
    c.execute('INSERT INTO comments (user_id, video_id, comment) VALUES (?, ?, ?)',
             (session['user_id'], video_id, comment_text))
    conn.commit()
    conn.close()
    
    flash('Comment added successfully!')
    return redirect(url_for('video_detail', video_id=video_id))

@app.route('/leaderboard')
@login_required
@payment_required
def leaderboard():
    conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), 'tournament.db'))
    c = conn.cursor()
    
    # Get ranking of all videos
    c.execute('''SELECT v.id, v.title, v.filename, v.total_votes, v.average_rating, 
                        u.username, v.upload_date,
                        ROW_NUMBER() OVER (ORDER BY v.average_rating DESC, v.total_votes DESC) as rank
                 FROM videos v JOIN users u ON v.user_id = u.id 
                 ORDER BY v.average_rating DESC, v.total_votes DESC''')
    ranked_videos = c.fetchall()
    
    conn.close()
    return render_template('leaderboard.html', videos=ranked_videos)

if __name__ == '__main__':
    init_db()
    # Configure for Replit environment - bind to 0.0.0.0:5000
    port = int(os.environ.get('PORT', 5000))
    # Only enable debug in development
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug_mode)