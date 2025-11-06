import os
from flask import Flask, render_template_string, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from functools import wraps
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Fix DATABASE_URL for Render (postgres:// -> postgresql://)
database_url = os.environ.get('DATABASE_URL', 'postgresql://localhost/chatapp')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

# Production-ready configuration from .env
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback-key-change-this')
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 10,
    'pool_recycle': 3600,
    'pool_pre_ping': True,
}

# Session configuration
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'False') == 'True'
app.config['SESSION_COOKIE_HTTPONLY'] = os.environ.get('SESSION_COOKIE_HTTPONLY', 'True') == 'True'
app.config['SESSION_COOKIE_SAMESITE'] = os.environ.get('SESSION_COOKIE_SAMESITE', 'Lax')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=int(os.environ.get('PERMANENT_SESSION_LIFETIME', 3600)))

# Application settings
MAX_MESSAGE_LENGTH = int(os.environ.get('MAX_MESSAGE_LENGTH', 1000))
MESSAGES_PER_PAGE = int(os.environ.get('MESSAGES_PER_PAGE', 100))
POLL_INTERVAL = int(os.environ.get('POLL_INTERVAL', 500))

db = SQLAlchemy(app)

# Models
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    messages = db.relationship('Message', backref='author', lazy=True, cascade='all, delete-orphan')

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

# Initialize database and create users
def init_db():
    with app.app_context():
        db.create_all()
        
        # Create default users if they don't exist
        if User.query.count() == 0:
            user1 = User(username='Tasauf', password=generate_password_hash('@Tasauf-123'), is_admin=False)
            user2 = User(username='Tasfia', password=generate_password_hash("tasauf's_property"), is_admin=False)
            admin = User(username='Ghost', password=generate_password_hash('@Salehin-5678'), is_admin=True)
            
            db.session.add(user1)
            db.session.add(user2)
            db.session.add(admin)
            db.session.commit()

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Login page template
LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Login - Private Chat App</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta charset="UTF-8">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            width: 100%;
            max-width: 400px;
        }
        h1 {
            color: #333;
            margin-bottom: 30px;
            text-align: center;
            font-size: 28px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            color: #555;
            font-weight: bold;
            font-size: 14px;
        }
        input {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        input:focus {
            outline: none;
            border-color: #667eea;
        }
        button {
            width: 100%;
            padding: 12px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: background 0.3s;
        }
        button:hover {
            background: #5568d3;
        }
        .error {
            background: #f8d7da;
            color: #721c24;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
            font-size: 14px;
        }
        .info {
            margin-top: 20px;
            padding: 15px;
            background: #e7f3ff;
            border-radius: 5px;
            font-size: 14px;
        }
        .info p { margin: 5px 0; }
        .copyright {
            margin-top: 20px;
            text-align: center;
            color: white;
            font-size: 12px;
            opacity: 0.9;
        }
        
        @media (max-width: 480px) {
            .login-container {
                padding: 30px 20px;
            }
            h1 {
                font-size: 24px;
                margin-bottom: 20px;
            }
            input, button {
                padding: 10px;
                font-size: 14px;
            }
            .info {
                font-size: 12px;
                padding: 12px;
            }
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>🔐 Chat Login</h1>
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        <form method="POST">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required autocomplete="username">
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required autocomplete="current-password">
            </div>
            <button type="submit">Login</button>
        </form>
    </div>
    <div class="copyright">
        © 2025 - Tasauf, All rights reserved.
    </div>
</body>
</html>
'''

# Not used template
NOT_USED = """
        <div class="info">
            <p><strong>Demo Accounts:</strong></p>
            <p>👤 Tasauf / @Tasauf-123</p>
            <p>👤 Tasfia / tasauf's_property</p>
            <p>👑 Ghost / @Salehin-5678</p>
        </div>
"""


# Chat page template
CHAT_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Chat - {{ current_user.username }}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta charset="UTF-8">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: Arial, sans-serif;
            background: #f0f2f5;
            height: 100vh;
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }
        .header {
            background: #667eea;
            color: white;
            padding: 15px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            flex-shrink: 0;
        }
        .header h1 {
            font-size: 24px;
        }
        .user-info {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .user-name {
            font-size: 14px;
        }
        .logout-btn {
            background: rgba(255,255,255,0.2);
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            transition: background 0.3s;
            white-space: nowrap;
        }
        .logout-btn:hover {
            background: rgba(255,255,255,0.3);
        }
        .chat-container {
            flex: 1;
            display: flex;
            flex-direction: column;
            max-width: 1200px;
            width: 100%;
            margin: 0 auto;
            padding: 20px;
            overflow: hidden;
        }
        .messages {
            flex: 1;
            overflow-y: auto;
            padding: 20px;
            background: white;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .message {
            margin-bottom: 15px;
            padding: 12px;
            border-radius: 8px;
            background: #f8f9fa;
            max-width: 80%;
            animation: fadeIn 0.3s ease-in;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .message.own {
            background: #667eea;
            color: white;
            margin-left: auto;
        }
        .message.admin {
            background: #ffc107;
            border-left: 4px solid #ff9800;
        }
        .message-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 5px;
            font-size: 12px;
            opacity: 0.8;
            gap: 10px;
        }
        .message-content {
            font-size: 15px;
            word-wrap: break-word;
            overflow-wrap: break-word;
        }
        .input-container {
            display: flex;
            gap: 10px;
            background: white;
            padding: 15px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            flex-shrink: 0;
        }
        #message-input {
            flex: 1;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 15px;
            min-width: 0;
        }
        #message-input:focus {
            outline: none;
            border-color: #667eea;
        }
        #send-btn {
            padding: 12px 30px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 15px;
            font-weight: bold;
            cursor: pointer;
            transition: background 0.3s;
            white-space: nowrap;
        }
        #send-btn:hover {
            background: #5568d3;
        }
        #send-btn:disabled {
            background: #ccc;
            cursor: not-allowed;
        }
        .admin-panel {
            background: #fff3cd;
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
            border-left: 4px solid #ffc107;
            flex-shrink: 0;
        }
        .admin-panel h3 {
            margin-bottom: 10px;
            font-size: 18px;
        }
        .admin-panel p {
            font-size: 14px;
        }
        .copyright {
            text-align: center;
            padding: 10px;
            background: white;
            font-size: 11px;
            color: #666;
            border-top: 1px solid #e0e0e0;
            flex-shrink: 0;
        }
        .typing-indicator {
            display: none;
            padding: 10px;
            font-size: 12px;
            color: #666;
            font-style: italic;
        }
        
        @media (max-width: 768px) {
            .header {
                padding: 12px 15px;
            }
            .header h1 {
                font-size: 18px;
            }
            .user-info {
                gap: 10px;
            }
            .user-name {
                font-size: 12px;
            }
            .logout-btn {
                padding: 6px 12px;
                font-size: 12px;
            }
            .chat-container {
                padding: 10px;
            }
            .messages {
                padding: 15px;
                margin-bottom: 15px;
            }
            .message {
                padding: 10px;
                max-width: 90%;
            }
            .message-content {
                font-size: 14px;
            }
            .input-container {
                padding: 10px;
                gap: 8px;
            }
            #message-input {
                padding: 10px;
                font-size: 14px;
            }
            #send-btn {
                padding: 10px 20px;
                font-size: 14px;
            }
            .admin-panel {
                padding: 12px;
                margin-bottom: 15px;
            }
            .admin-panel h3 {
                font-size: 16px;
            }
            .admin-panel p {
                font-size: 13px;
            }
        }
        
        @media (max-width: 480px) {
            .header {
                flex-direction: column;
                gap: 10px;
                align-items: stretch;
            }
            .header h1 {
                font-size: 16px;
                text-align: center;
            }
            .user-info {
                justify-content: space-between;
                flex-wrap: wrap;
            }
            .user-name {
                font-size: 11px;
                flex: 1;
            }
            .chat-container {
                padding: 8px;
            }
            .messages {
                padding: 10px;
                margin-bottom: 10px;
            }
            .message {
                padding: 8px;
                max-width: 95%;
            }
            .message-header {
                font-size: 11px;
            }
            .message-content {
                font-size: 13px;
            }
            #send-btn {
                padding: 10px 15px;
                font-size: 13px;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>💬 Private Chat - Made By Tasauf</h1>
        <div class="user-info">
            <span class="user-name">Logged in as: <strong>{{ current_user.username }}</strong>{% if current_user.is_admin %} 👑{% endif %}</span>
            <form method="POST" action="{{ url_for('logout') }}" style="display: inline;">
                <button type="submit" class="logout-btn">Logout</button>
            </form>
        </div>
    </div>
    
    <div class="chat-container">
        {% if current_user.is_admin %}
        <div class="admin-panel">
            <h3>👑 Admin Panel</h3>
            <p>Total messages: <span id="message-count">{{ messages|length }}</span></p>
            <p>You can see all messages and manage the chat.</p>
        </div>
        {% endif %}
        
        <div class="messages" id="messages">
            {% for msg in messages %}
            <div class="message {% if msg.author.id == current_user.id %}own{% elif msg.author.is_admin %}admin{% endif %}">
                <div class="message-header">
                    <strong>{{ msg.author.username }}</strong>
                    <span>{{ msg.timestamp.strftime('%H:%M:%S') }}</span>
                </div>
                <div class="message-content">{{ msg.content }}</div>
            </div>
            {% endfor %}
        </div>
        
        <div class="typing-indicator" id="typing-indicator">Someone is typing...</div>
        
        <div class="input-container">
            <input type="text" id="message-input" placeholder="Type your message..." autocomplete="off">
            <button id="send-btn">Send</button>
        </div>
    </div>
    
    <div class="copyright">
        © 2025 - Tasauf, All rights reserved.
    </div>

    <script>
        const messagesDiv = document.getElementById('messages');
        const messageInput = document.getElementById('message-input');
        const sendBtn = document.getElementById('send-btn');
        const currentUserId = {{ current_user.id }};
        const isAdmin = {{ 'true' if current_user.is_admin else 'false' }};
        let lastMessageId = {{ messages[-1].id if messages else 0 }};
        let isScrolledToBottom = true;

        // Auto-scroll to bottom
        function scrollToBottom() {
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
        }
        
        // Check if user is at bottom
        messagesDiv.addEventListener('scroll', () => {
            const threshold = 50;
            isScrolledToBottom = messagesDiv.scrollHeight - messagesDiv.scrollTop - messagesDiv.clientHeight < threshold;
        });
        
        scrollToBottom();

        // Send message
        function sendMessage() {
            const content = messageInput.value.trim();
            if (!content) return;
            
            sendBtn.disabled = true;
            
            fetch('/send_message', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({content: content})
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    messageInput.value = '';
                }
            })
            .catch(error => {
                console.error('Error sending message:', error);
            })
            .finally(() => {
                sendBtn.disabled = false;
                messageInput.focus();
            });
        }

        sendBtn.addEventListener('click', sendMessage);
        messageInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
            }
        });

        // Escape HTML to prevent XSS
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        // Poll for new messages
        function pollMessages() {
            fetch(`/get_messages?last_id=${lastMessageId}`)
                .then(response => response.json())
                .then(messages => {
                    if (messages && messages.length > 0) {
                        messages.forEach(msg => {
                            // Skip if message already exists (double-check)
                            if (msg.id <= lastMessageId) return;
                            
                            const msgDiv = document.createElement('div');
                            let classes = 'message';
                            if (msg.user_id === currentUserId) classes += ' own';
                            else if (msg.is_admin) classes += ' admin';
                            
                            msgDiv.className = classes;
                            msgDiv.innerHTML = `
                                <div class="message-header">
                                    <strong>${escapeHtml(msg.username)}</strong>
                                    <span>${escapeHtml(msg.timestamp)}</span>
                                </div>
                                <div class="message-content">${escapeHtml(msg.content)}</div>
                            `;
                            messagesDiv.appendChild(msgDiv);
                            lastMessageId = Math.max(lastMessageId, msg.id);
                        });
                        
                        // Auto-scroll if user was at bottom
                        if (isScrolledToBottom) {
                            scrollToBottom();
                        }
                        
                        if (isAdmin) {
                            const countSpan = document.getElementById('message-count');
                            if (countSpan) {
                                countSpan.textContent = parseInt(countSpan.textContent) + messages.length;
                            }
                        }
                    }
                })
                .catch(error => {
                    console.error('Error fetching messages:', error);
                });
        }

        // Poll every interval from .env
        setInterval(pollMessages, {{ poll_interval }});
        
        // Focus input on load
        messageInput.focus();
    </script>
</body>
</html>
'''

# Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('home'))
    
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            error = 'Username and password are required'
        else:
            user = User.query.filter_by(username=username).first()
            
            if user and check_password_hash(user.password, password):
                session['user_id'] = user.id
                session.permanent = True
                return redirect(url_for('home'))
            else:
                error = 'Invalid username or password'
    
    return render_template_string(LOGIN_TEMPLATE, error=error)


@app.route('/logout', methods=['POST', 'GET'])
def logout():
    session.clear()
    response = redirect(url_for('login'))
    # Prevent caching to ensure logout works properly
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/')
@login_required
def home():
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    messages = Message.query.order_by(Message.id.asc()).limit(MESSAGES_PER_PAGE).all()
    return render_template_string(CHAT_TEMPLATE, current_user=user, messages=messages, poll_interval=POLL_INTERVAL)

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    try:
        data = request.get_json()
        content = data.get('content', '').strip()
        
        if not content or len(content) > MAX_MESSAGE_LENGTH:
            return jsonify({'success': False, 'error': 'Invalid message'}), 400
        
        user = User.query.get(session['user_id'])
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 401
        
        message = Message(content=content, user_id=user.id)
        db.session.add(message)
        db.session.commit()
        db.session.refresh(message)  # Ensure ID is populated
        
        return jsonify({
            'success': True, 
            'message_id': message.id,
            'timestamp': message.timestamp.strftime('%H:%M:%S')
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error sending message: {e}")
        return jsonify({'success': False, 'error': 'Server error'}), 500

@app.route('/get_messages')
@login_required
def get_messages():
    try:
        last_id = request.args.get('last_id', 0, type=int)
        
        # Query messages with proper ordering and filtering
        messages = Message.query.filter(
            Message.id > last_id
        ).order_by(
            Message.id.asc()
        ).limit(50).all()
        
        # Return empty list if no new messages
        if not messages:
            return jsonify([])
        
        return jsonify([{
            'id': msg.id,
            'content': msg.content,
            'username': msg.author.username,
            'user_id': msg.author.id,
            'is_admin': msg.author.is_admin,
            'timestamp': msg.timestamp.strftime('%H:%M:%S')
        } for msg in messages])
    except Exception as e:
        app.logger.error(f"Error fetching messages: {e}")
        return jsonify([])

# Health check endpoint
@app.route('/health')
def health():
    return jsonify({'status': 'healthy'}), 200

# Error handlers
@app.errorhandler(404)
def not_found(e):
    return redirect(url_for('home'))

@app.errorhandler(500)
def server_error(e):
    app.logger.error(f"Server error: {e}")
    return "Internal server error", 500

if __name__ == '__main__':
    init_db()
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
