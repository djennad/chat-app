from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    sent_messages = db.relationship('Message', 
                                  foreign_keys='Message.user_id',
                                  backref='author', 
                                  lazy=True)
    received_messages = db.relationship('Message',
                                      foreign_keys='Message.recipient_id',
                                      backref='recipient',
                                      lazy=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def chat():
    messages = Message.query.order_by(Message.timestamp.desc()).limit(50).all()
    return render_template('chat.html', messages=messages)

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    content = request.form.get('content')
    if content:
        message = Message(content=content, user_id=current_user.id)
        db.session.add(message)
        db.session.commit()
        return jsonify({
            'status': 'success',
            'message': {
                'content': message.content,
                'username': current_user.username,
                'timestamp': message.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            }
        })
    return jsonify({'status': 'error'})

@app.route('/users')
@login_required
def users_list():
    users = User.query.filter(User.id != current_user.id).all()
    return render_template('users.html', users=users)

@app.route('/chat/<int:user_id>')
@login_required
def private_chat(user_id):
    other_user = User.query.get_or_404(user_id)
    messages = Message.query.filter(
        ((Message.user_id == current_user.id) & (Message.recipient_id == user_id)) |
        ((Message.user_id == user_id) & (Message.recipient_id == current_user.id))
    ).order_by(Message.timestamp.desc()).limit(50).all()
    return render_template('private_chat.html', messages=messages, other_user=other_user)

@app.route('/send_private_message', methods=['POST'])
@login_required
def send_private_message():
    content = request.form.get('content')
    recipient_id = request.form.get('recipient_id')
    if content and recipient_id:
        message = Message(
            content=content,
            user_id=current_user.id,
            recipient_id=recipient_id
        )
        db.session.add(message)
        db.session.commit()
        return jsonify({
            'status': 'success',
            'message': {
                'content': message.content,
                'username': current_user.username,
                'timestamp': message.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            }
        })
    return jsonify({'status': 'error'})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:  # في التطبيق الحقيقي، يجب استخدام تشفير كلمة المرور
            login_user(user)
            return redirect(url_for('chat'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
        else:
            user = User(username=username, password=password)  # في التطبيق الحقيقي، يجب تشفير كلمة المرور
            db.session.add(user)
            db.session.commit()
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
