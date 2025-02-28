from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime

app = Flask(__name__)

# Используем базу данных в памяти для работы на Vercel
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'  # база данных в памяти
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'supersecretkey'  # Используйте более безопасный ключ для продакшн
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Модели базы данных
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

class Chat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user2_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey('chat.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@app.before_first_request
def create_tables():
    db.create_all()

# Регистрация пользователя
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    hashed_pw = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    user = User(username=data['username'], password=hashed_pw)
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User registered'}), 201

# Логин пользователя
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        token = create_access_token(identity=user.id)
        return jsonify({'token': token})
    return jsonify({'error': 'Invalid credentials'}), 401

# Создание чата между двумя пользователями
@app.route('/create_chat', methods=['POST'])
@jwt_required()
def create_chat():
    data = request.json
    user1_id = get_jwt_identity()
    user2 = User.query.filter_by(username=data['username']).first()
    if not user2:
        return jsonify({'error': 'User not found'}), 404
    chat = Chat(user1_id=user1_id, user2_id=user2.id)
    db.session.add(chat)
    db.session.commit()
    return jsonify({'chat_id': chat.id})

# Отправка сообщения
@app.route('/send_message', methods=['POST'])
@jwt_required()
def send_message():
    data = request.json
    sender_id = get_jwt_identity()
    chat = Chat.query.get(data['chat_id'])
    if not chat:
        return jsonify({'error': 'Chat not found'}), 404
    message = Message(chat_id=chat.id, sender_id=sender_id, content=data['content'])
    db.session.add(message)
    db.session.commit()
    return jsonify({'message': 'Message sent'})

# Получение списка чатов пользователя
@app.route('/get_chats', methods=['GET'])
@jwt_required()
def get_chats():
    user_id = get_jwt_identity()
    chats = Chat.query.filter((Chat.user1_id == user_id) | (Chat.user2_id == user_id)).all()
    return jsonify([{'chat_id': chat.id, 'user1': chat.user1_id, 'user2': chat.user2_id} for chat in chats])

# Получение сообщений из чата
@app.route('/get_messages/<int:chat_id>', methods=['GET'])
@jwt_required()
def get_messages(chat_id):
    messages = Message.query.filter_by(chat_id=chat_id).order_by(Message.timestamp).all()
    return jsonify([{'sender': msg.sender_id, 'content': msg.content, 'timestamp': msg.timestamp} for msg in messages])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)