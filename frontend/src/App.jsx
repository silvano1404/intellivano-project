import os
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

app = Flask(__name__)

# Config
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'intellivano.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'super-secret-key-fixe-pour-le-test'

# IMPORTANT : Autoriser Vercel (CORS)
CORS(app, resources={r"/*": {"origins": "*"}})

db = SQLAlchemy(app)
jwt = JWTManager(app)
client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

# --- MODELS ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_premium = db.Column(db.Boolean, default=False)

class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user_msg = db.Column(db.Text, nullable=False)
    ai_response = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# --- CORRECTION DE L'ERREUR "NO SUCH TABLE" ---
# On crée les tables immédiatement au lancement
with app.app_context():
    db.create_all()
    print("Base de données et tables créées avec succès !")

# --- ROUTES ---
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if User.query.filter_by(email=data['email']).first():
        return jsonify({"msg": "Cet email est déjà utilisé"}), 400
    hashed_pw = generate_password_hash(data['password'])
    new_user = User(username=data['username'], email=data['email'], password=hashed_pw)
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"msg": "Utilisateur créé !"}), 201
    except Exception as e:
        return jsonify({"msg": str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if user and check_password_hash(user.password, data['password']):
        token = create_access_token(identity=str(user.id))
        return jsonify({"token": token, "username": user.username}), 200
    return jsonify({"msg": "Erreur login"}), 401

@app.route('/chat', methods=['POST'])
@jwt_required()
def chat():
    current_user_id = get_jwt_identity()
    user = User.query.get(int(current_user_id))
    data = request.get_json()
    
    user_message = data.get('message', '')
    image_data = data.get('image')

    if not user_message and not image_data:
        return jsonify({"msg": "Message vide"}), 400

    content_payload = []
    if user_message:
        content_payload.append({"type": "text", "text": user_message})
    if image_data:
        content_payload.append({
            "type": "image_url",
            "image_url": {"url": image_data}
        })

    history = Conversation.query.filter_by(user_id=user.id).order_by(Conversation.timestamp.desc()).limit(5).all()
    messages_payload = [{"role": "system", "content": "Tu es Intellivano."}]
    
    for conv in reversed(history):
        messages_payload.append({"role": "user", "content": conv.user_msg})
        messages_payload.append({"role": "assistant", "content": conv.ai_response})
    
    messages_payload.append({"role": "user", "content": content_payload})

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages_payload,
            max_tokens=500
        )
        ai_reply = response.choices[0].message.content
        text_log = f"[IMAGE] {user_message}" if image_data else user_message
        new_conv = Conversation(user_id=user.id, user_msg=text_log, ai_response=ai_reply)
        db.session.add(new_conv)
        db.session.commit()

        return jsonify({"response": ai_reply}), 200

    except Exception as e:
        print(f"Erreur: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)