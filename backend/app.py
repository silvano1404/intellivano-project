import os
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from openai import OpenAI
import stripe

# Charger les variables locales
load_dotenv()

app = Flask(__name__)

# --- CONFIGURATION DE LA BASE DE DONNÉES ---
database_url = os.getenv('DATABASE_URL')
# Correction pour Neon/Postgres
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///intellivano.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'super-secret-key-fixe-pour-le-test'

# --- CONFIGURATION STRIPE ---
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')

# --- CONFIGURATION CORS (LA CORRECTION EST ICI) ---
# On autorise explicitement votre site Vercel
CORS(app, resources={r"/*": {
    "origins": [
        "https://intellivano-project.vercel.app",  # Votre site en ligne
        "http://localhost:5173",                   # Vos tests sur PC
        "*"                                        # Sécurité par défaut
    ],
    "methods": ["GET", "POST", "OPTIONS"],
    "allow_headers": ["Content-Type", "Authorization"]
}})

db = SQLAlchemy(app)
jwt = JWTManager(app)
client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

# --- MODELES ---
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

# --- CRÉATION TABLES ---
with app.app_context():
    db.create_all()

# --- ROUTES ---
@app.route('/', methods=['GET'])
def home():
    return jsonify({"status": "Online", "msg": "Backend connecté !"})

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if User.query.filter_by(email=data['email']).first():
        return jsonify({"msg": "Email déjà utilisé"}), 400
    hashed_pw = generate_password_hash(data['password'])
    new_user = User(username=data['username'], email=data['email'], password=hashed_pw)
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"msg": "Compte créé !"}), 201
    except Exception as e:
        return jsonify({"msg": str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if user and check_password_hash(user.password, data['password']):
        token = create_access_token(identity=str(user.id))
        return jsonify({"token": token, "username": user.username}), 200
    return jsonify({"msg": "Identifiants incorrects"}), 401

@app.route('/chat', methods=['POST'])
@jwt_required()
def chat():
    current_user_id = get_jwt_identity()
    user = User.query.get(int(current_user_id))
    data = request.get_json()
    user_message = data.get('message', '')
    
    # Historique simplifié pour éviter les erreurs
    messages_payload = [{"role": "system", "content": "Tu es une IA utile."}]
    messages_payload.append({"role": "user", "content": user_message})

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages_payload
        )
        ai_reply = response.choices[0].message.content
        return jsonify({"response": ai_reply}), 200
    except Exception as e:
        print(f"Erreur: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)