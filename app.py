from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_pymongo import PyMongo
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib


app = Flask(__name__)
CORS(app)
app.config["MONGO_URI"] = "mongodb+srv://elnurliyev1619_db_user:<db_password>@cluster0.9x6zd9g.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"  # Doğru URI. 'history' collection adı, veritabanı değil!
mongo = PyMongo(app)
@app.route('/')
def home():
    return "Server işləyir!"

# Şifrəni hash-lə (sadə demo üçün)
def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

# Qeydiyyat endpointi
@app.route('/api/auth/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    if not username or not email or not password:
        return jsonify({'error': 'Bütün sahələr doldurulmalıdır!'}), 400
    if mongo.db.users.find_one({'username': username}):
        return jsonify({'error': 'İstifadəçi adı artıq mövcuddur!'}), 400
    if mongo.db.users.find_one({'email': email}):
        return jsonify({'error': 'Email artıq mövcuddur!'}), 400
    mongo.db.users.insert_one({
        'username': username,
        'email': email,
        'password': hash_password(password)
    })
    return jsonify({'success': True})

# Login endpointi
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'İstifadəçi adı və şifrə doldurulmalıdır!'}), 400
    user = mongo.db.users.find_one({'username': username})
    if not user or user['password'] != hash_password(password):
        return jsonify({'error': 'İstifadəçi adı və ya şifrə yanlışdır!'}), 401
    return jsonify({'success': True})

# Helper: AES key must be 16, 24, or 32 bytes
def get_aes_key(key):
    key_bytes = key.encode('utf-8')
    if len(key_bytes) < 16:
        key_bytes = key_bytes.ljust(16, b'0')
    elif len(key_bytes) > 32:
        key_bytes = key_bytes[:32]
    elif len(key_bytes) not in [16, 24, 32]:
        # Pad to next valid length
        if len(key_bytes) < 24:
            key_bytes = key_bytes.ljust(24, b'0')
        else:
            key_bytes = key_bytes.ljust(32, b'0')
    return key_bytes

@app.route('/api/crypto/encrypt', methods=['POST'])
def encrypt():
    data = request.get_json()
    message = data.get('message', '')
    key = data.get('key', '')
    if not message or not key:
        return jsonify({'error': 'Mesaj və açar doldurulmalıdır!'}), 400
    try:
        key_bytes = get_aes_key(key)
        cipher = AES.new(key_bytes, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
        iv = base64.b64encode(cipher.iv).decode('utf-8')
        ct = base64.b64encode(ct_bytes).decode('utf-8')
        encrypted = iv + ':' + ct
        # MongoDB'ye kaydet
        mongo.db.history.insert_one({
            'type': 'encrypt',
            'message': message,
            'key': key,
            'encrypted': encrypted
        })
        return jsonify({'encrypted': encrypted})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/crypto/decrypt', methods=['POST'])
def decrypt():
    data = request.get_json()
    encrypted = data.get('encrypted', '')
    key = data.get('key', '')
    if not encrypted or not key:
        return jsonify({'error': 'Əvvəl şifrələmə aparılmalıdır!'}), 400
    try:
        key_bytes = get_aes_key(key)
        iv, ct = encrypted.split(':')
        iv = base64.b64decode(iv)
        ct = base64.b64decode(ct)
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        decrypted = pt.decode('utf-8')
        # MongoDB'ye kaydet
        mongo.db.history.insert_one({
            'type': 'decrypt',
            'key': key,
            'encrypted': encrypted,
            'decrypted': decrypted
        })
        return jsonify({'decrypted': decrypted})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/crypto/history', methods=['GET'])
def get_history():
    items = list(mongo.db.history.find({}, {'_id': 0}))
    return jsonify({'history': items})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5432, debug=True)
