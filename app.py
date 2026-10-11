import os, secrets
from flask import Flask, jsonify, request, render_template, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
app=Flask(__name__)
app.secret_key=os.getenv('SECRET_KEY',secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI']=os.getenv('DATABASE_URL','sqlite:///security.db').replace('postgres://','postgresql://',1)
app.config.update(SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Lax',SESSION_COOKIE_SECURE=os.getenv('COOKIE_SECURE')=='1')
db=SQLAlchemy(app)
class User(db.Model):
 id=db.Column(db.Integer,primary_key=True)
 username=db.Column(db.String(80),unique=True,nullable=False)
 password_hash=db.Column(db.String(255),nullable=False)
 encrypted_note=db.Column(db.LargeBinary,nullable=False)
def key():
 raw=os.getenv('AES256_KEY_HEX','')
 if len(raw)!=64:raise RuntimeError('Set AES256_KEY_HEX to a random 32-byte hex key')
 return bytes.fromhex(raw)
def encrypt(text):
 nonce=os.urandom(12)
 return nonce+AESGCM(key()).encrypt(nonce,text.encode(),None)
def decrypt(blob):return AESGCM(key()).decrypt(blob[:12],blob[12:],None).decode()
@app.get('/')
def home():return render_template('index.html')
@app.get('/health')
def health():return jsonify(status='ok')
@app.post('/api/register')
def register():
 data=request.get_json(silent=True) or {};username=str(data.get('username','')).strip();password=str(data.get('password',''));note=str(data.get('note',''))
 if not (3<=len(username)<=80 and len(password)>=12 and len(note)<=2000):return jsonify(error='Username 3-80, password 12+ and note max 2000 required'),400
 if User.query.filter_by(username=username).first():return jsonify(error='Username exists'),409
 user=User(username=username,password_hash=generate_password_hash(password),encrypted_note=encrypt(note));db.session.add(user);db.session.commit()
 return jsonify(status='registered'),201
@app.post('/api/login')
def login():
 data=request.get_json(silent=True) or {};user=User.query.filter_by(username=str(data.get('username',''))).first()
 if not user or not check_password_hash(user.password_hash,str(data.get('password',''))):return jsonify(error='Invalid credentials'),401
 session.clear();session['uid']=user.id;session['capability']=secrets.token_urlsafe(32)
 return jsonify(status='authenticated',capability=session['capability'])
@app.get('/api/note')
def note():
 if not session.get('uid') or not secrets.compare_digest(request.headers.get('X-Capability',''),session.get('capability','')):return jsonify(error='Access denied'),403
 user=db.session.get(User,session['uid'])
 if not user:return jsonify(error='Access denied'),403
 return jsonify(note=decrypt(user.encrypted_note))
@app.post('/api/logout')
def logout():session.clear();return jsonify(status='logged_out')
with app.app_context():db.create_all()
if __name__=='__main__':app.run(debug=os.getenv('FLASK_DEBUG')=='1')
