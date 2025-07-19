from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

# Cipher imports
from cipher.caesar import encrypt_caesar, decrypt_caesar, brute_force_caesar
from cipher.vigenere import encrypt_vigenere, decrypt_vigenere
from cipher.base64_cipher import encode_base64, decode_base64
from cipher.aes_cipher import encrypt_aes, decrypt_aes, generate_key

# -------------------- App Config --------------------
app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Change in production

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FOLDER = os.path.join(BASE_DIR, "database")
os.makedirs(DB_FOLDER, exist_ok=True)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(DB_FOLDER, 'crypto.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Only initialize once
db = SQLAlchemy(app)

# -------------------- Models --------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(200))

class History(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    input_text = db.Column(db.Text)
    output_text = db.Column(db.Text)
    cipher = db.Column(db.String(50))
    mode = db.Column(db.String(20))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='history')

# -------------------- Routes --------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        uname = request.form['username']
        pwd = request.form['password']
        if User.query.filter_by(username=uname).first():
            return "Username already exists"
        hashed_pwd = generate_password_hash(pwd)
        user = User(username=uname, password=hashed_pwd)
        db.session.add(user)
        db.session.commit()
        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        uname = request.form['username']
        pwd = request.form['password']
        user = User.query.filter_by(username=uname).first()
        if user and check_password_hash(user.password, pwd):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect('/')
        else:
            return "Invalid credentials"
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/result', methods=['POST'])
def result():
    mode = request.form['mode']
    cipher_type = request.form['cipher']
    text = request.form['text']
    shift = request.form.get('shift')
    keyword = request.form.get('keyword')

    if cipher_type == 'caesar':
        if mode == 'brute':
            results = brute_force_caesar(text)
            return render_template('result.html', mode=mode, cipher=cipher_type, results=results, original=text)
        if not shift or not shift.isdigit():
            return "Shift required", 400
        shift = int(shift)
        output = encrypt_caesar(text, shift) if mode == 'encrypt' else decrypt_caesar(text, shift)

    elif cipher_type == 'vigenere':
        if not keyword:
            return "Keyword required", 400
        output = encrypt_vigenere(text, keyword) if mode == 'encrypt' else decrypt_vigenere(text, keyword)

    elif cipher_type == 'base64':
        output = encode_base64(text) if mode == 'encrypt' else decode_base64(text)

    elif cipher_type == 'aes':
        if not keyword:
            return "Key required", 400
        output = encrypt_aes(text, keyword) if mode == 'encrypt' else decrypt_aes(text, keyword)

    else:
        return "Invalid cipher", 400

    # Save to DB if user is logged in
    if 'user_id' in session:
        new_entry = History(
            user_id=session['user_id'],
            input_text=text,
            output_text=output,
            cipher=cipher_type,
            mode=mode
        )
        db.session.add(new_entry)
        db.session.commit()

    return render_template('result.html', mode=mode, cipher=cipher_type, output=output, original=text)

@app.route('/generate-key')
def generate_key_route():
    return generate_key()

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', user=user)

@app.route('/delete/<int:entry_id>')
def delete_entry(entry_id):
    if 'user_id' not in session:
        return redirect('/login')
    entry = History.query.get_or_404(entry_id)
    if entry.user_id != session['user_id']:
        return "Unauthorized", 403
    db.session.delete(entry)
    db.session.commit()
    return redirect('/dashboard')

# -------------------- Main --------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
