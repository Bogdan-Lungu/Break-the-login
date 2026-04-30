from flask import Flask, request, render_template, redirect, url_for, session, make_response, flash
from flask_session import Session
import psycopg2
import psycopg2.extras
import bcrypt
import os
import secrets
from datetime import datetime, timedelta, timezone
from config import DB_CONFIG

# 3.2 folosim cookie-uri de sesiune (session) gestionate de flask
app = Flask(__name__, template_folder='templates_v2')
app.secret_key = os.urandom(32)

# 4.5 securizare: sesiuni server-side
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'server_sessions')
Session(app)


# 4.5 securizare: cookie-uri securizate (httponly, secure, samesite)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# 4.5 securizare: expirare sesiune - setam o limita clara de timp pentru sesiune
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

def get_db_connection():
    # 3.1 stocarea utilizatorului intr o baza de date reala
    conn = psycopg2.connect(**DB_CONFIG)
    return conn

def is_password_complex(password):
    # 4.1 lungime minima parola si complexitate minima
    if len(password) < 8: return False
    if not any(char.isdigit() for char in password): return False
    if not any(char.isupper() for char in password): return False
    if not any(char.islower() for char in password): return False
    if not any(char in "!@#$%^&*()-_=+[]{};:,.<>?" for char in password): return False
    return True

@app.route('/')
def index():
    # 3.5 mentinerea autentificarii intre request uri
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    # 3.1 formular de creare cont cu email/username si parola
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # 3.1 input-ul trebuie validat in backend
        # 4.1 validare la inregistrare
        if not is_password_complex(password):
            return render_template('register.html', error="parola trebuie sa aiba minim 8 caractere, litere mari, mici, cifre si caractere speciale.")
        
        # 4.2 hash modern (bcrypt) + salt implicit (nici o parola in clar in db)
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            # 3.1 asocierea unui rol simplu - 'user'
            cur.execute("INSERT INTO users (email, password_hash) VALUES (%s, %s)", (email, password_hash))
            conn.commit()
            return redirect(url_for('login'))
        except psycopg2.IntegrityError:
            conn.rollback()
            return render_template('register.html', error="email indisponibil.")
        finally:
            cur.close()
            conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # 3.2 formular de login cu username + parola
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        # 3.2 verificarea credentialelor in backend
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        
        # 4.3 rate limiting pe login - blocare temporara dupa n incercari. verificam daca e deja blocat
        if user and user['locked']:
            cur.close()
            conn.close()
            return render_template('login.html', error="cont blocat. contactati administratorul.")
            
        # 4.4 anti user enumeration - mesaj unic: "credentiale invalide" pentru ambele cazuri
        generic_error = "credentiale invalide"
        
        if not user:
            # 4.4 timp de raspuns uniform - simulam hash-uirea chiar daca userul nu exista pentru a preveni timing attacks
            bcrypt.checkpw(password.encode('utf-8'), bcrypt.gensalt())
            cur.close()
            conn.close()
            return render_template('login.html', error=generic_error)
            
        if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            # 4.3 logarea tentativelor - incrementam failed_logins si blocam dupa 5 incercari
            failed_logins = user['failed_logins'] + 1
            locked = True if failed_logins >= 5 else False
            cur.execute("UPDATE users SET failed_logins = %s, locked = %s WHERE id = %s", (failed_logins, locked, user['id']))
            conn.commit()
            cur.close()
            conn.close()
            return render_template('login.html', error=generic_error)
            
        # resetam incercarile esuate la login success
        cur.execute("UPDATE users SET failed_logins = 0, locked = FALSE WHERE id = %s", (user['id'],))
        conn.commit()
        cur.close()
        conn.close()
        
        # 4.5 rotatie token la login - curatam sesiunea veche inainte de a crea una noua
        session.clear()
        
        # 3.2 crearea unei sesiuni
        session.permanent = True
        session['user_id'] = user['id']
        session['email'] = user['email']
        
        # 3.2 transmiterea sesiunii catre client se face automat de flask, dar acum cu setari complete
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    # 3.5 asocierea request-urilor cu utilizatorul logat - baza pentru access control
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', email=session['email'])

@app.route('/logout')
def logout():
    # 3.3 stergerea cookie-ului sau marcarea token-ului ca invalid
    # 4.5 invalidare la logout - distrugem sesiunea pe server si stergem cookie-ul din browser
    session.clear()
    resp = make_response(redirect(url_for('login')))
    resp.set_cookie(app.config['SESSION_COOKIE_NAME'], '', expires=0, httponly=True, secure=True, samesite='Lax')
    # 3.3 dupa logout sesiunea nu mai este valida
    return resp

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    # 3.4 functionalitate "forgot password"
    if request.method == 'POST':
        email = request.form['email']
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        
        if user:
            # 3.4 generarea unui token de resetare
            # 4.6 token random, criptografic sigur
            token = secrets.token_urlsafe(32)
            # 4.6 expirare scurta (15 minute)
            expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)
            cur.execute("INSERT INTO password_resets (user_id, token, expires_at) VALUES (%s, %s, %s)", (user['id'], token, expires_at))
            conn.commit()
            reset_link = url_for('reset_password', token=token, _external=True)
            cur.close()
            conn.close()
            return f'link de resetare trimis (simulare): <a href="{reset_link}">{reset_link}</a>'
        
        cur.close()
        conn.close()
        # prevenire enumerare si la forgot password
        return "daca adresa exista in sistem, vei primi un email de resetare."
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # 3.4 endpoint pentru setarea unei parole noi
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute("SELECT * FROM password_resets WHERE token = %s", (token,))
    reset_entry = cur.fetchone()
    
    if not reset_entry:
        cur.close()
        conn.close()
        return "token invalid."
        
    expires_at = reset_entry['expires_at']
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
        
    # 4.6 verificam daca tokenul a expirat
    if datetime.now(timezone.utc) > expires_at:
        cur.execute("DELETE FROM password_resets WHERE id = %s", (reset_entry['id'],))
        conn.commit()
        cur.close()
        conn.close()
        return "token expirat."
    
    if request.method == 'POST':
        new_password = request.form['new_password']
        
        # 4.1 validam si aici complexitatea parolei noi
        if not is_password_complex(new_password):
            return render_template('reset_password.html', token=token, error="parola nu este suficient de complexa.")
            
        password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cur.execute("UPDATE users SET password_hash = %s WHERE id = %s", (password_hash, reset_entry['user_id']))
        # 4.6 one-time use - invalidare dupa utilizare (stergem tokenul din db imediat ce a fost folosit)
        cur.execute("DELETE FROM password_resets WHERE user_id = %s", (reset_entry['user_id'],))
        conn.commit()
        cur.close()
        conn.close()
        return redirect(url_for('login'))
        
    cur.close()
    conn.close()
    return render_template('reset_password.html', token=token)

if __name__ == '__main__':
    app.run(port=5002, debug=True)