from flask import Flask, request, render_template, redirect, url_for, session, make_response
import psycopg2
import psycopg2.extras
import hashlib
import os
from config import DB_CONFIG

# 3.2 crearea unei sesiuni sau token
app = Flask(__name__, template_folder='templates_v1')
app.secret_key = 'super_secret_key_v1'

# 3.2 setari initial incomplete (intentionat) - transmiterea sesiunii catre client fara flaguri de securitate
# 4.5 vulnerabilitate: gestionare nesigura a sesiunilor
app.config['SESSION_COOKIE_HTTPONLY'] = False
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_SAMESITE'] = None

def get_db_connection():
    # 3.1 stocarea utilizatorului intr-o baza de date reala - conectare la postgresql
    conn = psycopg2.connect(**DB_CONFIG)
    return conn

@app.route('/')
def index():
    # 3.5 mentinerea autentificarii intre request-uri - verificam daca user_id este in sesiune
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    # 3.1 formular de creare cont cu email/username si parola
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # 4.1 vulnerabilitate: password policy slab 
        # 4.2 vulnerabilitate: stocare nesigura a parolelor - hash slab (md5) fara salt
        password_hash = hashlib.md5(password.encode()).hexdigest()
        
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            # 3.1 asocierea unui rol simplu - rolul 'user' 
            cur.execute("INSERT INTO users (email, password_hash) VALUES (%s, %s)", (email, password_hash))
            conn.commit()
            return redirect(url_for('login'))
        except psycopg2.IntegrityError:
            conn.rollback()
            return "email deja existent."
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
        
        # 4.4 vulnerabilitate: user enumeration - mesaje diferite pentru "utilizator inexistent" vs "parola incorecta"
        # 3.2 raspuns initial diferentiat (vulnerabil)
        if not user:
            cur.close()
            conn.close()
            return "utilizator inexistent"
        
        # 4.3 vulnerabilitate: brute force / lipsa rate limiting - numar nelimitat de incercari login, fara blocare cont
        password_hash = hashlib.md5(password.encode()).hexdigest()
        if user['password_hash'] != password_hash:
            cur.close()
            conn.close()
            return "parola incorecta"
        
        # 3.2 crearea unei sesiuni
        # 4.5 vulnerabilitate: token cu expirare prea lunga - sesiune permanenta
        session.permanent = True
        session['user_id'] = user['id']
        session['email'] = user['email']
        cur.close()
        conn.close()
        
        # 3.2 transmiterea sesiunii catre client - se face automat de flask
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
    # 3.3 stergerea cookie-ului
    # 4.5 vulnerabilitate: reutilizarea sesiunii - lipseste invalidarea sesiunii pe server (session.clear() lipseste intentionat), dupa logout sesiunea inca este valida
    resp = make_response(redirect(url_for('login')))
    resp.set_cookie('session', '', expires=0)
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
            # 4.6 vulnerabilitate: resetare parola nesigura - token predictibil (doar un md5 al email-ului)
            token = hashlib.md5(email.encode()).hexdigest()
            # 4.6 vulnerabilitate: fara expirare la token - data din viitorul indepartat / ignoram expirarea
            cur.execute("INSERT INTO password_resets (user_id, token, expires_at) VALUES (%s, %s, '9999-12-31')", (user['id'], token))
            conn.commit()
            reset_link = url_for('reset_password', token=token, _external=True)
            cur.close()
            conn.close()
            return f'link de resetare trimis (simulare): <a href="{reset_link}">{reset_link}</a>'
        cur.close()
        conn.close()
        return "daca emailul exista, a fost trimis un link."
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # 3.4 endpoint pentru setarea unei parole noi - fara controale avansate la inceput
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute("SELECT * FROM password_resets WHERE token = %s", (token,))
    reset_entry = cur.fetchone()
    
    if not reset_entry:
        cur.close()
        conn.close()
        return "token invalid."
        
    # 4.6 vulnerabilitate: fara expirare - nu se verifica daca tokenul a expirat
        
    if request.method == 'POST':
        new_password = request.form['new_password']
        
        # 4.1 vulnerabilitate: nu exista validare nici la resetare
        
        password_hash = hashlib.md5(new_password.encode()).hexdigest()
        cur.execute("UPDATE users SET password_hash = %s WHERE id = %s", (password_hash, reset_entry['user_id']))
        # 4.6 vulnerabilitate: token reutilizabil - nu stergem token-ul dupa folosire (resetarea parolei fara control corect)
        conn.commit()
        cur.close()
        conn.close()
        return redirect(url_for('login'))
        
    cur.close()
    conn.close()
    return render_template('reset_password.html', token=token)

if __name__ == '__main__':
    app.run(port=5001, debug=True)
