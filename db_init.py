import psycopg2
from config import DB_CONFIG

def init_db():
    try:
        # conectare la postgres pt a crea baza de date
        conn_postgres = psycopg2.connect(
            dbname="postgres",
            user=DB_CONFIG["user"],
            password=DB_CONFIG["password"],
            host=DB_CONFIG["host"],
            port=DB_CONFIG["port"]
        )
        conn_postgres.autocommit = True
        cursor = conn_postgres.cursor()
        
        cursor.execute("SELECT 1 FROM pg_catalog.pg_database WHERE datname = %s", (DB_CONFIG["dbname"],))
        exists = cursor.fetchone()
        if not exists:
            cursor.execute(f"CREATE DATABASE {DB_CONFIG['dbname']}")
            print("Baza de date a fost creata!")
        
        cursor.close()
        conn_postgres.close()
        
        # conectare la baza de date noua creata pt a crea tabelele
        conn = psycopg2.connect(
            dbname=DB_CONFIG["dbname"],
            user=DB_CONFIG["user"],
            password=DB_CONFIG["password"],
            host=DB_CONFIG["host"],
            port=DB_CONFIG["port"]
        )
        cursor = conn.cursor()
        
        # 3.1 stocare utilizator baza de date reala + asocierea unui rol simplu 'user'
        # 4.3 adaugarea coloanelor failed_logins si locked pt a putea bloca conturi
        cursor.execute("CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, email VARCHAR(255) UNIQUE NOT NULL, password_hash TEXT NOT NULL, role VARCHAR(10) DEFAULT 'USER' CHECK (role IN ('USER', 'ADMIN')), created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, locked BOOLEAN DEFAULT FALSE, failed_logins INTEGER DEFAULT 0)")
        
        # tabel pt gestionarea tokenurilor de resetare a parolei (utilizat pt 3.4 / 4.6)
        cursor.execute("CREATE TABLE IF NOT EXISTS password_resets (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, token TEXT NOT NULL, expires_at TIMESTAMP WITH TIME ZONE NOT NULL)")
        
        conn.commit()
        cursor.close()
        conn.close()
        print("Tabelele au fost create!")
        
    except Exception as e:
        print(f"Eroare: {e}")

if __name__ == "__main__":
    init_db()
