import pymysql
import sys

def init_db():
    print("--- SIEM-Blue Database Setup Started ---")
    try:
        # 1. Connect to MySQL Server
        db = pymysql.connect(
            host="localhost",
            user="Ketan",
            password="Ketan@1407#2002"
        )
        cursor = db.cursor()
        print("[+] Connected to MySQL.")

        # 2. Create Database
        cursor.execute("CREATE DATABASE IF NOT EXISTS SIEM_DB")
        cursor.execute("USE SIEM_DB")
        
        # 3. Create Tables
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) NOT NULL,
                password VARCHAR(255) NOT NULL
            )
        """)
        
        # 4. Insert User
        cursor.execute("SELECT * FROM users WHERE username='Ketan'")
        if not cursor.fetchone():
            cursor.execute("INSERT INTO users (username, password) VALUES ('Ketan', 'Ketan@1407#2002')")
            db.commit()
            print("[+] User 'Ketan' created.")
        else:
            print("[!] User 'Ketan' already exists.")

        db.close()
        print("--- Setup Completed Successfully! ---")
    except Exception as e:
        print(f"\n[!] ERROR: {e}")

if __name__ == "__main__":
    init_db()
