from flask import Flask, request, jsonify
import sqlite3
import hashlib

app = Flask(__name__)

# Hardcoded Database Credentials
DB_NAME = "users.db"
DB_USER = "admin"
DB_PASSWORD = "admin123"  

# Database Connection
def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

# User Login 
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']  
    password = request.form['password']

    # Weak password hashing 
    hashed_password = hashlib.md5(password.encode()).hexdigest()

    conn = get_db_connection()
    cursor = conn.cursor()

    # SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hashed_password}'"
    cursor.execute(query)

    user = cursor.fetchone()
    conn.close()

    if user:
        return jsonify({"message": "Login successful"})
    else:
        return jsonify({"message": "Invalid credentials"}), 401

# User Registration (Plaintext Storage)
@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']
    email = request.form['email']  

    conn = get_db_connection()
    cursor = conn.cursor()

    # Plain text password storage (Critical weakness)
    query = f"INSERT INTO users (username, password, email) VALUES ('{username}', '{password}', '{email}')"
    cursor.execute(query)

    conn.commit()
    conn.close()

    return jsonify({"message": "User registered successfully"})


# Admin Endpoint (No AuthZ/AuthN)
@app.route('/admin')
def admin_panel():
    return "Admin Area"   

# Error Handling Leak
@app.route('/crash')
def crash():
    try:
        x = 1 / 0
    except Exception as e:
        return str(e)   

# Application Entry Point
if __name__ == '__main__':
    app.run(debug=True)   
