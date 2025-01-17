from flask import Flask, render_template, session, request, jsonify
from passlib.hash import sha256_crypt
from datetime import timedelta
import sqlite3
import os
from flask_cors import CORS

# Initialize Flask app
app = Flask(__name__, static_folder='build/static', template_folder='build')

# Set secret key for sessions
app.secret_key = 'secret123'

# Database setup
DATABASE = 'wanguana.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Enable dictionary-like access to rows
    return conn

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

# Initialize database before the first request
def initialize():
    init_db()

# Enable CORS for all routes
CORS(app)

# Routes
@app.route('/')
def index():
    return render_template('index.html')  # Serve the React app's entry point (index.html)

# Register API (User Registration)
@app.route('/api/register', methods=['POST'])
def api_register():
    try:
        data = request.get_json()
        
        # Validate incoming data
        name = data.get('name', '').strip()
        email = data.get('email', '').strip()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        confirm_password = data.get('confirmPassword', '').strip()

        if not all([name, email, username, password, confirm_password]):
            return jsonify({"message": "All fields are required"}), 400

        if password != confirm_password:
            return jsonify({"message": "Passwords do not match"}), 400

        if len(password) < 8:
            return jsonify({"message": "Password must be at least 8 characters long"}), 400

        # Check if user already exists
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        if cur.fetchone():
            return jsonify({"message": "Username already exists"}), 400

        # Insert user into the database
        hashed_password = sha256_crypt.encrypt(password)
        cur.execute(
            "INSERT INTO users (name, email, username, password) VALUES (?, ?, ?, ?)",
            (name, email, username, hashed_password),
        )
        conn.commit()
        conn.close()

        return jsonify({"message": "User registered successfully"}), 201

    except Exception as e:
        print("Error during registration:", e)  # Log error for debugging
        return jsonify({"message": "An internal error occurred"}), 500

# Login API (User Login)
@app.route('/api/login', methods=['POST'])
def api_login():
    try:
        data = request.get_json()
        email = data.get('email', '').strip()
        password_candidate = data.get('password', '').strip()

        # Validate inputs
        if not all([email, password_candidate]):
            return jsonify({"message": "Email and password are required"}), 400

        # Check if the user exists
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cur.fetchone()
        conn.close()

        if user:
            # Verify password
            stored_password = user['password']
            if sha256_crypt.verify(password_candidate, stored_password):
                # Create a session if password is correct
                session['logged_in'] = True
                session['username'] = user['username']  # Retrieve the username from the database
                
                # Set the session cookie expiration (if rememberMe is true)
                remember_me = data.get('rememberMe', False)
                if remember_me:
                    session.permanent = True
                    app.permanent_session_lifetime = timedelta(days=30)  # Keep the session for 30 days
                else:
                    session.permanent = False

                return jsonify({"message": "Login successful", "username": user['username']}), 200
            else:
                return jsonify({"message": "Invalid password"}), 401
        else:
            return jsonify({"message": "User not found"}), 404
    except Exception as e:
        print("Error during login:", e)  # Log error for debugging
        return jsonify({"message": "An internal error occurred"}), 500

# Dashboard API (Get Articles for Logged-in User)
@app.route('/api/articles', methods=['GET'])
def api_articles():
    try:
        if 'username' not in session:
            return jsonify({"message": "Unauthorized"}), 403

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM articles WHERE author = ?", (session['username'],))
        articles = [dict(row) for row in cur.fetchall()]
        conn.close()

        return jsonify(articles)
    except Exception as e:
        print("Error fetching articles:", e)  # Log error for debugging
        return jsonify({"message": "An internal error occurred"}), 500

# Logout API (User Logout)
@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({"message": "Logged out successfully"}), 200


@app.route('/api/check-auth', methods=['GET'])
def check_auth():
    if 'logged_in' in session and session['logged_in']:
        return jsonify({"username": session.get('username')}), 200
    return jsonify({"message": "Not authenticated"}), 401


if __name__ == '__main__':
    app.run(debug=True)
