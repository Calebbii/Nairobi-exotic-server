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
        try:
            # Ensure schema.sql is in the correct location and readable
            with app.open_resource('schema.sql', mode='r') as f:
                print(f"Reading schema from: {f.name}")  # Debug line to check if schema.sql is found
                db.cursor().executescript(f.read())
            db.commit()
        except Exception as e:
            print(f"Error initializing database: {e}")

# Initialize database before the first request
def initialize():
    if not os.path.exists(DATABASE):
        print(f"Database '{DATABASE}' not found. Initializing...")
        init_db()
    else:
        print(f"Database '{DATABASE}' already exists. Skipping initialization.")

# Enable CORS for all routes
# Allow CORS for the frontend origin
CORS(app, supports_credentials=True, resources={r"/api/*": {"origins": "https://www.nairobi-exotic.com"}})

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


# Fetch all users'

@app.route('/api/admin/users', methods=['GET'])
def admin_get_users():
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id, name, email, username FROM users")
        users = [dict(row) for row in cur.fetchall()]
        conn.close()
        return jsonify(users), 200
    except Exception as e:
        print("Error fetching users:", e)
        return jsonify({"message": "An error occurred"}), 500

# Add a new user
@app.route('/api/admin/users', methods=['POST'])
def admin_add_user():
    try:
        data = request.get_json()
        name = data.get('name', '').strip()
        email = data.get('email', '').strip()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()

        if not all([name, email, username, password]):
            return jsonify({"message": "All fields are required"}), 400

        conn = get_db()
        cur = conn.cursor()
        hashed_password = sha256_crypt.encrypt(password)
        cur.execute(
            "INSERT INTO users (name, email, username, password) VALUES (?, ?, ?, ?)",
            (name, email, username, hashed_password),
        )
        conn.commit()
        conn.close()
        return jsonify({"message": "User added successfully"}), 201
    except Exception as e:
        print("Error adding user:", e)
        return jsonify({"message": "An error occurred"}), 500

# Update a user
@app.route('/api/admin/users/<int:user_id>', methods=['PUT'])
def admin_update_user(user_id):
    try:
        data = request.get_json()
        name = data.get('name', '').strip()
        email = data.get('email', '').strip()
        username = data.get('username', '').strip()

        if not all([name, email, username]):
            return jsonify({"message": "All fields are required"}), 400

        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET name = ?, email = ?, username = ? WHERE id = ?",
            (name, email, username, user_id),
        )
        conn.commit()
        conn.close()
        return jsonify({"message": "User updated successfully"}), 200
    except Exception as e:
        print("Error updating user:", e)
        return jsonify({"message": "An error occurred"}), 500

# Delete a user
@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
def admin_delete_user(user_id):
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        return jsonify({"message": "User deleted successfully"}), 200
    except Exception as e:
        print("Error deleting user:", e)
        return jsonify({"message": "An error occurred"}), 500

if __name__ == '__main__':
    # Ensure that the database is initialized before running the app
    initialize()

    # Get the port from the environment variable or use 5000 as a default
    port = int(os.environ.get("PORT", 5000))

    # Run the app with host '0.0.0.0' so it is accessible externally
    app.run(debug=True, host="0.0.0.0", port=port)
