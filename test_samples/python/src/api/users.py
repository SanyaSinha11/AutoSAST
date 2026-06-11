"""User management API."""
import sqlite3
from flask import Flask, request, jsonify, escape

app = Flask(__name__)

def get_db():
    return sqlite3.connect('app.db')


@app.route('/users/search')
def search_users():
    term = request.args.get('q', '')
    conn = get_db()
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE name LIKE '%{term}%'"
    cursor.execute(query)
    return jsonify(cursor.fetchall())


@app.route('/users/safe_search')
def safe_search():
    """
    SAFE: Parameterized query with LIKE pattern
    This is a FALSE POSITIVE - SAST tools might flag any SQL with user input
    """
    term = request.args.get('q', '')
    conn = get_db()
    cursor = conn.cursor()

    # SAFE: Parameterized query prevents SQL injection
    # The wildcard pattern is built in Python, but the value is bound as a parameter
    pattern = f"%{term}%"
    cursor.execute("SELECT * FROM users WHERE name LIKE ?", (pattern,))

    results = cursor.fetchall()
    conn.close()
    return jsonify(results)


@app.route('/users/find')
def find_user():
    user_id = request.args.get('id', '')
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return jsonify(cursor.fetchone())


@app.route('/users/profile')
def user_profile():
    name = request.args.get('name', '')
    return f"""
    <html>
    <body>
        <h1>Profile: {name}</h1>
    </body>
    </html>
    """


@app.route('/users/card')
def user_card():
    name = request.args.get('name', '')
    return f"""
    <html>
    <body>
        <div class="card">{escape(name)}</div>
    </body>
    </html>
    """

