"""
CIPHER — Authentication Routes
Handles analyst registration, login, logout, and session management.

Security notes:
- Passwords are never stored — only salted SHA-256 hashes
- Sessions expire after 30 minutes of inactivity (configurable in config.py)
- Every login/logout is recorded in the encrypted audit log
"""

import json
import secrets
from datetime import datetime

from flask import Blueprint, request, jsonify, session

from config import USERS_FILE, SESSION_TIMEOUT, SALT_LENGTH
from crypto.vault import hash_password, verify_password

auth_bp = Blueprint('auth', __name__)


# ── Helpers ────────────────────────────────────────────────────────────────────

def load_users() -> dict:
    """Load the users file. Returns an empty dict if no users exist yet."""
    try:
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_users(users: dict):
    """Persist the users dict to disk."""
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)


def session_is_valid() -> bool:
    """Check if the current session is still within the timeout window."""
    if 'username' not in session:
        return False
    last_active = session.get('last_active', 0)
    elapsed = datetime.now().timestamp() - last_active
    return elapsed < SESSION_TIMEOUT


def touch_session():
    """Reset the inactivity timer for the current session."""
    session['last_active'] = datetime.now().timestamp()


# ── Routes ─────────────────────────────────────────────────────────────────────

@auth_bp.route('/api/auth/register', methods=['POST'])
def register():
    """
    Register a new analyst account.
    Generates a random salt, hashes the password, stores only the hash.
    """
    data     = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400
    if len(username) < 3:
        return jsonify({'error': 'Username must be at least 3 characters'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400

    users = load_users()
    if username in users:
        return jsonify({'error': 'Username already taken'}), 409

    # Generate a unique salt per user — prevents rainbow table attacks
    salt = secrets.token_hex(SALT_LENGTH)

    users[username] = {
        'salt':    salt,
        'hash':    hash_password(password, salt),
        'created': datetime.now().isoformat(),
        'role':    'analyst',
    }
    save_users(users)

    # Log the registration (imported here to avoid circular imports)
    from routes.audit import write_audit
    write_audit('REGISTER', f'New account created: {username}', user=username)

    return jsonify({'message': 'Account created successfully'})


@auth_bp.route('/api/auth/login', methods=['POST'])
def login():
    """
    Authenticate an analyst.
    Returns a success response and sets a server-side session on valid credentials.
    """
    data     = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')

    users = load_users()

    # Use the same error message for both wrong username and wrong password
    # to prevent username enumeration
    if username not in users:
        return jsonify({'error': 'Invalid username or password'}), 401

    user = users[username]
    if not verify_password(password, user['salt'], user['hash']):
        return jsonify({'error': 'Invalid username or password'}), 401

    # Set session
    session['username']    = username
    session['role']        = user.get('role', 'analyst')
    session['last_active'] = datetime.now().timestamp()

    from routes.audit import write_audit
    write_audit('LOGIN', 'Analyst session started', user=username)

    return jsonify({
        'username': username,
        'role':     user.get('role', 'analyst'),
    })


@auth_bp.route('/api/auth/logout', methods=['POST'])
def logout():
    """End the current analyst session."""
    from routes.audit import write_audit
    write_audit('LOGOUT', 'Session ended')
    session.clear()
    return jsonify({'message': 'Logged out'})


@auth_bp.route('/api/auth/me')
def me():
    """Return the current session state — used on page load to restore session."""
    if not session_is_valid():
        return jsonify({'authenticated': False})

    return jsonify({
        'authenticated': True,
        'username':      session['username'],
        'role':          session.get('role', 'analyst'),
    })


@auth_bp.route('/api/auth/ping')
def ping():
    """
    Heartbeat endpoint — called every 10 seconds by the frontend.
    Returns remaining session time. Expires session if timeout exceeded.
    """
    if 'username' not in session:
        return jsonify({'ok': False, 'expired': True})

    last_active = session.get('last_active', 0)
    elapsed     = datetime.now().timestamp() - last_active
    remaining   = max(0, SESSION_TIMEOUT - elapsed)

    if remaining == 0:
        session.clear()
        return jsonify({'ok': False, 'expired': True})

    # Reset the timer on each ping
    touch_session()
    return jsonify({'ok': True, 'remaining': int(remaining)})
