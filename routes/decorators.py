"""
CIPHER — Route Decorators
Shared decorators used across all route modules.
"""

from functools import wraps
from datetime import datetime
from flask import session, jsonify
from config import SESSION_TIMEOUT


def require_auth(f):
    """
    Decorator that protects a route behind analyst authentication.
    Also enforces the session inactivity timeout.
    Apply to any route that should not be accessible without login.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            return jsonify({'error': 'Authentication required'}), 401

        # Check session timeout
        last_active = session.get('last_active', 0)
        elapsed     = datetime.now().timestamp() - last_active

        if elapsed > SESSION_TIMEOUT:
            session.clear()
            return jsonify({'error': 'Session expired — please sign in again'}), 401

        # Refresh the inactivity timer on each authenticated request
        session['last_active'] = datetime.now().timestamp()

        return f(*args, **kwargs)

    return decorated
