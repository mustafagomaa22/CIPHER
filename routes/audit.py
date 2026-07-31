"""
CIPHER — Audit Log
Every analyst action is recorded here and encrypted with Blowfish.
The audit log is a tamper-evident record of who did what and when.
"""

import secrets
from datetime import datetime
from flask import Blueprint, jsonify, session

from config import LOGS_FILE, MAX_AUDIT_LOGS
from crypto.vault import load, save
from routes.decorators import require_auth

audit_bp = Blueprint('audit', __name__)


def write_audit(action: str, detail: str = '', user: str = None):
    """
    Append an entry to the encrypted audit log.
    Called from all routes whenever a significant action occurs.

    Args:
        action: Short action code e.g. 'IOC_ADD', 'LOGIN', 'KEY_ROTATE'
        detail: Human-readable description of what happened
        user:   Override the username (used during login before session exists)
    """
    logs = load(LOGS_FILE)

    analyst = user or session.get('username', 'system')

    logs.append({
        'id':     secrets.token_hex(6),
        'ts':     datetime.now().isoformat(),
        'user':   analyst,
        'action': action,
        'detail': detail,
    })

    # Keep log size bounded — drop oldest entries beyond the limit
    logs = logs[-MAX_AUDIT_LOGS:]
    save(logs, LOGS_FILE)


@audit_bp.route('/api/audit')
@require_auth
def get_audit():
    """Return the audit log, newest entries first."""
    logs = load(LOGS_FILE)
    logs.reverse()
    return jsonify({'logs': logs[:200]})
