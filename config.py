"""
CIPHER — Configuration
All application settings live here. Change these to customize your deployment.
"""

import os
import secrets

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
DATA_DIR  = os.path.join(BASE_DIR, 'data')

VAULT_FILE     = os.path.join(DATA_DIR, 'vault.enc')
CASES_FILE     = os.path.join(DATA_DIR, 'cases.enc')
ACTORS_FILE    = os.path.join(DATA_DIR, 'actors.enc')
LOGS_FILE      = os.path.join(DATA_DIR, 'audit.enc')
WATCHLIST_FILE = os.path.join(DATA_DIR, 'watchlist.enc')
NOTES_FILE     = os.path.join(DATA_DIR, 'notes.enc')
USERS_FILE     = os.path.join(DATA_DIR, 'users.json')
KEY_FILE       = os.path.join(DATA_DIR, 'vault.key')
CONFIG_FILE    = os.path.join(DATA_DIR, 'config.json')

# Make sure data directory exists
os.makedirs(DATA_DIR, exist_ok=True)

# ── Server ─────────────────────────────────────────────────────────────────────
HOST            = '127.0.0.1'
PORT            = 5000
DEBUG           = True

# ── Security ───────────────────────────────────────────────────────────────────
SESSION_TIMEOUT = 1800        # seconds — 30 minutes of inactivity
MAX_AUDIT_LOGS  = 500         # keep last N audit entries
SALT_LENGTH     = 16          # bytes for password salt

# ── Threat Scoring Weights ─────────────────────────────────────────────────────
SEVERITY_WEIGHTS = {
    'critical': 40,
    'high':     28,
    'medium':   14,
    'low':       5,
}

TYPE_WEIGHTS = {
    'apt':     25,
    'malware': 20,
    'hash':    15,
    'ip':      12,
    'url':     10,
    'domain':  10,
    'email':    8,
    'other':    5,
}

TLP_WEIGHTS = {
    'RED':    18,
    'AMBER':  10,
    'GREEN':   5,
    'WHITE':   0,
}

# Tags that boost the threat score
DANGER_TAGS = [
    'ransomware', 'apt', 'c2', 'rootkit', 'backdoor',
    'zero-day', 'wiper', 'critical', 'lockbit', 'lazarus',
]

# ── Live Threat Feeds ──────────────────────────────────────────────────────────
THREAT_FEEDS = [
    {
        'name': 'Feodo C2 IPs',
        'url':  'https://feodotracker.abuse.ch/downloads/ipblocklist.csv',
        'type': 'ip',
    },
    {
        'name': 'URLhaus Malware URLs',
        'url':  'https://urlhaus.abuse.ch/downloads/csv_recent/',
        'type': 'url',
    },
]

FEED_MAX_RESULTS = 25   # max IOCs to pull per feed
FEED_TIMEOUT     = 8    # seconds before feed request times out
