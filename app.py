"""
CIPHER — Threat Intelligence Platform
======================================
Built by Mustafa Gomaa
GitHub  : https://github.com/lumidren
LinkedIn: https://www.linkedin.com/in/lumidren/
THM     : https://tryhackme.com/p/MustafaGomaa

A professional-grade encrypted threat intelligence platform for SOC analysts.
All cryptographic components implemented from scratch — no external crypto libraries.

Encryption  : Blowfish CBC (256-bit key, PKCS7 padding)
Auth        : SHA-256 + random salt per user
Key rotation: Full re-encryption of all data files on demand

Run:
    pip install flask
    python app.py
"""

import secrets
from flask import Flask, send_file

from config import HOST, PORT, DEBUG
from routes.auth      import auth_bp
from routes.iocs      import iocs_bp
from routes.cases     import cases_bp
from routes.actors    import actors_bp
from routes.intel     import intel_bp
from routes.analytics import analytics_bp
from routes.audit     import audit_bp

# ── App setup ──────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# ── Register blueprints ────────────────────────────────────────────────────────
app.register_blueprint(auth_bp)
app.register_blueprint(iocs_bp)
app.register_blueprint(cases_bp)
app.register_blueprint(actors_bp)
app.register_blueprint(intel_bp)
app.register_blueprint(analytics_bp)
app.register_blueprint(audit_bp)

# ── Frontend ───────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return send_file('ui.html')

# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print("""
  ██████╗██╗██████╗ ██╗  ██╗███████╗██████╗
 ██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗
 ██║     ██║██████╔╝███████║█████╗  ██████╔╝
 ██║     ██║██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗
 ╚██████╗██║██║     ██║  ██║███████╗██║  ██║
  ╚═════╝╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝

  Threat Intelligence Platform
  Built by Mustafa Gomaa
  http://127.0.0.1:5000
    """)
    app.run(host=HOST, port=PORT, debug=DEBUG, use_reloader=False)
