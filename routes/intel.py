"""
CIPHER — Threat Intelligence Routes
External enrichment (VirusTotal, AbuseIPDB), STIX 2.1 export,
settings management, and encryption key rotation.
"""

import json
import secrets
import urllib.request
import urllib.parse
import urllib.error
import base64
from datetime import datetime

from flask import Blueprint, request, jsonify, session

from config import (
    VAULT_FILE, CASES_FILE, ACTORS_FILE, LOGS_FILE,
    WATCHLIST_FILE, NOTES_FILE, KEY_FILE, CONFIG_FILE
)
from crypto.vault import load, load_dict, save, calculate_score, rotate_key
from routes.decorators import require_auth
from routes.audit import write_audit

intel_bp = Blueprint('intel', __name__)


# ── Config helpers ─────────────────────────────────────────────────────────────

def load_config() -> dict:
    """Load application config (API keys etc.) from disk."""
    try:
        with open(CONFIG_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_config(cfg: dict):
    """Persist application config to disk."""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(cfg, f, indent=2)


# ── VirusTotal ─────────────────────────────────────────────────────────────────

@intel_bp.route('/api/vt', methods=['POST'])
@require_auth
def vt_check():
    """
    Check an IOC against VirusTotal.
    Supports: IP, domain, file hash, URL.
    Requires a free VirusTotal API key configured in Settings.
    """
    data    = request.get_json() or {}
    value   = data.get('value', '').strip()
    ioc_type = data.get('type', '')
    api_key = load_config().get('vt_key', '')

    if not api_key:
        return jsonify({'error': 'No VirusTotal API key configured. Go to Settings to add one.'}), 400
    if not value:
        return jsonify({'error': 'IOC value is required'}), 400

    # Build the correct VT endpoint for each IOC type
    try:
        if ioc_type == 'ip':
            url = f'https://www.virustotal.com/api/v3/ip_addresses/{urllib.parse.quote(value)}'
        elif ioc_type == 'domain':
            url = f'https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(value)}'
        elif ioc_type == 'hash':
            url = f'https://www.virustotal.com/api/v3/files/{urllib.parse.quote(value)}'
        elif ioc_type == 'url':
            url_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip('=')
            url    = f'https://www.virustotal.com/api/v3/urls/{url_id}'
        else:
            return jsonify({'error': 'VT check not supported for this IOC type'}), 400

        req = urllib.request.Request(url, headers={
            'x-apikey': api_key,
            'Accept':   'application/json',
        })

        with urllib.request.urlopen(req, timeout=10) as r:
            vt_data = json.loads(r.read().decode())

        stats     = vt_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        harmless   = stats.get('harmless', 0)
        undetected = stats.get('undetected', 0)
        total      = malicious + suspicious + harmless + undetected

        result = {
            'malicious':   malicious,
            'suspicious':  suspicious,
            'harmless':    harmless,
            'undetected':  undetected,
            'total':       total,
            'verdict':     'MALICIOUS' if malicious > 3 else ('SUSPICIOUS' if malicious > 0 or suspicious > 0 else 'CLEAN'),
            'checked_at':  datetime.now().isoformat(),
        }

        write_audit('VT_CHECK', f'{value}: {result["verdict"]} ({malicious}/{total} detections)')
        return jsonify(result)

    except urllib.error.HTTPError as e:
        return jsonify({'error': f'VirusTotal API error: HTTP {e.code}'}), 400
    except Exception as e:
        return jsonify({'error': f'Check failed: {str(e)}'}), 500


# ── AbuseIPDB ──────────────────────────────────────────────────────────────────

@intel_bp.route('/api/abuseipdb', methods=['POST'])
@require_auth
def abuseipdb_check():
    """
    Check an IP address against AbuseIPDB.
    Returns abuse confidence score, country, ISP, Tor status, and report count.
    Only works for IP addresses. Requires a free AbuseIPDB API key.
    """
    data    = request.get_json() or {}
    ip      = data.get('value', '').strip()
    api_key = load_config().get('abuseipdb_key', '')

    if not api_key:
        return jsonify({'error': 'No AbuseIPDB API key configured. Go to Settings to add one.'}), 400
    if not ip:
        return jsonify({'error': 'IP address is required'}), 400

    try:
        params = urllib.parse.urlencode({'ipAddress': ip, 'maxAgeInDays': 90})
        req    = urllib.request.Request(
            f'https://api.abuseipdb.com/api/v2/check?{params}',
            headers={'Key': api_key, 'Accept': 'application/json'},
        )

        with urllib.request.urlopen(req, timeout=10) as r:
            raw = json.loads(r.read().decode())

        dd    = raw.get('data', {})
        score = dd.get('abuseConfidenceScore', 0)

        result = {
            'ip':            dd.get('ipAddress', ip),
            'score':         score,
            'country':       dd.get('countryCode', 'Unknown'),
            'isp':           dd.get('isp', 'Unknown'),
            'total_reports': dd.get('totalReports', 0),
            'last_reported': dd.get('lastReportedAt', ''),
            'is_tor':        dd.get('isTor', False),
            'verdict':       'MALICIOUS' if score >= 50 else ('SUSPICIOUS' if score >= 20 else 'CLEAN'),
            'checked_at':    datetime.now().isoformat(),
        }

        write_audit('ABUSEIPDB_CHECK', f'{ip}: score {score}/100 — {result["verdict"]}')
        return jsonify(result)

    except urllib.error.HTTPError as e:
        return jsonify({'error': f'AbuseIPDB error: HTTP {e.code}'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── STIX 2.1 Export ────────────────────────────────────────────────────────────

@intel_bp.route('/api/export/stix')
@require_auth
def export_stix():
    """
    Export IOCs as a STIX 2.1 bundle.
    STIX (Structured Threat Information eXpression) is the industry standard
    format for sharing threat intelligence between organizations and tools.
    Compatible with any SIEM or TIP that accepts STIX.
    """
    iocs     = load(VAULT_FILE)
    severity = request.args.get('severity', '')
    if severity:
        iocs = [i for i in iocs if i.get('severity') == severity]

    # Map our IOC types to STIX object types
    type_map = {
        'ip':      'ipv4-addr',
        'domain':  'domain-name',
        'url':     'url',
        'email':   'email-addr',
        'hash':    'file',
        'malware': 'malware',
        'apt':     'threat-actor',
        'other':   'indicator',
    }

    # Pattern templates for STIX indicator objects
    pattern_map = {
        'ip':     lambda v: f"[ipv4-addr:value = '{v}']",
        'domain': lambda v: f"[domain-name:value = '{v}']",
        'url':    lambda v: f"[url:value = '{v}']",
        'email':  lambda v: f"[email-addr:value = '{v}']",
        'hash':   lambda v: f"[file:hashes.MD5 = '{v}']",
    }

    bundle_objects = []

    # Identity object — identifies CIPHER as the source
    bundle_objects.append({
        'type':            'identity',
        'spec_version':    '2.1',
        'id':              f'identity--{secrets.token_hex(16)}',
        'created':         datetime.now().isoformat() + 'Z',
        'modified':        datetime.now().isoformat() + 'Z',
        'name':            'CIPHER Threat Intelligence Platform',
        'identity_class':  'system',
    })

    for ioc in iocs:
        stix_type = type_map.get(ioc.get('type', 'other'), 'indicator')
        ts        = ioc.get('created', datetime.now().isoformat())
        if not ts.endswith('Z'):
            ts += 'Z'

        obj = {
            'type':          'indicator' if stix_type not in ['malware', 'threat-actor'] else stix_type,
            'spec_version':  '2.1',
            'id':            f'{stix_type}--{ioc.get("id", secrets.token_hex(16))}',
            'created':       ts,
            'modified':      ts,
            'name':          ioc.get('title') or ioc.get('value', ''),
            'description':   ioc.get('notes', ''),
            'confidence':    {'high': 85, 'medium': 60, 'low': 30}.get(ioc.get('confidence', 'medium'), 60),
            'labels':        ioc.get('tags', []),
            'object_marking_refs': [
                f'marking-definition--tlp-{ioc.get("tlp", "white").lower()}'
            ],
        }

        # Indicator objects need a pattern
        if obj['type'] == 'indicator':
            ioc_val      = ioc.get('value', '')
            ioc_type_key = ioc.get('type', 'other')
            obj['pattern']          = pattern_map.get(ioc_type_key, lambda v: f"[artifact:payload_bin = '{v}']")(ioc_val)
            obj['pattern_type']     = 'stix'
            obj['valid_from']       = ts
            obj['indicator_types']  = ['malicious-activity']

        bundle_objects.append(obj)

    bundle = {
        'type':    'bundle',
        'id':      f'bundle--{secrets.token_hex(16)}',
        'objects': bundle_objects,
    }

    write_audit('EXPORT_STIX', f'STIX 2.1 bundle exported: {len(iocs)} indicators')
    return jsonify(bundle)


# ── JSON Export ────────────────────────────────────────────────────────────────

@intel_bp.route('/api/export')
@require_auth
def export_json():
    """Export vault entries as plain JSON."""
    iocs     = load(VAULT_FILE)
    severity = request.args.get('severity', '')
    if severity:
        iocs = [i for i in iocs if i.get('severity') == severity]
    for ioc in iocs:
        ioc['score'] = calculate_score(ioc)
    write_audit('EXPORT', f'{len(iocs)} IOCs exported as JSON')
    return jsonify({
        'exported_by': session['username'],
        'exported_at': datetime.now().isoformat(),
        'tool':        'CIPHER Threat Intelligence Platform',
        'total':       len(iocs),
        'iocs':        iocs,
    })


# ── Settings ───────────────────────────────────────────────────────────────────

@intel_bp.route('/api/settings', methods=['GET'])
@require_auth
def get_settings():
    """Return non-sensitive settings status — whether API keys are configured."""
    cfg = load_config()
    return jsonify({
        'has_vt_key':    bool(cfg.get('vt_key', '')),
        'has_abuse_key': bool(cfg.get('abuseipdb_key', '')),
    })


@intel_bp.route('/api/settings', methods=['POST'])
@require_auth
def save_settings():
    """Save API keys and other settings. Keys are stored in config.json."""
    data = request.get_json() or {}
    cfg  = load_config()

    if 'vt_key' in data:
        cfg['vt_key'] = data['vt_key']
    if 'abuseipdb_key' in data:
        cfg['abuseipdb_key'] = data['abuseipdb_key']

    save_config(cfg)
    write_audit('SETTINGS_UPDATE', 'Configuration updated')
    return jsonify({'ok': True})


# ── Key Rotation ───────────────────────────────────────────────────────────────

@intel_bp.route('/api/rotate', methods=['POST'])
@require_auth
def rotate():
    """
    Generate a new 256-bit Blowfish key and re-encrypt all data files.
    The old key is permanently overwritten after all files are migrated.
    This limits damage if the current key is ever compromised.
    """
    all_files = [
        VAULT_FILE, CASES_FILE, ACTORS_FILE,
        LOGS_FILE, WATCHLIST_FILE, NOTES_FILE,
    ]

    new_key = secrets.token_bytes(32)
    rotate_key(new_key, all_files)

    ioc_count   = len(load(VAULT_FILE))
    case_count  = len(load(CASES_FILE))
    actor_count = len(load(ACTORS_FILE))

    write_audit(
        'KEY_ROTATE',
        f'All data re-encrypted. {ioc_count} IOCs, {case_count} cases, {actor_count} actors migrated to new Blowfish key.'
    )

    return jsonify({
        'message': f'Key rotated. {ioc_count} IOCs, {case_count} cases, {actor_count} actors re-encrypted with new Blowfish key.'
    })
