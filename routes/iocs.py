"""
CIPHER — IOC Vault Routes
All operations on Indicators of Compromise: list, add, edit, delete, bulk import.
Every IOC is encrypted with Blowfish CBC before being written to disk.
"""

import secrets
from datetime import datetime

from flask import Blueprint, request, jsonify, session

from config import VAULT_FILE
from crypto.vault import load, save, calculate_score
from routes.decorators import require_auth
from routes.audit import write_audit

iocs_bp = Blueprint('iocs', __name__)


def _apply_filters(iocs: list, args: dict) -> list:
    """
    Filter a list of IOCs based on query parameters.
    Supports full-text search across value, title, notes, source, tags, and MITRE fields.
    """
    q        = args.get('q', '').lower()
    ioc_type = args.get('type', '')
    severity = args.get('severity', '')
    status   = args.get('status', '')
    expired  = args.get('expired', '')
    now      = datetime.now().isoformat()

    if q:
        searchable = ['value', 'title', 'notes', 'source', 'tags', 'mitre_techniques', 'analyst']
        iocs = [
            i for i in iocs
            if any(q in str(i.get(field, '')).lower() for field in searchable)
        ]

    if ioc_type:
        iocs = [i for i in iocs if i.get('type') == ioc_type]

    if severity:
        iocs = [i for i in iocs if i.get('severity') == severity]

    if status:
        iocs = [i for i in iocs if i.get('status') == status]

    if expired == '1':
        iocs = [i for i in iocs if i.get('expiry') and i['expiry'] < now]
    elif expired == '0':
        iocs = [i for i in iocs if not i.get('expiry') or i['expiry'] >= now]

    return iocs


@iocs_bp.route('/api/iocs', methods=['GET'])
@require_auth
def list_iocs():
    """List all IOCs, with optional filtering and search."""
    iocs = load(VAULT_FILE)
    iocs = _apply_filters(iocs, request.args)

    # Attach a fresh score to each result
    for ioc in iocs:
        ioc['score'] = calculate_score(ioc)

    # Newest first
    iocs.sort(key=lambda x: x.get('created', ''), reverse=True)

    return jsonify({'iocs': iocs, 'total': len(iocs)})


@iocs_bp.route('/api/iocs', methods=['POST'])
@require_auth
def add_ioc():
    """
    Add a new IOC to the encrypted vault.
    Requires at minimum: type, value, severity.
    """
    data = request.get_json() or {}

    if not data.get('type') or not data.get('value') or not data.get('severity'):
        return jsonify({'error': 'type, value, and severity are required'}), 400

    iocs = load(VAULT_FILE)

    ioc = {
        'id':                secrets.token_hex(8),
        'type':              data['type'],
        'value':             data['value'].strip(),
        'severity':          data['severity'],
        'title':             data.get('title', ''),
        'notes':             data.get('notes', ''),
        'source':            data.get('source', ''),
        'tags':              data.get('tags', []),
        'tlp':               data.get('tlp', 'WHITE'),
        'status':            data.get('status', 'active'),
        'confidence':        data.get('confidence', 'medium'),
        'mitre_techniques':  data.get('mitre_techniques', []),
        'expiry':            data.get('expiry', ''),
        'related_ids':       data.get('related_ids', []),
        'case_id':           data.get('case_id', ''),
        'vt':                data.get('vt', None),
        'analyst':           session['username'],
        'created':           datetime.now().isoformat(),
        'updated':           datetime.now().isoformat(),
    }
    ioc['score'] = calculate_score(ioc)

    iocs.append(ioc)
    save(iocs, VAULT_FILE)

    write_audit('IOC_ADD', f'{ioc["type"].upper()}: {ioc["value"][:60]}')

    return jsonify({'id': ioc['id'], 'score': ioc['score']})


@iocs_bp.route('/api/iocs/<ioc_id>', methods=['GET'])
@require_auth
def get_ioc(ioc_id):
    """Fetch a single IOC by ID."""
    iocs = load(VAULT_FILE)
    ioc  = next((i for i in iocs if i['id'] == ioc_id), None)

    if not ioc:
        return jsonify({'error': 'IOC not found'}), 404

    ioc['score'] = calculate_score(ioc)
    return jsonify(ioc)


@iocs_bp.route('/api/iocs/<ioc_id>', methods=['PUT'])
@require_auth
def update_ioc(ioc_id):
    """Update an existing IOC. Only provided fields are changed."""
    iocs = load(VAULT_FILE)
    idx  = next((i for i, x in enumerate(iocs) if x['id'] == ioc_id), None)

    if idx is None:
        return jsonify({'error': 'IOC not found'}), 404

    data = request.get_json() or {}

    updatable = [
        'type', 'value', 'severity', 'title', 'notes', 'source',
        'tags', 'tlp', 'status', 'confidence', 'mitre_techniques',
        'expiry', 'related_ids', 'case_id', 'vt',
    ]
    for field in updatable:
        if field in data:
            iocs[idx][field] = data[field]

    iocs[idx]['updated'] = datetime.now().isoformat()
    iocs[idx]['score']   = calculate_score(iocs[idx])

    save(iocs, VAULT_FILE)
    write_audit('IOC_UPDATE', f'{iocs[idx]["type"].upper()}: {iocs[idx]["value"][:60]}')

    return jsonify({'score': iocs[idx]['score']})


@iocs_bp.route('/api/iocs/<ioc_id>', methods=['DELETE'])
@require_auth
def delete_ioc(ioc_id):
    """Permanently delete an IOC from the vault."""
    iocs = load(VAULT_FILE)
    ioc  = next((i for i in iocs if i['id'] == ioc_id), None)

    if not ioc:
        return jsonify({'error': 'IOC not found'}), 404

    save([i for i in iocs if i['id'] != ioc_id], VAULT_FILE)
    write_audit('IOC_DELETE', f'{ioc["type"].upper()}: {ioc["value"][:60]}')

    return jsonify({'ok': True})


@iocs_bp.route('/api/iocs/bulk', methods=['POST'])
@require_auth
def bulk_import():
    """
    Import multiple IOCs at once from a newline or comma-separated list.
    Skips duplicates — will not import a value that already exists in the vault.
    """
    data = request.get_json() or {}

    raw      = data.get('data', '')
    ioc_type = data.get('type', 'ip')
    severity = data.get('severity', 'medium')
    source   = data.get('source', 'Bulk Import')
    tags     = data.get('tags', [])
    tlp      = data.get('tlp', 'WHITE')

    # Parse values — support both newline and comma-separated input
    values = list(set(
        v.strip() for v in raw.replace(',', '\n').split('\n')
        if v.strip()
    ))

    if not values:
        return jsonify({'error': 'No valid values found in input'}), 400

    iocs     = load(VAULT_FILE)
    existing = {i['value'] for i in iocs}
    added    = 0
    skipped  = 0

    for value in values:
        if value in existing:
            skipped += 1
            continue

        ioc = {
            'id':               secrets.token_hex(8),
            'type':             ioc_type,
            'value':            value,
            'severity':         severity,
            'title':            f'Bulk import — {ioc_type.upper()}',
            'notes':            '',
            'source':           source,
            'tags':             tags,
            'tlp':              tlp,
            'status':           'active',
            'confidence':       'low',
            'mitre_techniques': [],
            'expiry':           '',
            'related_ids':      [],
            'case_id':          '',
            'vt':               None,
            'analyst':          session['username'],
            'created':          datetime.now().isoformat(),
            'updated':          datetime.now().isoformat(),
        }
        ioc['score'] = calculate_score(ioc)
        iocs.append(ioc)
        existing.add(value)
        added += 1

    save(iocs, VAULT_FILE)
    write_audit('BULK_IMPORT', f'{added} {ioc_type} IOCs imported ({skipped} duplicates skipped)')

    return jsonify({'added': added, 'skipped': skipped})
