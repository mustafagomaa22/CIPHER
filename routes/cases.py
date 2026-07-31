"""
CIPHER — Investigation Cases + Notes
Group related IOCs into incident cases.
Each case has a living investigation log — analysts add notes as the incident develops.
"""

import secrets
from datetime import datetime

from flask import Blueprint, request, jsonify, session

from config import CASES_FILE, VAULT_FILE, NOTES_FILE
from crypto.vault import load, load_dict, save, calculate_score
from routes.decorators import require_auth
from routes.audit import write_audit

cases_bp = Blueprint('cases', __name__)


@cases_bp.route('/api/cases', methods=['GET'])
@require_auth
def list_cases():
    """
    List all investigation cases.
    Attaches IOC count and severity breakdown to each case automatically.
    """
    cases = load(CASES_FILE)
    iocs  = load(VAULT_FILE)

    for case in cases:
        # Find IOCs linked to this case
        linked = [i for i in iocs if i.get('case_id') == case['id']]
        case['ioc_count'] = len(linked)
        case['severity_counts'] = {}
        for ioc in linked:
            sev = ioc.get('severity', 'low')
            case['severity_counts'][sev] = case['severity_counts'].get(sev, 0) + 1

    # Newest first
    cases.sort(key=lambda x: x.get('created', ''), reverse=True)
    return jsonify({'cases': cases})


@cases_bp.route('/api/cases', methods=['POST'])
@require_auth
def create_case():
    """Open a new investigation case."""
    data = request.get_json() or {}

    if not data.get('title'):
        return jsonify({'error': 'Case title is required'}), 400

    cases = load(CASES_FILE)

    case = {
        'id':          secrets.token_hex(8),
        'title':       data['title'].strip(),
        'description': data.get('description', ''),
        'severity':    data.get('severity', 'medium'),
        'status':      data.get('status', 'open'),
        'tlp':         data.get('tlp', 'AMBER'),
        'tags':        data.get('tags', []),
        'analyst':     session['username'],
        'created':     datetime.now().isoformat(),
        'updated':     datetime.now().isoformat(),
    }

    cases.append(case)
    save(cases, CASES_FILE)
    write_audit('CASE_CREATE', f'Case opened: {case["title"]}')

    return jsonify({'id': case['id']})


@cases_bp.route('/api/cases/<case_id>', methods=['PUT'])
@require_auth
def update_case(case_id):
    """Update an existing case — status, severity, description, etc."""
    cases = load(CASES_FILE)
    idx   = next((i for i, c in enumerate(cases) if c['id'] == case_id), None)

    if idx is None:
        return jsonify({'error': 'Case not found'}), 404

    data = request.get_json() or {}

    for field in ['title', 'description', 'severity', 'status', 'tlp', 'tags']:
        if field in data:
            cases[idx][field] = data[field]

    cases[idx]['updated'] = datetime.now().isoformat()
    save(cases, CASES_FILE)
    write_audit('CASE_UPDATE', f'Case updated: {cases[idx]["title"]}')

    return jsonify({'ok': True})


@cases_bp.route('/api/cases/<case_id>', methods=['DELETE'])
@require_auth
def delete_case(case_id):
    """Delete a case. Linked IOCs are not deleted — just unlinked."""
    cases = load(CASES_FILE)
    case  = next((c for c in cases if c['id'] == case_id), None)

    if not case:
        return jsonify({'error': 'Case not found'}), 404

    save([c for c in cases if c['id'] != case_id], CASES_FILE)
    write_audit('CASE_DELETE', f'Case deleted: {case["title"]}')

    return jsonify({'ok': True})


@cases_bp.route('/api/cases/<case_id>/iocs')
@require_auth
def case_iocs(case_id):
    """Return all IOCs linked to a specific case."""
    iocs   = load(VAULT_FILE)
    linked = [i for i in iocs if i.get('case_id') == case_id]
    for ioc in linked:
        ioc['score'] = calculate_score(ioc)
    return jsonify({'iocs': linked})


# ── Investigation Notes ────────────────────────────────────────────────────────

@cases_bp.route('/api/cases/<case_id>/notes', methods=['GET'])
@require_auth
def get_notes(case_id):
    """Return all notes for a specific case, newest first."""
    all_notes = load_dict(NOTES_FILE)
    return jsonify({'notes': all_notes.get(case_id, [])})


@cases_bp.route('/api/cases/<case_id>/notes', methods=['POST'])
@require_auth
def add_note(case_id):
    """
    Add a note to the investigation log.
    Note types: update, finding, action, ioc, tlp
    """
    data    = request.get_json() or {}
    content = data.get('content', '').strip()

    if not content:
        return jsonify({'error': 'Note content cannot be empty'}), 400

    all_notes = load_dict(NOTES_FILE)

    note = {
        'id':      secrets.token_hex(8),
        'content': content,
        'type':    data.get('type', 'update'),
        'analyst': session['username'],
        'ts':      datetime.now().isoformat(),
        'edited':  False,
    }

    if case_id not in all_notes:
        all_notes[case_id] = []

    # Insert at the beginning — newest note appears first
    all_notes[case_id].insert(0, note)
    save(all_notes, NOTES_FILE)

    write_audit('CASE_NOTE', f'Note added to case {case_id}: {content[:60]}')
    return jsonify({'note': note})


@cases_bp.route('/api/cases/<case_id>/notes/<note_id>', methods=['PUT'])
@require_auth
def edit_note(case_id, note_id):
    """Edit an existing note. Marks it as edited with a timestamp."""
    data    = request.get_json() or {}
    content = data.get('content', '').strip()

    if not content:
        return jsonify({'error': 'Content cannot be empty'}), 400

    all_notes  = load_dict(NOTES_FILE)
    case_notes = all_notes.get(case_id, [])
    idx        = next((i for i, n in enumerate(case_notes) if n['id'] == note_id), None)

    if idx is None:
        return jsonify({'error': 'Note not found'}), 404

    case_notes[idx]['content']   = content
    case_notes[idx]['edited']    = True
    case_notes[idx]['edited_ts'] = datetime.now().isoformat()
    all_notes[case_id]           = case_notes

    save(all_notes, NOTES_FILE)
    return jsonify({'ok': True})


@cases_bp.route('/api/cases/<case_id>/notes/<note_id>', methods=['DELETE'])
@require_auth
def delete_note(case_id, note_id):
    """Delete a note from the investigation log."""
    all_notes  = load_dict(NOTES_FILE)
    case_notes = all_notes.get(case_id, [])
    all_notes[case_id] = [n for n in case_notes if n['id'] != note_id]

    save(all_notes, NOTES_FILE)
    write_audit('CASE_NOTE_DELETE', f'Note deleted from case {case_id}')

    return jsonify({'ok': True})
