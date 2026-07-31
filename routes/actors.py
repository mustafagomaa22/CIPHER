"""
CIPHER — Threat Actor Routes
Maintain a database of known APT groups and cybercrime organizations.
Each actor profile includes attribution, TTPs, tools, and MITRE mapping.
"""

import secrets
from datetime import datetime

from flask import Blueprint, request, jsonify, session

from config import ACTORS_FILE
from crypto.vault import load, save
from routes.decorators import require_auth
from routes.audit import write_audit

actors_bp = Blueprint('actors', __name__)


@actors_bp.route('/api/actors', methods=['GET'])
@require_auth
def list_actors():
    """Return all threat actor profiles, sorted alphabetically by name."""
    actors = load(ACTORS_FILE)
    actors.sort(key=lambda x: x.get('name', ''))
    return jsonify({'actors': actors})


@actors_bp.route('/api/actors', methods=['POST'])
@require_auth
def add_actor():
    """Add a new threat actor profile to the database."""
    data = request.get_json() or {}

    if not data.get('name'):
        return jsonify({'error': 'Actor name is required'}), 400

    actors = load(ACTORS_FILE)

    actor = {
        'id':                secrets.token_hex(8),
        'name':              data['name'].strip(),
        'aliases':           data.get('aliases', []),
        'origin':            data.get('origin', 'Unknown'),
        'motivation':        data.get('motivation', 'unknown'),
        'sophistication':    data.get('sophistication', 'medium'),
        'targets':           data.get('targets', []),
        'tools':             data.get('tools', []),
        'mitre_techniques':  data.get('mitre_techniques', []),
        'description':       data.get('description', ''),
        'first_seen':        data.get('first_seen', ''),
        'last_seen':         data.get('last_seen', ''),
        'references':        data.get('references', []),
        'active':            data.get('active', True),
        'analyst':           session['username'],
        'created':           datetime.now().isoformat(),
    }

    actors.append(actor)
    save(actors, ACTORS_FILE)
    write_audit('ACTOR_ADD', f'Threat actor added: {actor["name"]}')

    return jsonify({'id': actor['id']})


@actors_bp.route('/api/actors/<actor_id>', methods=['PUT'])
@require_auth
def update_actor(actor_id):
    """Update an existing threat actor profile."""
    actors = load(ACTORS_FILE)
    idx    = next((i for i, a in enumerate(actors) if a['id'] == actor_id), None)

    if idx is None:
        return jsonify({'error': 'Actor not found'}), 404

    data = request.get_json() or {}

    updatable = [
        'name', 'aliases', 'origin', 'motivation', 'sophistication',
        'targets', 'tools', 'mitre_techniques', 'description',
        'first_seen', 'last_seen', 'references', 'active',
    ]
    for field in updatable:
        if field in data:
            actors[idx][field] = data[field]

    save(actors, ACTORS_FILE)
    write_audit('ACTOR_UPDATE', f'Actor updated: {actors[idx]["name"]}')

    return jsonify({'ok': True})


@actors_bp.route('/api/actors/<actor_id>', methods=['DELETE'])
@require_auth
def delete_actor(actor_id):
    """Remove a threat actor profile."""
    actors = load(ACTORS_FILE)
    actor  = next((a for a in actors if a['id'] == actor_id), None)

    if not actor:
        return jsonify({'error': 'Actor not found'}), 404

    save([a for a in actors if a['id'] != actor_id], ACTORS_FILE)
    write_audit('ACTOR_DELETE', f'Actor deleted: {actor["name"]}')

    return jsonify({'ok': True})
