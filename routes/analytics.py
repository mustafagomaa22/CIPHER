"""
CIPHER — Analytics, Feeds, Watchlist, Graph
Dashboard statistics, 30-day timeline, IOC relationship graph,
live threat feed integration, and watchlist alerting.
"""

import secrets
import urllib.request
import urllib.error
from datetime import datetime, timedelta

from flask import Blueprint, request, jsonify, session

from config import VAULT_FILE, CASES_FILE, WATCHLIST_FILE, THREAT_FEEDS, FEED_MAX_RESULTS, FEED_TIMEOUT
from crypto.vault import load, load_dict, save, calculate_score
from routes.decorators import require_auth
from routes.audit import write_audit

analytics_bp = Blueprint('analytics', __name__)


# ── Dashboard Stats ────────────────────────────────────────────────────────────

@analytics_bp.route('/api/analytics')
@require_auth
def analytics():
    """
    Aggregate statistics for the dashboard.
    Returns severity breakdown, type distribution, MITRE frequency,
    top tags, active/expired counts, and 30-day entry count.
    """
    iocs  = load(VAULT_FILE)
    cases = load(CASES_FILE)
    now   = datetime.now().isoformat()
    cutoff_30d = (datetime.now() - timedelta(days=30)).isoformat()

    by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    by_type     = {}
    by_status   = {}
    by_tlp      = {}
    mitre_count = {}
    tag_count   = {}
    active      = expired = recent = 0
    scores      = []

    for ioc in iocs:
        # Severity
        sev = ioc.get('severity', 'low')
        if sev in by_severity:
            by_severity[sev] += 1

        # Type
        t = ioc.get('type', 'other')
        by_type[t] = by_type.get(t, 0) + 1

        # Status
        st = ioc.get('status', 'active')
        by_status[st] = by_status.get(st, 0) + 1

        # TLP
        tlp = ioc.get('tlp', 'WHITE')
        by_tlp[tlp] = by_tlp.get(tlp, 0) + 1

        # MITRE technique frequency
        for technique in ioc.get('mitre_techniques', []):
            mitre_count[technique] = mitre_count.get(technique, 0) + 1

        # Tag frequency
        for tag in ioc.get('tags', []):
            tag_count[tag] = tag_count.get(tag, 0) + 1

        if ioc.get('status') == 'active':
            active += 1
        if ioc.get('expiry') and ioc['expiry'] < now:
            expired += 1
        if ioc.get('created', '') >= cutoff_30d:
            recent += 1

        scores.append(calculate_score(ioc))

    top_mitre = sorted(mitre_count.items(), key=lambda x: -x[1])[:10]
    top_tags  = sorted(tag_count.items(),   key=lambda x: -x[1])[:10]
    avg_score = round(sum(scores) / len(scores)) if scores else 0

    return jsonify({
        'total':        len(iocs),
        'active':       active,
        'expired':      expired,
        'recent_30d':   recent,
        'avg_score':    avg_score,
        'total_cases':  len(cases),
        'open_cases':   sum(1 for c in cases if c.get('status') == 'open'),
        'by_severity':  by_severity,
        'by_type':      by_type,
        'by_status':    by_status,
        'by_tlp':       by_tlp,
        'top_mitre':    top_mitre,
        'top_tags':     top_tags,
    })


# ── 30-Day Timeline ────────────────────────────────────────────────────────────

@analytics_bp.route('/api/timeline')
@require_auth
def timeline():
    """
    Return daily IOC counts for the last N days (default 30).
    Broken down by severity so the chart can show stacked bars.
    Missing days are filled with zeros so the chart is always complete.
    """
    days   = int(request.args.get('days', 30))
    cutoff = (datetime.now() - timedelta(days=days)).isoformat()
    iocs   = load(VAULT_FILE)

    daily_total = {}
    daily_sev   = {'critical': {}, 'high': {}, 'medium': {}, 'low': {}}

    for ioc in iocs:
        created = ioc.get('created', '')
        if not created or created < cutoff:
            continue
        day = created[:10]
        daily_total[day] = daily_total.get(day, 0) + 1

        sev = ioc.get('severity', 'low')
        if sev in daily_sev:
            daily_sev[sev][day] = daily_sev[sev].get(day, 0) + 1

    # Build a complete list of days — fill gaps with zeros
    all_days = [
        (datetime.now() - timedelta(days=days - n - 1)).strftime('%Y-%m-%d')
        for n in range(days)
    ]
    for day in all_days:
        daily_total.setdefault(day, 0)
        for sev in daily_sev:
            daily_sev[sev].setdefault(day, 0)

    return jsonify({
        'days':        all_days,
        'total':       [daily_total[d] for d in all_days],
        'by_severity': {sev: [daily_sev[sev][d] for d in all_days] for sev in daily_sev},
    })


# ── IOC Relationship Graph ─────────────────────────────────────────────────────

@analytics_bp.route('/api/graph')
@require_auth
def graph():
    """
    Return node/link data for the D3.js IOC relationship map.
    Nodes are IOCs. Links are drawn between IOCs that reference each other
    via the related_ids field.
    """
    iocs   = load(VAULT_FILE)
    ioc_ids = {ioc['id'] for ioc in iocs}
    nodes  = []
    links  = []

    for ioc in iocs:
        nodes.append({
            'id':       ioc['id'],
            'label':    ioc['value'][:25],
            'type':     ioc['type'],
            'severity': ioc['severity'],
            'score':    calculate_score(ioc),
        })
        for related_id in ioc.get('related_ids', []):
            # Only draw links between IOCs that both exist in the vault
            if related_id in ioc_ids:
                links.append({'source': ioc['id'], 'target': related_id})

    return jsonify({'nodes': nodes, 'links': links})


# ── Live Threat Feeds ──────────────────────────────────────────────────────────

@analytics_bp.route('/api/feeds')
@require_auth
def feeds():
    """
    Pull real-time IOCs from configured public threat feeds.
    Currently pulling from Feodo Tracker and URLhaus.
    Each feed result can be imported into the vault with one click.
    """
    results = []

    for feed in THREAT_FEEDS:
        try:
            req = urllib.request.Request(
                feed['url'],
                headers={'User-Agent': 'CIPHER-TI/3.0 (Threat Intelligence Platform)'},
            )
            with urllib.request.urlopen(req, timeout=FEED_TIMEOUT) as r:
                text = r.read().decode('utf-8', errors='ignore')

            lines = [l for l in text.split('\n') if l and not l.startswith('#')]
            for line in lines[:FEED_MAX_RESULTS]:
                value = line.strip().split(',')[0].strip().strip('"')
                if value and len(value) > 3:
                    results.append({
                        'source': feed['name'],
                        'type':   feed['type'],
                        'value':  value,
                    })

        except Exception:
            # Feed unavailable — skip silently, don't crash the whole endpoint
            results.append({
                'source': feed['name'],
                'type':   feed['type'],
                'value':  '',
                'error':  'Feed temporarily unavailable',
            })

    valid = [r for r in results if r.get('value')]
    write_audit('FEEDS_FETCH', f'Pulled {len(valid)} IOCs from {len(THREAT_FEEDS)} feeds')
    return jsonify({'feeds': valid})


# ── Watchlist ──────────────────────────────────────────────────────────────────

@analytics_bp.route('/api/watchlist', methods=['GET'])
@require_auth
def get_watchlist():
    """Return the current watchlist."""
    return jsonify({'watchlist': load(WATCHLIST_FILE)})


@analytics_bp.route('/api/watchlist', methods=['POST'])
@require_auth
def add_to_watchlist():
    """Add an IOC value to the watchlist for automatic feed monitoring."""
    data  = request.get_json() or {}
    value = data.get('value', '').strip()

    if not value:
        return jsonify({'error': 'Value is required'}), 400

    watchlist = load(WATCHLIST_FILE)

    if any(w['value'] == value for w in watchlist):
        return jsonify({'error': 'This value is already on the watchlist'}), 409

    item = {
        'id':      secrets.token_hex(8),
        'value':   value,
        'type':    data.get('type', 'ip'),
        'label':   data.get('label', ''),
        'analyst': session['username'],
        'created': datetime.now().isoformat(),
        'hits':    [],
    }

    watchlist.append(item)
    save(watchlist, WATCHLIST_FILE)
    write_audit('WATCHLIST_ADD', f'Watching: {value}')

    return jsonify({'id': item['id']})


@analytics_bp.route('/api/watchlist/<item_id>', methods=['DELETE'])
@require_auth
def remove_from_watchlist(item_id):
    """Remove an item from the watchlist."""
    watchlist = load(WATCHLIST_FILE)
    item      = next((w for w in watchlist if w['id'] == item_id), None)

    if not item:
        return jsonify({'error': 'Watchlist item not found'}), 404

    save([w for w in watchlist if w['id'] != item_id], WATCHLIST_FILE)
    write_audit('WATCHLIST_REMOVE', f'Removed: {item["value"]}')

    return jsonify({'ok': True})


@analytics_bp.route('/api/watchlist/check', methods=['POST'])
@require_auth
def check_watchlist():
    """
    Check a list of values against the watchlist.
    Called automatically after every feed pull.
    Returns any matches found, and records hit timestamps.
    """
    data      = request.get_json() or {}
    values    = set(data.get('values', []))
    context   = data.get('context', 'Manual check')
    watchlist = load(WATCHLIST_FILE)
    matches   = []
    now       = datetime.now().isoformat()

    for item in watchlist:
        if item['value'] in values:
            hit = {'ts': now, 'context': context}
            item.setdefault('hits', []).append(hit)
            item['hits'] = item['hits'][-20:]  # keep last 20 hits
            matches.append({'watchlist_item': item, 'matched_value': item['value']})

    if matches:
        save(watchlist, WATCHLIST_FILE)
        write_audit('WATCHLIST_HIT', f'{len(matches)} watchlist matches found in feed')

    return jsonify({'matches': matches, 'total': len(matches)})
