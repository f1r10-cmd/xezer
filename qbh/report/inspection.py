"""Read-only CLI views with redacted summaries and scan isolation."""
from collections import Counter
from qbh import db
from qbh.redact import redact

SEVERITIES = ('info', 'low', 'medium', 'high', 'critical')


def scan_id(value=None):
    if value is None:
        row = db.get_db().execute('SELECT id FROM scans ORDER BY id DESC LIMIT 1').fetchone()
        value = row['id'] if row else None
    if value is None or db.get_scan(value) is None:
        raise ValueError('scan_not_found')
    return value


def findings(value=None, severity='low'):
    sid = scan_id(value)
    threshold = SEVERITIES.index(severity)
    return [{'id': row['id'], 'scan_id': sid, 'module': row['module'],
             'severity': row['severity'], 'status': row['status'], 'title': redact(row['title']),
             'confidence': row['confidence']} for row in db.findings_all(sid)
            if row['severity'] in SEVERITIES and SEVERITIES.index(row['severity']) >= threshold]


def compare(left, right):
    left, right = scan_id(left), scan_id(right)
    def inventory(sid):
        rows = db.get_db().execute('SELECT f.module,f.title,f.template,f.status,h.subdomain FROM findings f '
                                  'JOIN hosts h ON h.id=f.host_id WHERE f.scan_id=?', (sid,))
        return Counter(tuple(row) for row in rows)
    a, b = inventory(left), inventory(right)
    def counts(sid):
        return {'findings': len(db.findings_all(sid)),
                'urls': db.get_db().execute('SELECT count(*) FROM urls WHERE scan_id=?', (sid,)).fetchone()[0]}
    return {'left_scan': left, 'right_scan': right, 'left': counts(left), 'right': counts(right),
            'added': sum((b-a).values()), 'removed': sum((a-b).values()),
            'unchanged': sum((a & b).values()),
            'comparison_identity': 'host,module,title,template,status; multiplicity preserved'}
