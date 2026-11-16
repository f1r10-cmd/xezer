"""Durable explainable plans in the existing database; no credential-bearing views."""
from dataclasses import asdict
from qbh import db
from qbh.ingest.har_importer import canonical

TERMINAL = {'completed', 'candidate', 'confirmed', 'inconclusive', 'failed'}


def get(plan_id, scan_id):
    row = db.get_db().execute('SELECT * FROM test_plans WHERE id=? AND scan_id=?', (plan_id, scan_id)).fetchone()
    return dict(row) if row else None


def _event(conn, plan_id, status, reason, prerequisite_hash):
    conn.execute('INSERT INTO test_plan_events(plan_id,status,reason,prerequisite_hash,created_at) VALUES(?,?,?,?,?)',
                 (plan_id, status, reason, prerequisite_hash, db._now()))


def save(plan_id, context, plan, status, reason):
    conn = db.get_db()
    previous = get(plan_id, context.scan_id)
    if previous:
        if previous['user_decision'] == 'rejected':
            status, reason = 'rejected', 'user_rejected'
        elif previous['prerequisite_hash'] == plan.prerequisite_hash and previous['status'] in TERMINAL:
            status, reason = previous['status'], previous['reason']
    with conn:
        conn.execute('INSERT INTO test_plans '
                     '(id,scan_id,request_id,url_id,vuln_class,prerequisite_hash,status,reason,'
                     'missing_prerequisites,evidence_refs,classifications,created_at,updated_at) '
                     'VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET '
                     'prerequisite_hash=excluded.prerequisite_hash,status=excluded.status,reason=excluded.reason,'
                     'missing_prerequisites=excluded.missing_prerequisites,evidence_refs=excluded.evidence_refs,'
                     'classifications=excluded.classifications,updated_at=excluded.updated_at',
                     (plan_id, context.scan_id, context.request_id, context.url_id, plan.vuln_class,
                      plan.prerequisite_hash, status, reason, canonical(plan.missing_prerequisites),
                      canonical(plan.evidence_refs), canonical([asdict(c) for c in context.classifications]),
                      db._now(), db._now()))
        if not previous or (previous['status'], previous['reason'], previous['prerequisite_hash']) != (status, reason, plan.prerequisite_hash):
            _event(conn, plan_id, status, reason, plan.prerequisite_hash)
    return get(plan_id, context.scan_id)


def transition(plan_id, scan_id, status, reason, *, result_enc=None, finding_id=None):
    conn = db.get_db()
    with conn:
        row = get(plan_id, scan_id)
        if row is None:
            raise ValueError('plan_not_in_scan')
        if result_enc is not None:
            conn.execute('INSERT INTO test_plan_results(plan_id,result_enc,created_at) VALUES(?,?,?)',
                         (plan_id, result_enc, db._now()))
        if row['user_decision'] == 'rejected' and status != 'rejected':
            return row
        conn.execute('UPDATE test_plans SET status=?,reason=?,result_enc=COALESCE(?,result_enc),'
                     'finding_id=COALESCE(?,finding_id),updated_at=? WHERE id=? AND scan_id=?',
                     (status, reason, result_enc, finding_id, db._now(), plan_id, scan_id))
        _event(conn, plan_id, status, reason, row['prerequisite_hash'])
    return get(plan_id, scan_id)


def decide(plan_id, scan_id, *, approve, reason):
    if not reason:
        raise ValueError('decision_reason_required')
    conn = db.get_db()
    with conn:
        row = get(plan_id, scan_id)
        if row is None:
            raise ValueError('plan_not_in_scan')
        # This is a preference only. A subsequent planner pass rechecks prerequisites and RoE.
        conn.execute('UPDATE test_plans SET user_decision=?,decision_reason=? WHERE id=? AND scan_id=?',
                     ('approved' if approve else 'rejected', reason, plan_id, scan_id))
        transition(plan_id, scan_id, (row['status'] if row['status'] in TERMINAL else 'pending') if approve else 'rejected',
                   'user_approved_recheck_required' if approve else 'user_rejected')


def list_plans(scan_id=None):
    fields = ('id,scan_id,request_id,url_id,vuln_class,prerequisite_hash,status,reason,'
              'missing_prerequisites,evidence_refs,classifications,user_decision,decision_reason,finding_id')
    sql = 'SELECT ' + fields + ' FROM test_plans'
    rows = db.get_db().execute(sql + (' WHERE scan_id=?' if scan_id is not None else '') + ' ORDER BY created_at,id',
                              (scan_id,) if scan_id is not None else ())
    return [dict(row) for row in rows]
