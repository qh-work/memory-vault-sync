"""Shared durable fact conflicts across the two authorized directory stores.

Only internal callers with a fully authenticated publication or already stored
records may call this helper, inside their writer transaction. It grants no
authority and allocates no replacement resource.
"""
import json


LEGACY = 'open_provider_facts'
REPAIR = 'open_repair_index_facts'


def _one(db, sql, parameters=()):
    cursor = db.execute(sql, parameters)
    values = cursor.fetchone()
    return dict(zip((column[0] for column in cursor.description), values)) if values is not None else None


def _conflict(db, table, row, second):
    if row['second_record'] is None:
        if table == REPAIR:
            allocation = _one(db, 'SELECT budget,metadata_bytes FROM open_repair_index_resources WHERE allocation_id=?',
                              (row['allocation_id'],))
            if allocation is None:
                raise ValueError('repair_index_allocation_missing')
            if allocation['metadata_bytes'] + len(second) > json.loads(bytes(allocation['budget']))['max_meta_bytes']:
                # The original allocation cannot be enlarged to retain a fork.
                # Keep its first original and a permanent refusal, as with the
                # existing same-store conflict-capacity path.
                db.execute('INSERT OR IGNORE INTO open_repair_index_blocked_roots VALUES(?,?)',
                           (row['root_digest'], 'repair_index_fact_capacity'))
                db.execute('UPDATE '+table+" SET status='conflict' WHERE fact_key=?", (row['fact_key'],))
                return
            db.execute('UPDATE open_repair_index_resources SET metadata_bytes=metadata_bytes+? WHERE allocation_id=?',
                       (len(second), row['allocation_id']))
        # The legacy FACT_CHARGE already reserves two bounded fact originals.
        db.execute('UPDATE '+table+" SET second_record=?,status='conflict' WHERE fact_key=?", (second, row['fact_key']))
    else:
        db.execute('UPDATE '+table+" SET status='conflict' WHERE fact_key=?", (row['fact_key'],))


def observe_cross_fact(db, table, *, key, revision, digest, raw):
    """Return a refusal suffix, committing observations in the caller's gate.

    `raw` is the real verified signed fact. An equal-revision fork is sticky
    even if a later caller uses the other API with a higher revision.
    """
    if table not in (LEGACY, REPAIR) or not db.in_transaction:
        raise ValueError('provider_storage_transaction')
    other = REPAIR if table == LEGACY else LEGACY
    if _one(db, "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (other,)) is None:
        return None
    prior = _one(db, 'SELECT * FROM '+other+' WHERE fact_key=?', (key,))
    if prior is None:
        return None
    own = _one(db, 'SELECT * FROM '+table+' WHERE fact_key=?', (key,))
    if prior['status'] in ('conflict', 'withdrawn') or own is not None and own['status'] in ('conflict', 'withdrawn'):
        return 'inactive'
    # Older releases could already have admitted a fork into separate tables.
    # A new higher revision must not overwrite that evidence before lookup.
    if own is not None and own['revision'] == prior['revision'] and own['digest'] != prior['digest']:
        _conflict(db, other, prior, bytes(own['record']))
        _conflict(db, table, own, bytes(prior['record']))
        return 'conflict'
    if revision < prior['revision']:
        return 'rollback'
    if revision == prior['revision'] and digest != prior['digest']:
        _conflict(db, other, prior, bytes(raw))
        if own is not None and own['revision'] == revision:
            _conflict(db, table, own, bytes(prior['record']))
        return 'conflict'
    return None
