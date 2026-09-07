"""Optional experience-v1 semantics over unchanged record/v1 bytes and relations.

All metadata is a publisher claim, never an instruction or proof of truth.
The codec fits the existing opaque provenance.source_ref slot so old readers
can store, sign and share the same record without a schema migration.
"""
from __future__ import annotations
from typing import Any, Mapping
import re

PREFIX = "memory-vault:experience:v1:"
TYPES = frozenset({'observation', 'experiment', 'inference', 'hearsay',
                   'speculation', 'summary', 'external_source', 'unspecified'})
RELATIONS = frozenset({'heard_from', 'derived_from', 'independently_confirms',
                       'contradicts', 'summarizes', 'applies_to', 'fails_under',
                       'proposes_supersession'})
LINEAGE = frozenset({'heard_from', 'derived_from', 'summarizes'})
EVIDENCE = LINEAGE | {'independently_confirms', 'contradicts'}
MAX_BYTES = 2048
_ID = re.compile(r'mem_[0-9a-f]{40}\Z')


def normalize(value: Any) -> dict[str, Any]:
    from memory_vault import MemoryError, canonical_bytes, strict_json_loads
    if not isinstance(value, dict):
        raise MemoryError('invalid_experience')
    # Copy without mutating caller-owned metadata, preserving unknown fields.
    result = strict_json_loads(canonical_bytes(value))
    kind = result.get('epistemic_type', 'unspecified')
    if not isinstance(kind, str) or not kind or len(kind) > 64:
        raise MemoryError('invalid_experience')
    result['epistemic_type'] = kind
    refs = result.get('source_memory_refs', [])
    evidence = result.get('evidence_refs', [])
    if (not isinstance(refs, list) or len(refs) > 16
            or any(not isinstance(x, str) or not _ID.fullmatch(x) for x in refs)
            or not isinstance(evidence, list) or len(evidence) > 16
            or any(not isinstance(x, str) or not x or len(x.encode('utf-8')) > 512 for x in evidence)):
        raise MemoryError('invalid_experience')
    relations = result.get('relations', [])
    if not isinstance(relations, list) or len(relations) > 16:
        raise MemoryError('invalid_experience')
    pairs = set()
    for relation in relations:
        if (not isinstance(relation, dict) or set(relation) != {'type', 'target'}
                or not isinstance(relation['type'], str) or not relation['type']
                or len(relation['type']) > 64 or not isinstance(relation['target'], str)
                or not _ID.fullmatch(relation['target'])):
            raise MemoryError('invalid_experience')
        pairs.add((relation['type'], relation['target']))
    # An explicit independently-observed/experimental counterclaim is a new
    # assertion. A copy with no such assertion is a retelling, not recollection.
    independent = kind in {'observation', 'experiment'} and any(
        typ in {'independently_confirms', 'contradicts'} for typ, _ in pairs)
    if kind == 'observation' and not independent and (refs or any(t in LINEAGE for t, _ in pairs)):
        result['epistemic_type'] = 'hearsay'
    if not independent or result['epistemic_type'] == 'hearsay':
        relation_type = {'hearsay': 'heard_from', 'summary': 'summarizes'}.get(result['epistemic_type'], 'derived_from')
        pairs.update((relation_type, target) for target in refs)
    if len(pairs) > 16:
        raise MemoryError('invalid_experience')
    if pairs or 'relations' in result:
        result['relations'] = [{'type': t, 'target': target} for t, target in sorted(pairs)]
    if 'source_memory_refs' in result:
        result['source_memory_refs'] = sorted(set(refs))
    if 'evidence_refs' in result:
        result['evidence_refs'] = sorted(set(evidence))
    if len(canonical_bytes(result)) > MAX_BYTES or b'\\u0000' in canonical_bytes(result):
        raise MemoryError('experience_too_large')
    return result


def _inherit_native(value: Any, relations: list[dict[str, str]]) -> Any:
    if not isinstance(value, dict) or not isinstance(value.get('relations', []), list):
        return value
    typed = value.get('relations', [])
    targets = {r['target'] for r in typed if isinstance(r, dict)
               and isinstance(r.get('type'), str) and r['type'] in LINEAGE
               and isinstance(r.get('target'), str)}
    native = [r for r in relations if r['type'] == 'derived_from' and r['target'] not in targets]
    return {**value, 'relations': [*typed, *native]} if native else value


def encode(value: Any, provenance: Mapping[str, str], relations: list[dict[str, str]]) -> tuple[dict[str, str], list[dict[str, str]]]:
    from memory_vault import MemoryError, canonical_bytes
    # The same native lineage rule applies to writes and received records.
    metadata = normalize(_inherit_native(value, relations))
    wrapper: dict[str, Any] = {'metadata': metadata}
    if 'source_ref' in provenance:
        if provenance['source_ref'].startswith(PREFIX):
            raise MemoryError('ambiguous_experience_source')
        wrapper['source_ref'] = provenance['source_ref']
    encoded = PREFIX + canonical_bytes(wrapper).decode('utf-8')
    if len(encoded.encode('utf-8')) > MAX_BYTES:
        raise MemoryError('experience_too_large')
    projected = {(r['type'], r['target']) for r in relations}
    for r in metadata.get('relations', []):
        if r['type'] in RELATIONS:
            projected.add(('derived_from' if r['type'] in LINEAGE else 'related_to', r['target']))
    # source refs participate in bounded sharing even for independent experiments.
    projected.update(('related_to', target) for target in metadata.get('source_memory_refs', []))
    return {**provenance, 'source_ref': encoded}, [{'type': t, 'target': target} for t, target in sorted(projected)]


def decode(record: Mapping[str, Any]) -> dict[str, Any]:
    from memory_vault import MemoryError, strict_json_loads
    ref = record.get('provenance', {}).get('source_ref', '')
    if not isinstance(ref, str) or not ref.startswith(PREFIX):
        inherited = [r for r in record.get('relations', []) if r['type'] == 'derived_from']
        return {'epistemic_type': 'unspecified', **({'relations': inherited} if inherited else {})}
    try:
        wrapper = strict_json_loads(ref[len(PREFIX):])
        value = normalize(_inherit_native(wrapper['metadata'], record.get('relations', [])))
        if value['epistemic_type'] not in TYPES:
            value['declared_epistemic_type'] = value['epistemic_type']
            value['epistemic_type'] = 'unspecified'
        if 'source_ref' in wrapper:
            value['original_source_ref'] = wrapper['source_ref']
        return value
    except (MemoryError, KeyError, TypeError, ValueError):
        inherited = [r for r in record.get('relations', []) if r['type'] == 'derived_from']
        return {'epistemic_type': 'unspecified', 'metadata_status': 'unrecognized',
                **({'relations': inherited} if inherited else {})}


def summarize(records: Mapping[str, Mapping[str, Any]], root: str,
              verifications: Mapping[str, Mapping[str, Any]] | None = None,
              *, truncated: bool = False) -> dict[str, Any]:
    """Bounded local publisher claims; absent edges and cycles never add evidence."""
    decoded = {key: decode(value) for key, value in records.items()}
    edges = [(source, r['type'], r['target']) for source, value in decoded.items()
             for r in value.get('relations', []) if r['type'] in EVIDENCE]
    adjacent: dict[str, set[str]] = {key: set() for key in records}
    for source, _, target in edges:
        if target in records:
            adjacent[source].add(target)
            adjacent[target].add(source)
    connected, todo = set(), [root]
    while todo:
        node = todo.pop()
        if node in connected or node not in records:
            continue
        connected.add(node)
        todo.extend(adjacent[node] - connected)
    parents = {node: set() for node in connected}
    missing = set()
    for source, typ, target in edges:
        if source not in connected:
            continue
        if target not in records:
            missing.add(target)
        if typ in LINEAGE:
            parents[source].add(target)
    roots = {node for node in connected if not parents[node]}
    # Kahn's algorithm: linear work even for a dense diamond/forwarding graph.
    degrees = {node: 0 for node in connected}
    children = {node: set() for node in connected}
    for node in connected:
        for parent in parents[node] & connected:
            degrees[node] += 1
            children[parent].add(node)
    queue = [node for node, degree in degrees.items() if degree == 0]
    processed = 0
    while queue:
        node = queue.pop()
        processed += 1
        for child in children[node]:
            degrees[child] -= 1
            if degrees[child] == 0:
                queue.append(child)
    cycle = processed != len(connected)
    unattributed: set[str] = set()
    def independent_sources(relation: str) -> set[str]:
        identities = set()
        for source, typ, target in edges:
            if (typ != relation or source not in connected or target not in connected or parents[source]
                    or decoded[source]['epistemic_type'] not in {'observation', 'experiment'}):
                continue
            proof = (verifications or {}).get(source, {})
            if proof.get('eligible_for_context') is False or proof.get('admission') == 'quarantined':
                continue
            # A current attester is not the origin of these immutable claims.
            # This first-known local pin is only a deduplication clue, never
            # portable authorship proof or permission for a revoked identity.
            origin = proof.get('local_origin_key_id')
            if isinstance(origin, str) and re.fullmatch(r'ed25519_[0-9a-f]{64}', origin):
                identities.add(origin)
            elif (proof.get('local_origin_key_present') is True or origin is not None
                    or proof.get('signature_verified_at_admission') is True
                    or proof.get('admission') == 'verified'):
                unattributed.add(source)
            else:
                # Never-signed records (and standalone claim-only summaries)
                # retain record identity, without certifying independence.
                identities.add(source)
        return identities
    confirmations = independent_sources('independently_confirms')
    contradictions = independent_sources('contradicts')
    return {
        'propagation_count': sum(decoded[node]['epistemic_type'] == 'hearsay' or
                                 any(s == node and t == 'heard_from' for s, t, _ in edges) for node in connected),
        'unique_origin_roots': len(roots),
        'independent_confirmation_count': len(confirmations),
        'contradiction_count': len(contradictions),
        'records_considered': len(connected), 'cycle_detected': cycle,
        'truncated': truncated or bool(missing) or cycle or bool(unattributed),
        'origin_identity_basis': 'local_first_verified_signer_or_unsigned_record',
        'origin_identity_incomplete': bool(unattributed),
        'unattributed_evidence_count': len(unattributed),
        'missing_reference_count': len(missing),
        'basis': 'local_declared_provenance', 'independence_verified': False,
        'truth_score': None,
    }
