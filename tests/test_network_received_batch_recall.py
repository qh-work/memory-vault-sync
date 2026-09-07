"""Synthetic received-batch inspection preserves historical transport and memory."""
from contextlib import closing, contextmanager, ExitStack
from pathlib import Path
import base64
import hashlib
import sqlite3
import unittest
from unittest.mock import patch

from memory_vault import build_record, canonical_bytes, strict_json_loads
from memory_vault_experience import encode
from memory_vault_network import NetworkClient
from memory_vault_trust import Identity, TrustStore
import memory_vault_network_recovery as recovery
from tests.test_network_hints import control, policy, query_offer, outbox_row
from tests.test_network_hints_batch import choose
from tests.test_network_hints_cancellation import cancel
from tests.test_network_message_semantics import agent, records, proofs, vault_snapshot, inject_ciphertext
from tests.test_network_recovery import archive
from tests.test_network_worker import fixture


QUERY = "Synthetic received batch"


def prepare_batch(test, owner, requester, transport, *, cross_pages=False, long_text=False,
                  trusted_witnesses=True, suffix="initial", transfer_call=None, receive_call=None):
    """Two endpoints, independently signed V1/V2 evidence, and real JWE delivery.

    Independent witness keys are local synthetic test identities, not extra
    network nodes. Their original signatures travel through the existing relay.
    """
    witnesses = [Identity.generate(owner.config_path.parent / ("synthetic-witness-" + suffix + "-" + str(i) + ".json"))
                 for i in range(2)]
    for endpoint in (owner, requester):
        trust = TrustStore(endpoint.client_config.trust_path)
        for witness in witnesses:
            if endpoint is owner or trusted_witnesses:
                trust.add(witness.public_descriptor())
    prepared, attestations = [], {}
    def add(label, text, metadata, signer):
        provenance, relations = encode(metadata, {"agent_ref": "synthetic:" + label + ":" + suffix}, [])
        record = build_record(kind="observation", text=text, created_at="2026-01-01T00:00:00Z",
                              provenance=provenance, relations=relations)
        prepared.append(record)
        attestations[record["memory_id"]] = signer.sign_record(record)
        return record["memory_id"]
    extra = (' 😀中\\"\n' * 170) if long_text else ""
    dependency = add("setup", "Synthetic shared setup evidence", {"epistemic_type": "observation"}, owner.identity)
    a = add("A", QUERY + " method X failed under V1" + extra,
        {"epistemic_type": "observation", "source_agent": "synthetic-A", "observed_under": {"environment": "V1"}}, owner.identity)
    b = add("B", QUERY + " independent experiment X failed under V1" + extra,
        {"epistemic_type": "experiment", "source_agent": "synthetic-B", "observed_under": {"environment": "V1"},
         "relations": [{"type": "independently_confirms", "target": a}, {"type": "applies_to", "target": dependency}]}, witnesses[0])
    c = add("C", QUERY + " independent experiment X succeeded under V2" + extra,
        {"epistemic_type": "experiment", "source_agent": "synthetic-C",
         "observed_under": {"environment": "V2", "build_id": 9223372036854775807},
         "retry_predicate": {"environment_changed": True},
         "relations": [{"type": "contradicts", "target": a}, {"type": "contradicts", "target": b},
                       {"type": "applies_to", "target": dependency}]}, witnesses[1])
    summary = add("summary", QUERY + " keep both contextual outcomes; no timeless conclusion" + extra,
        {"epistemic_type": "summary", "context": "V1 and V2 are different environments",
         "relations": [{"type": "summarizes", "target": mid} for mid in (a, b, c, dependency)]}, owner.identity)
    roots = [summary, c, a, b]  # Explicit request order, independent of export order.
    hint_ids = list(roots)
    if cross_pages:
        # Fill the three ID intervals so the four meaningful roots occur on
        # four separate pages. This search is bounded and uses only synthetic
        # canonical candidates; no protocol ID is altered or forged.
        ordered = sorted(roots)
        buckets = [[] for _ in range(3)]
        for index in range(8192):
            candidate = build_record(kind="observation", text=QUERY + " filler " + str(index),
                                     created_at="2026-01-01T00:00:00Z")
            mid = candidate["memory_id"]
            for slot in range(3):
                if len(buckets[slot]) < 3 and ordered[slot] < mid < ordered[slot + 1]:
                    buckets[slot].append(candidate)
                    break
            if all(len(bucket) == 3 for bucket in buckets):
                break
        test.assertTrue(all(len(bucket) == 3 for bucket in buckets), "bounded synthetic ID interval fill exhausted")
        for record in [item for bucket in buckets for item in bucket]:
            prepared.append(record)
            attestations[record["memory_id"]] = owner.identity.sign_record(record)
            hint_ids.append(record["memory_id"])
    trust = TrustStore(owner.client_config.trust_path)
    for record in prepared:
        trust.verify_record(record, attestations[record["memory_id"]])
    owner.client_config.vault().ingest_records(prepared, admission="verified", attestations=attestations)
    owner.set_hint_policy(policy(owner, requester, hint_ids, [*roots, dependency]))
    query, offer, page = query_offer(test, owner, requester, transport, query=QUERY, suffix="received_" + suffix)
    offers, pages = [offer], [page]
    from tests.test_network_hints_pagination import page_offer
    while page["next_cursor"] is not None:
        _, offer, page = page_offer(test, owner, requester, query, page, "received_" + suffix + "_" + str(len(pages)))
        offers.append(offer)
        pages.append(page)
    by_root = {item["memory_id"]: offer["message_id"] for offer, page in zip(offers, pages) for item in page["hints"]}
    test.assertTrue(set(roots).issubset(by_root))
    selected = choose(test, owner, requester, control("select", query_message_id=query["message_id"],
        selections=[{"offer_message_id": by_root[mid], "memory_id": mid} for mid in roots]), suffix="received_" + suffix)
    transfer = (transfer_call or owner.respond_to)(selected["message_id"])
    test.assertEqual(transfer["stored_nodes"], 2, transfer)
    received = (receive_call or requester.receive)()
    test.assertFalse(received["errors"], received)
    test.assertEqual(received["messages"][0]["content_kind"], "hint_batch_transfer")
    if trusted_witnesses:
        test.assertEqual(received["messages"][0]["share"]["admission"], "verified")
    return {"dependency": dependency, "roots": roots, "query": query, "offers": offers, "pages": pages,
            "select": selected, "transfer": transfer, "received": received, "originals": records(owner),
            "original_proofs": proofs(owner), "witnesses": witnesses}


def transport_snapshot(endpoint):
    database = endpoint.directory / "network.sqlite3"
    if not database.exists():
        return None
    with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as db:
        tables = [row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        return {name: sorted((tuple(row) for row in db.execute('SELECT * FROM "' + name.replace('"', '""') + '"')), key=repr)
                for name in tables}


def file_snapshot(endpoint):
    root = endpoint.config_path.parent
    return {str(path.relative_to(root)): (path.stat().st_mode & 0o777, hashlib.sha256(path.read_bytes()).hexdigest())
            for path in root.rglob("*") if path.is_file() and not path.name.endswith(("-wal", "-shm", "-journal"))}


@contextmanager
def readonly_probe(test, endpoint, transport):
    """No network, writable transport entry, SQL mutation, import or repair."""
    before = (vault_snapshot(endpoint), transport_snapshot(endpoint), file_snapshot(endpoint))
    original_connect, attempts = sqlite3.connect, []
    writes = {sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE, sqlite3.SQLITE_CREATE_TABLE,
              sqlite3.SQLITE_CREATE_INDEX, sqlite3.SQLITE_CREATE_TRIGGER, sqlite3.SQLITE_DROP_TABLE,
              sqlite3.SQLITE_DROP_INDEX, sqlite3.SQLITE_DROP_TRIGGER, sqlite3.SQLITE_ALTER_TABLE}
    def authorizer(action, one, two, database, trigger):
        if action in writes:
            attempts.append((action, one, database))
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK
    def checked_connect(*args, **kwargs):
        db = original_connect(*args, **kwargs)
        db.set_authorizer(authorizer)
        return db
    with ExitStack() as stack:
        stack.enter_context(patch.object(transport, "request", side_effect=AssertionError("received batch recall accessed network")))
        stack.enter_context(patch.object(NetworkClient, "db", side_effect=AssertionError("readonly recall entered writable transport")))
        stack.enter_context(patch("memory_vault_sharing.import_share", side_effect=AssertionError("recall reimported retained share")))
        stack.enter_context(patch("memory_vault_sharing.export_share", side_effect=AssertionError("recall reexported retained share")))
        stack.enter_context(patch("memory_vault_sharing._scan", side_effect=AssertionError("local recall used file-based share scan")))
        stack.enter_context(patch.object(sqlite3, "connect", side_effect=checked_connect))
        yield
    test.assertEqual(attempts, [])
    test.assertEqual((vault_snapshot(endpoint), transport_snapshot(endpoint), file_snapshot(endpoint)), before)


def recall_pages(test, endpoint, transport, message_id, *, include_experience=None):
    request = {"op": "recall", "received_batch_message_id": message_id}
    if include_experience is not None:
        request["include_experience"] = include_experience
    pages = []
    for _ in range(64):
        response = agent(endpoint, transport).handle(request)
        test.assertTrue(response["ok"], response)
        test.assertLessEqual(len(canonical_bytes(response)), 8192)
        result = response["result"]
        test.assertFalse(result["network_accessed"])
        test.assertFalse(response["authority"]["authorization_eligible"])
        pages.append(result)
        if result["next_cursor"] is None:
            return pages
        request = {"op": "recall", "cursor": result["next_cursor"]}
    test.fail("bounded received batch cursor did not complete")


def cursor(value):
    return base64.urlsafe_b64encode(canonical_bytes(value)).decode().rstrip("=")


class ReceivedBatchRecallTests(unittest.TestCase):
    def assert_error(self, endpoint, transport, request, code):
        value = agent(endpoint, transport).handle(request)
        self.assertFalse(value["ok"], value)
        self.assertEqual(value["error"]["code"], code)
        return value

    def assert_batch_pages(self, batch, pages, *, experience=True):
        hits = [hit for page in pages for hit in page["hits"]]
        self.assertEqual(list(dict.fromkeys(hit["memory_id"] for hit in hits)), batch["roots"])
        for page in pages:
            self.assertEqual(page["selected_memory_ids"], batch["roots"])
            self.assertEqual(page["received_batch_message_id"], batch["transfer"]["message_id"])
            self.assertEqual(page["query_candidate_limit"], 4)
            self.assertLessEqual(len(page["hits"]), 4)
            self.assertNotIn("context", page)
        for memory_id in batch["roots"]:
            pieces = [hit for hit in hits if hit["memory_id"] == memory_id]
            original = strict_json_loads(batch["originals"][memory_id])
            self.assertEqual("".join(hit["text"] for hit in pieces), original["text"])
            offset = 0
            for hit in pieces:
                self.assertEqual(hit["text_offset_bytes"], offset)
                self.assertLessEqual(len(hit["text"].encode()), 768)
                offset += len(hit["text"].encode())
                self.assertEqual("experience" in hit, experience)
                if experience:
                    self.assertEqual(hit["experience"]["content"], hit["text"])
                    self.assertEqual(hit["experience"]["source"]["attribution"], "recorded_source_not_reader")
                    self.assertFalse(hit["experience"]["source"]["claims_authenticated"])
        self.assertNotIn(batch["dependency"], [hit["memory_id"] for hit in hits])
        return {hit["memory_id"]: hit for hit in hits}

    def test_four_cross_page_roots_keep_explicit_order_original_sources_and_context_without_writes(self):
        with fixture() as (owner, requester, transport):
            batch = prepare_batch(self, owner, requester, transport, cross_pages=True)
            self.assertEqual([len(page["hints"]) for page in batch["pages"]], [4, 4, 4, 1])
            self.assertEqual([sum(item["memory_id"] in batch["roots"] for item in page["hints"])
                              for page in batch["pages"]], [1, 1, 1, 1])
            self.assertEqual(set(records(requester)), {*batch["roots"], batch["dependency"]})
            for mid in records(requester):
                self.assertEqual(records(requester)[mid], batch["originals"][mid])
                self.assertEqual(proofs(requester)[mid], batch["original_proofs"][mid])
            with readonly_probe(self, requester, transport):
                first = recall_pages(self, requester, transport, batch["transfer"]["message_id"])
                self.assertEqual(first, recall_pages(self, requester, transport, batch["transfer"]["message_id"]))
                short = recall_pages(self, requester, transport, batch["transfer"]["message_id"], include_experience=False)
            found = self.assert_batch_pages(batch, first)
            self.assert_batch_pages(batch, short, experience=False)
            summary, v2, observation, confirmation = batch["roots"]
            self.assertEqual(found[summary]["experience"]["epistemic_type"], "summary")
            self.assertEqual(found[observation]["experience"]["observed_under"], {"environment": "V1"})
            self.assertEqual(found[confirmation]["experience"]["observed_under"], {"environment": "V1"})
            self.assertEqual(found[v2]["experience"]["observed_under"], {"environment": "V2", "build_id": 2**63 - 1})
            self.assertEqual(found[observation]["experience"]["source"]["signer_key_id"], owner.identity.key_id)
            self.assertEqual(found[confirmation]["experience"]["source"]["signer_key_id"], batch["witnesses"][0].key_id)
            self.assertEqual(found[v2]["experience"]["source"]["signer_key_id"], batch["witnesses"][1].key_id)
            provenance = found[observation]["experience"]["provenance_summary"]
            self.assertEqual(provenance["independent_confirmation_count"], 1)
            self.assertEqual(provenance["contradiction_count"], 1)
            self.assertIsNone(provenance["truth_score"])
            # A one-item explicit selection uses the same historical selector.
            wanted = batch["roots"][0]
            offer = next(offer for offer, page in zip(batch["offers"], batch["pages"])
                         if any(item["memory_id"] == wanted for item in page["hints"]))
            selected = choose(self, owner, requester, control("select", query_message_id=batch["query"]["message_id"],
                selections=[{"offer_message_id": offer["message_id"], "memory_id": wanted}]), suffix="single_received")
            sent = owner.respond_to(selected["message_id"])
            self.assertFalse(requester.receive()["errors"])
            with readonly_probe(self, requester, transport):
                single = recall_pages(self, requester, transport, sent["message_id"])
            self.assertEqual(single[0]["selected_memory_ids"], [wanted])
            self.assertEqual([hit["memory_id"] for page in single for hit in page["hits"]], [wanted])

    def test_accepted_history_survives_cancel_restart_recovery_but_real_late_batch_is_unavailable(self):
        with fixture() as (owner, requester, transport):
            batch = prepare_batch(self, owner, requester, transport)
            accepted = batch["transfer"]["message_id"]
            notice = cancel(requester, owner, batch["query"], batch["offers"][0], batch["pages"][0], suffix="received_history")
            self.assertTrue(notice["cancellation"]["local_cancelled"])
            late = "msg_" + hashlib.sha256(b"synthetic-local-history-late-batch").hexdigest()
            before = vault_snapshot(requester)
            inject_ciphertext(owner, requester, outbox_row(owner, accepted)["body"], late)
            received = requester.receive()
            rejected, = [item for item in received["messages"] if item["message_id"] == late]
            self.assertEqual((rejected["state"], rejected["code"]), ("rejected", "network_invalid_content"))
            self.assertEqual(vault_snapshot(requester), before)
            with readonly_probe(self, requester, transport):
                expected = recall_pages(self, requester, transport, accepted)
                self.assert_error(requester, transport, {"op": "recall", "received_batch_message_id": late}, "received_batch_not_available")
            with NetworkClient(requester.config_path, transport=transport) as restarted:
                with readonly_probe(self, restarted, transport):
                    self.assertEqual(recall_pages(self, restarted, transport, accepted), expected)
            source = (transport_snapshot(requester), vault_snapshot(requester))
            _, arguments = archive(requester)
            self.assertEqual((transport_snapshot(requester), vault_snapshot(requester)), source)
            restored = recovery.restore_endpoint(directory=requester.config_path.parent.parent / "synthetic-local-history-restored", **arguments)
            with NetworkClient(Path(restored["network_config"]), transport=transport) as endpoint:
                self.assertFalse(any(row[0].startswith("hint-session:") for row in transport_snapshot(endpoint)["state"]))
                with readonly_probe(self, endpoint, transport):
                    self.assertEqual(recall_pages(self, endpoint, transport, accepted), expected)
                    self.assert_error(endpoint, transport, {"op": "recall", "received_batch_message_id": late}, "received_batch_not_available")
                self.assertEqual(records(endpoint), records(requester))
                self.assertEqual(proofs(endpoint), proofs(requester))

    def test_selector_rejects_nonbatch_unbound_unverified_and_absent_transport_without_repair(self):
        with fixture() as (owner, requester, transport):
            batch = prepare_batch(self, owner, requester, transport)
            accepted = batch["transfer"]["message_id"]
            chat = owner.send("req_received_not_batch_chat", [requester.identity.key_id], "Synthetic local selector chat")
            manual = owner.send("req_received_not_batch_share", [requester.identity.key_id], memory_ids=[batch["roots"][0]])
            requester.receive()
            with readonly_probe(self, requester, transport):
                for identifier in (chat["message_id"], manual["message_id"], batch["offers"][0]["message_id"],
                                   batch["select"]["message_id"], "msg_" + "f" * 64, "wrong-message-id"):
                    with self.subTest(identifier=identifier):
                        self.assert_error(requester, transport, {"op": "recall", "received_batch_message_id": identifier}, "received_batch_not_available")
                for key, value in (("query", QUERY), ("memory_id", batch["roots"][0]), ("handoff", True),
                                   ("ranking_profile", "memory-vault-retrieval/v1")):
                    with self.subTest(selector=key):
                        self.assert_error(requester, transport, {"op": "recall", "received_batch_message_id": accepted, key: value}, "ambiguous_recall_selector")
            with readonly_probe(self, owner, transport):
                self.assert_error(owner, transport, {"op": "recall", "received_batch_message_id": accepted}, "received_batch_not_available")
            # Controlled synthetic index faults must never trigger re-admission,
            # fallback to existing roots, or repair of retained transport data.
            with requester.db() as db:
                row = dict(db.execute("SELECT * FROM inbox WHERE message_id=?", (accepted,)).fetchone())
                selected = dict(db.execute("SELECT * FROM outbox WHERE message_id=?", (batch["select"]["message_id"],)).fetchone())
            altered = strict_json_loads(row["result"])
            altered["share"]["admission"] = "accepted_unsigned"
            faults = [("inbox", "result", canonical_bytes(altered).decode(), accepted),
                      ("inbox", "sender", requester.identity.key_id, accepted),
                      ("outbox", "recipients", canonical_bytes([requester.identity.key_id]).decode(), batch["select"]["message_id"]),
                      ("outbox", "input_sha", "0" * 64, batch["select"]["message_id"])]
            for table, column, value, identifier in faults:
                with self.subTest(fault=column):
                    original = row[column] if table == "inbox" else selected[column]
                    try:
                        with requester.db() as db:
                            db.execute("UPDATE " + table + " SET " + column + "=? WHERE message_id=?", (value, identifier))
                        with readonly_probe(self, requester, transport):
                            self.assert_error(requester, transport, {"op": "recall", "received_batch_message_id": accepted}, "received_batch_not_available")
                    finally:
                        with requester.db() as db:
                            db.execute("UPDATE " + table + " SET " + column + "=? WHERE message_id=?", (original, identifier))
            database = requester.directory / "network.sqlite3"
            preserved = database.with_name("synthetic-preserved-network.sqlite3")
            database.rename(preserved)
            try:
                with readonly_probe(self, requester, transport):
                    self.assert_error(requester, transport, {"op": "recall", "received_batch_message_id": accepted}, "received_batch_not_available")
                self.assertFalse(database.exists())
            finally:
                preserved.rename(database)

    def test_each_cursor_page_rechecks_current_signer_revocation_without_rewriting_history(self):
        with fixture() as (owner, requester, transport):
            batch = prepare_batch(self, owner, requester, transport, long_text=True)
            accepted = batch["transfer"]["message_id"]
            with readonly_probe(self, requester, transport):
                first = agent(requester, transport).handle({"op": "recall", "received_batch_message_id": accepted})
                self.assertTrue(first["ok"], first)
                self.assertTrue(first["result"]["hits"][0]["verification"]["eligible_for_context"])
            self.assertIsNotNone(first["result"]["next_cursor"])
            immutable = records(requester), proofs(requester)
            TrustStore(requester.client_config.trust_path).revoke(owner.identity.key_id)
            with readonly_probe(self, requester, transport):
                next_page = agent(requester, transport).handle({"op": "recall", "cursor": first["result"]["next_cursor"]})
                self.assertTrue(next_page["ok"], next_page)
                hit = next_page["result"]["hits"][0]
                self.assertEqual(hit["memory_id"], batch["roots"][0])
                self.assertFalse(hit["verification"]["eligible_for_context"])
                self.assertTrue(hit["verification"]["signature_verified_at_admission"])
                self.assertTrue(hit["verification"]["current_trust_checked"])
                self.assertEqual(hit["experience"]["source"]["signer_key_id"], owner.identity.key_id)
                pages = recall_pages(self, requester, transport, accepted)
            self.assert_batch_pages(batch, pages)
            self.assertEqual((records(requester), proofs(requester)), immutable)

    def test_missing_current_records_dependencies_and_oversized_retained_body_never_fallback(self):
        with fixture() as (owner, requester, transport):
            batch = prepare_batch(self, owner, requester, transport)
            accepted = batch["transfer"]["message_id"]
            vault = requester.client_config.vault()
            # Admissions are mutable local policy; immutable memory/proof rows
            # and their triggers remain intact throughout this fixture.
            with closing(vault._connect()) as db:
                prior = db.execute("SELECT state FROM record_admissions WHERE memory_id=?", (batch["dependency"],)).fetchone()[0]
                db.execute("UPDATE record_admissions SET state='quarantined' WHERE memory_id=?", (batch["dependency"],))
                db.commit()
            with readonly_probe(self, requester, transport):
                pages = recall_pages(self, requester, transport, accepted)
            summary = next(hit for page in pages for hit in page["hits"] if hit["memory_id"] == batch["roots"][0])["experience"]["provenance_summary"]
            self.assertTrue(summary["truncated"])
            self.assertGreaterEqual(summary["missing_reference_count"], 1)
            with closing(vault._connect()) as db:
                db.execute("UPDATE record_admissions SET state=? WHERE memory_id=?", (prior, batch["dependency"]))
                db.commit()
            # A valid alternate Vault contains every original record except a
            # selected summary root. No record references that summary.
            path = requester.client_config.vault_path
            preserved = path.with_name("synthetic-preserved-vault.sqlite3")
            path.rename(preserved)
            try:
                originals = [strict_json_loads(raw) for mid, raw in records(owner).items() if mid != batch["roots"][0]]
                attestations = {mid: strict_json_loads(proof[1]) for mid, proof in proofs(owner).items() if mid != batch["roots"][0]}
                trust = TrustStore(requester.client_config.trust_path)
                for record in originals:
                    trust.verify_record(record, attestations[record["memory_id"]])
                requester.client_config.vault().ingest_records(originals, admission="verified", attestations=attestations)
                with readonly_probe(self, requester, transport):
                    self.assert_error(requester, transport, {"op": "recall", "received_batch_message_id": accepted}, "not_found")
            finally:
                path.unlink(missing_ok=True)
                preserved.rename(path)
            with requester.db() as db:
                raw = db.execute("SELECT body FROM inbox WHERE message_id=?", (accepted,)).fetchone()[0]
                db.execute("UPDATE inbox SET body=? WHERE message_id=?", (b"x" * (8 * 1024 * 1024 + 1), accepted))
            try:
                with readonly_probe(self, requester, transport):
                    self.assert_error(requester, transport, {"op": "recall", "received_batch_message_id": accepted}, "received_batch_not_available")
            finally:
                with requester.db() as db:
                    db.execute("UPDATE inbox SET body=? WHERE message_id=?", (raw, accepted))

    def test_unicode_fragments_int64_budget_and_strict_batch_bound_cursors(self):
        with fixture() as (owner, requester, transport):
            batch = prepare_batch(self, owner, requester, transport, long_text=True)
            accepted = batch["transfer"]["message_id"]
            with readonly_probe(self, requester, transport):
                pages = recall_pages(self, requester, transport, accepted)
                short = recall_pages(self, requester, transport, accepted, include_experience=False)
                self.assertGreater(len(pages), 4)
                found = self.assert_batch_pages(batch, pages)
                self.assert_batch_pages(batch, short, experience=False)
                self.assertEqual(found[batch["roots"][1]]["experience"]["observed_under"]["build_id"], 2**63 - 1)
                for collection, include in ((pages, True), (short, False)):
                    previous = (-1, -1)
                    for page in collection[:-1]:
                        state = strict_json_loads(base64.urlsafe_b64decode(page["next_cursor"] + "=" * (-len(page["next_cursor"]) % 4)))
                        self.assertEqual(set(state), {"received_batch_message_id", "root_index", "offset", "include_experience"})
                        self.assertEqual(state["received_batch_message_id"], accepted)
                        self.assertIs(state["include_experience"], include)
                        self.assertGreater((state["root_index"], state["offset"]), previous)
                        previous = state["root_index"], state["offset"]
                base = {"received_batch_message_id": accepted, "root_index": 0, "offset": 0, "include_experience": True}
                raw_text = strict_json_loads(batch["originals"][batch["roots"][0]])["text"].encode()
                continuation = next(index for index, byte in enumerate(raw_text) if byte & 0xC0 == 0x80)
                invalid = [{**base, "ids": batch["roots"]}, {key: val for key, val in base.items() if key != "include_experience"},
                           {**base, "root_index": True}, {**base, "root_index": 4}, {**base, "root_index": -1},
                           {**base, "offset": 2**53}, {**base, "offset": len(raw_text) + 1}, {**base, "offset": continuation},
                           {**base, "include_experience": 1}]
                for state in invalid:
                    with self.subTest(cursor_state=state):
                        self.assert_error(requester, transport, {"op": "recall", "cursor": cursor(state)}, "invalid_recall_cursor")
                self.assert_error(requester, transport, {"op": "recall", "cursor": cursor({**base,
                    "received_batch_message_id": "msg_" + "e" * 64})}, "received_batch_not_available")
                self.assert_error(requester, transport, {"op": "recall", "cursor": cursor(base),
                    "received_batch_message_id": accepted}, "ambiguous_recall_cursor")


if __name__ == "__main__":
    unittest.main()
