"""Synthetic metadata/byte plans, not legal Signed histories or authorization.

Opaque role bodies deliberately have no claimed signature. The complete typed
authority consumer is still required before any live operation may use a plan.
"""
from copy import deepcopy
import hashlib
import unittest

import memory_vault_open_repair_history as history
import memory_vault_open_repair_wire as wire


def policy(**changes):
    values = dict(max_document_bytes=131072, max_total_bytes=4000000,
                  max_nodes=100000, max_depth=64, max_string_bytes=65536,
                  max_hash_bytes=4000000, max_hashes=1000, max_entries=1000,
                  max_retained_bytes=4000000)
    values.update(changes)
    return wire.RepairPolicy(**values)


def ref(raw):
    return dict(namespace="meta", key=hashlib.sha256(b"synthetic-locator:" + raw).hexdigest(),
                raw_sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))


def root(ack=False):
    return dict(owner=dict(signing_key_id="ed25519_" + "a" * 64,
                           encryption_key_id="x25519_" + "b" * 64),
                root_kind="ack_return" if ack else "mailbox",
                anchor_ref=dict(namespace="anchor", key="c" * 64),
                owner_epoch="synthetic-epoch", root_id="synthetic-root")


def slot(ack=False):
    result = dict(root_key=root(ack), slot_id="synthetic-slot")
    dual = dict(signing_key_id="ed25519_" + "d" * 64, encryption_key_id="x25519_" + "e" * 64)
    return {**result, **(dict(receipt_writer=dual, grant_id="synthetic-grant") if ack else
                         dict(writer=dual, writer_storage_epoch="synthetic-writer-epoch"))}


def resource():
    return dict(node_key_id="ed25519_" + "f" * 64, storage_epoch="synthetic-node-epoch",
                lease_id="synthetic-lease", resource_id="synthetic-resource")


def make(variant, fields, assigned, *, extra=()):
    """Freeze a byte-level fixture in source order using actual pack functions."""
    local = policy()
    budget = wire.RepairBudget(local)
    pack = wire.build_raw_pack([body for _, body in assigned] + list(extra), local, budget)
    positions = {entry.raw_sha256: index for index, entry in enumerate(pack.entries)}
    roles = [dict(role=name, document_ref=ref(body), pack_ref=pack.ref.as_dict(),
                  entry_index=positions[hashlib.sha256(body).hexdigest()]) for name, body in assigned]
    roles.sort(key=lambda value: (value["role"], *history._ref_tuple(value["document_ref"])))
    value = dict(schema_version=history.SCHEMA, kind="historical.manifest", variant=variant,
                 root_key=root(variant.startswith("ack_")), roles=roles, **fields)
    draft = history.build_historical_manifest(value, local, budget)
    return dict(value=value, raw=draft.raw, packs=[pack.raw])


def fixtures():
    authority, catalog, attempt = b"synthetic root authority bytes", b"synthetic catalog bytes", b"synthetic attempt bytes"
    mailbox_root = make("mailbox_root", dict(root_authority_ref=ref(authority), catalog_ref=ref(catalog),
                       genesis_head_refs=[]), [("mailbox.root_authority", authority), ("mailbox.catalog", catalog)])
    mailbox_member = make("mailbox_member", dict(slot_key=slot(), message_id="msg_" + "1" * 64,
                          envelope_ref=ref(b"synthetic E"), attempt_ref=ref(attempt)), [("delivery.attempt", attempt)])
    head, selected_slot, core, link, custody = (b"synthetic head", b"synthetic slot", b"synthetic core",
                                             b"synthetic link", b"synthetic custody")
    member = dict(sequence=0, message_id=mailbox_member["value"]["message_id"],
                  envelope_ref=mailbox_member["value"]["envelope_ref"],
                  historical_manifest_ref=ref(mailbox_member["raw"]), admission_core_ref=ref(core),
                  admission_link_ref=ref(link), source_custody_ref=ref(custody))
    feed = make("mailbox_feed", dict(slot_key=slot(), slot_ref=ref(selected_slot), feed_head_ref=ref(head),
                covered_interval=dict(start=0, end=1), subtree=dict(root_ref=ref(b"synthetic range"),
                parent_path_refs=[ref(b"synthetic parent range")]), members=[member]),
                [("mailbox.slot", selected_slot), ("feed.head", head),
                ("range.index", b"synthetic range"), ("range.index", b"synthetic parent range"),
                ("history.member", mailbox_member["raw"]), ("member.core", core), ("member.link", link),
                ("member.custody", custody)])
    feed["packs"] += mailbox_member["packs"]
    unbound = make("ack_unbound", dict(ack_slot=slot(True), root_authority_ref=ref(authority)),
                   [("ack.root_authority", authority)])
    grant, binding = b"synthetic grant bytes", b"synthetic binding bytes"
    empty_fields = dict(ack_slot=slot(True), root_authority_ref=ref(authority), grant_ref=ref(grant), binding_ref=ref(binding))
    empty = make("ack_empty", empty_fields, [("history.ack_unbound", unbound["raw"]),
                 ("ack.write_grant", grant), ("ack.binding", binding)])
    empty["packs"] += unbound["packs"]
    receipt, put, disclosure = b"synthetic receipt bytes", b"synthetic put bytes", b"synthetic disclosure bytes"
    occupied = make("ack_occupied_inputs", dict(**empty_fields, receipt_ref=ref(receipt), put_ref=ref(put),
                    disclosure_ref=ref(disclosure), admission_resource=resource()),
                    [("history.ack_empty", empty["raw"]), ("recipient.receipt", receipt),
                     ("ack.put", put), ("ack.disclosure", disclosure)])
    occupied["packs"] += empty["packs"]
    return {value["value"]["variant"]: value for value in (mailbox_root, mailbox_member, feed, unbound, empty, occupied)}


def load_packs(fixture, local=None):
    local = local or policy()
    budget = wire.RepairBudget(local)
    resolver = wire.LocalRawResolver(local, budget)
    for body in fixture["packs"]:
        resolver.put("meta", hashlib.sha256(body).hexdigest(), body)
    return resolver, local, budget


class OpenRepairHistoryTests(unittest.TestCase):
    def assertCode(self, code, callback, *args):
        with self.assertRaises(wire.RepairWireError) as caught:
            callback(*args)
        self.assertEqual(caught.exception.code, code)

    def build(self, value):
        local = policy()
        return history.build_historical_manifest(value, local, wire.RepairBudget(local))

    def test_six_closed_shapes_round_trip_without_claiming_authority(self):
        for variant, fixture in fixtures().items():
            with self.subTest(variant=variant):
                local = policy()
                budget = wire.RepairBudget(local)
                draft = history.parse_historical_manifest(fixture["raw"], local, budget)
                self.assertEqual(draft.value, fixture["value"])
                self.assertEqual(draft.raw, self.build(fixture["value"]).raw)
                self.assertEqual(budget.snapshot()["signature_checks"], 0)
                self.assertEqual(budget.snapshot()["hashes"], 0)
                fixture["value"]["root_key"]["root_id"] = "changed-after-build"
                self.assertEqual(draft.value["root_key"]["root_id"], "synthetic-root")

    def test_wrong_variant_role_root_and_unknown_fields_refused(self):
        original = fixtures()["mailbox_member"]["value"]
        variants = []
        for changes in (dict(variant="ack_empty"), dict(unexpected=0), dict(kind="replica.manifest"), dict(roles=[])):
            variants.append({**deepcopy(original), **changes})
        changed = deepcopy(original)
        changed["roles"][0]["role"] = "ack.binding"
        variants.append(changed)
        changed = deepcopy(original)
        changed["slot_key"]["root_key"]["owner_epoch"] = "another-root"
        variants.append(changed)
        changed = deepcopy(original)
        changed["roles"].append(deepcopy(changed["roles"][0]))
        variants.append(changed)
        for value in variants:
            self.assertCode("repair_invalid_history", self.build, value)
        changed = deepcopy(original)
        changed["roles"][0]["entry_index"] = True
        self.assertCode("repair_invalid_integer", self.build, changed)

    def test_feed_requires_exact_contiguous_members_and_parent_path(self):
        original = fixtures()["mailbox_feed"]["value"]
        changes = []
        for interval in (dict(start=0, end=0), dict(start=0, end=2), dict(start=1, end=2)):
            changes.append({**deepcopy(original), "covered_interval": interval})
        changed = deepcopy(original)
        changed["members"][0]["sequence"] = 1
        changes.append(changed)
        changed = deepcopy(original)
        changed["subtree"]["parent_path_refs"] = [changed["subtree"]["root_ref"]]
        changes.append(changed)
        for value in changes:
            self.assertCode("repair_invalid_history", self.build, value)

    def test_all_six_local_byte_plans_resolve_and_ack_has_three_original_phases(self):
        for variant, fixture in fixtures().items():
            with self.subTest(variant=variant):
                resolver, local, budget = load_packs(fixture)
                result = history.resolve_historical_inputs(fixture["raw"], resolver, local, budget)
                self.assertEqual(result.manifest.value, fixture["value"])
                self.assertEqual(len(result.roles), len(fixture["value"]["roles"]))
                for role, expected in zip(result.roles, fixture["value"]["roles"]):
                    self.assertEqual(role.original.ref.as_dict(), expected["document_ref"])
                    self.assertEqual(hashlib.sha256(role.original.raw).hexdigest(), role.original.ref.raw_sha256)
                self.assertEqual(budget.snapshot()["signature_checks"], 0)
                if variant == "ack_occupied_inputs":
                    self.assertEqual(result.predecessors[0].manifest.value["variant"], "ack_empty")
                    self.assertEqual(result.predecessors[0].predecessors[0].manifest.value["variant"], "ack_unbound")
                    self.assertEqual(result.predecessors[0].predecessors[0].predecessors, ())

    def test_unused_pack_entry_missing_dependency_and_wrong_explicit_binding_refused(self):
        attempt = b"synthetic attempt bytes"
        fixture = make("mailbox_member", dict(slot_key=slot(), message_id="msg_" + "1" * 64,
                       envelope_ref=ref(b"synthetic E"), attempt_ref=ref(attempt)),
                       [("delivery.attempt", attempt)], extra=[b"unrelated private bytes"])
        resolver, local, budget = load_packs(fixture)
        self.assertCode("repair_invalid_history", history.resolve_historical_inputs, fixture["raw"], resolver, local, budget)
        normal = fixtures()["mailbox_member"]
        local = policy()
        budget = wire.RepairBudget(local)
        self.assertCode("repair_ref_missing", history.resolve_historical_inputs, normal["raw"],
                        wire.LocalRawResolver(local, budget), local, budget)
        changed = deepcopy(normal["value"])
        changed["attempt_ref"] = ref(b"another attempt")
        normal["raw"] = self.build(changed).raw
        resolver, local, budget = load_packs(normal)
        self.assertCode("repair_invalid_history", history.resolve_historical_inputs, normal["raw"], resolver, local, budget)

    def test_nested_wrong_phase_and_slot_binding_refused(self):
        sample = fixtures()
        empty = sample["ack_empty"]
        wrong = make("ack_empty", {key: value for key, value in empty["value"].items()
                     if key in history.VARIANT_FIELDS["ack_empty"]},
                     [("history.ack_unbound", sample["mailbox_member"]["raw"]),
                      ("ack.write_grant", b"synthetic grant bytes"), ("ack.binding", b"synthetic binding bytes")])
        resolver, local, budget = load_packs(wrong)
        self.assertCode("repair_invalid_history", history.resolve_historical_inputs, wrong["raw"], resolver, local, budget)
        feed = sample["mailbox_feed"]
        changed = deepcopy(feed["value"])
        changed["members"][0]["message_id"] = "msg_" + "2" * 64
        feed["raw"] = self.build(changed).raw
        resolver, local, budget = load_packs(feed)
        self.assertCode("repair_invalid_history", history.resolve_historical_inputs, feed["raw"], resolver, local, budget)

    def test_explicit_subtree_and_parent_refs_require_range_originals(self):
        feed = fixtures()["mailbox_feed"]
        for parent in (False, True):
            reference = feed["value"]["subtree"]["parent_path_refs"][0] if parent else (
                feed["value"]["subtree"]["root_ref"])
            for fault in ("missing_role", "wrong_role", "wrong_ref"):
                with self.subTest(parent=parent, fault=fault):
                    changed = deepcopy(feed["value"])
                    entry = next(item for item in changed["roles"]
                                 if item["role"] == "range.index" and item["document_ref"] == reference)
                    if fault == "missing_role":
                        changed["roles"].remove(entry)
                    elif fault == "wrong_role":
                        entry["role"] = "range.repair_page"
                        changed["roles"].sort(key=lambda item: (item["role"], *history._ref_tuple(item["document_ref"])))
                    elif parent:
                        changed["subtree"]["parent_path_refs"][0] = ref(b"missing parent")
                    else:
                        changed["subtree"]["root_ref"] = ref(b"missing subtree")
                    resolver, local, budget = load_packs(feed)
                    self.assertCode("repair_invalid_history", history.resolve_historical_inputs,
                                    self.build(changed).raw, resolver, local, budget)

    def test_resolver_is_the_actual_local_store_and_one_shared_budget(self):
        fixture = fixtures()["ack_unbound"]
        resolver, local, budget = load_packs(fixture)
        def forbidden(*args):
            self.fail("instance override must not become an arbitrary fetch callback")
        with self.assertRaises(AttributeError):
            resolver.resolve = forbidden
        result = history.resolve_historical_inputs(fixture["raw"], resolver, local, budget)
        self.assertEqual(result.roles[0].original.raw, b"synthetic root authority bytes")
        self.assertCode("repair_invalid_policy", history.resolve_historical_inputs, fixture["raw"], resolver,
                        local, wire.RepairBudget(local))
        local = policy(max_hashes=1)
        resolver, local, budget = load_packs(fixture, local)
        self.assertCode("repair_over_budget", history.resolve_historical_inputs, fixture["raw"], resolver, local, budget)
        self.assertEqual(budget.snapshot()["hashes"], 1)
