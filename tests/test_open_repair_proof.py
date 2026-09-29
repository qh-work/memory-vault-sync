"""Actual inline manifests/handles and finite signed subject requests."""
import copy
import json
import unittest

from memory_vault import canonical_bytes
import memory_vault_open_repair_probe as probe
import memory_vault_open_repair_proof as proof
import memory_vault_open_repair_wire as wire
from tests.open_repair_ack_fixtures import ack_unbound_fixture, policy


def entry(original):
    return dict(raw=original.raw, ref=original.ref.as_dict())


class RepairProofTests(unittest.TestCase):
    def setUp(self):
        self.fixture = f = ack_unbound_fixture()
        self.policy = policy()
        self.now = 2_000_000_006
        self.subject, self.target = f["expected"]["expected_owner"], f["expected"]["expected_target"]
        grant = f["docs"]["bootstrap"]["payload"]
        self.binding = dict(expected_subject=self.subject, expected_target=self.target,
            target_storage_epoch=f["expected"]["target_storage_epoch"], bootstrap_grant_sha256=f["entries"]["bootstrap"]["ref"]["raw_sha256"],
            selector=grant["selector"], at=self.now, policy=self.policy)
        b = wire.RepairBudget(self.policy)
        self.request = probe.make_bootstrap_probe(f["signers"]["owner"], **self.binding, expires_at=self.now+30, budget=b)
        self.challenge = probe.issue_bootstrap_challenge(entry(self.request.original), signer=f["signers"]["target"],
            encryption_identity=f["encryption"]["target"], **self.binding, expires_at=self.now+30, budget=b)
        self.answer = probe.solve_bootstrap_challenge(entry(self.request.original), entry(self.challenge.original),
            signer=f["signers"]["owner"], encryption_identity=f["encryption"]["owner"], target_nonce=self.request.nonce,
            **self.binding, expires_at=self.now+30, budget=b)
        self.parents = dict(probe_ref=self.request.original.ref.as_dict(), challenge_ref=self.challenge.original.ref.as_dict(),
                            answer_ref=self.answer.ref.as_dict())
        rows = [(role, f["entries"][name]["ref"]) for role,name in f["role_map"].items()]
        rows += [("history.ack_unbound", f["manifest"]["ref"]), ("ack.unbound_custody", f["custody"]["ref"])]
        rows += [(name, f["entries"]["target_status" if name.endswith("ack_resource") else "owner_status"]["ref"]) for name in proof.CURRENT_ROLES]
        rows += [("history.raw_pack", f["packs"][0]["ref"])]
        rows.sort(key=lambda row: (row[0],row[1]["key"]))
        self.manifest = dict(schema_version=proof.SCHEMA, kind="bootstrap.proof_manifest", probe_ref=self.parents["probe_ref"],
            subject=probe._dual(self.subject), target=probe._dual(self.target), target_storage_epoch=self.binding["target_storage_epoch"],
            consumer="ack_owner", selector=grant["selector"], bootstrap_grant_ref=f["entries"]["bootstrap"]["ref"],
            service_generation=1, response_profile="ack_owner_service_v1",
            children=[dict(index=i,role=role,ref=ref) for i,(role,ref) in enumerate(rows)])

    def response(self, manifest=None, **changes):
        options = dict(**self.parents, subject=self.subject, target=self.target, at=self.now, expires_at=self.now+30,
                       handle_id="synthetic_handle", policy=self.policy, budget=wire.RepairBudget(self.policy))
        options.update(changes)
        return proof.make_bootstrap_proof_response(self.fixture["signers"]["target"],
            self.manifest if manifest is None else manifest, **options)

    def verify(self, raw=None, **changes):
        options = dict(expected_subject=self.subject, expected_target=self.target,
            target_storage_epoch=self.binding["target_storage_epoch"], selector=self.binding["selector"],
            bootstrap_grant_ref=self.fixture["entries"]["bootstrap"]["ref"], **self.parents, at=self.now,
            max_proof_items=64, max_proof_bytes=131072, policy=self.policy, budget=wire.RepairBudget(self.policy))
        options.update(changes)
        return proof.verify_bootstrap_proof_response(self.response().raw if raw is None else raw, **options)

    def mailbox_manifest(self):
        # Manifest-format fixture only; these locators do not assert mailbox
        # authority. The mailbox source consumer separately validates children.
        manifest=copy.deepcopy(self.manifest)
        selector=dict(root_key_sha256="a"*64,anchor_ref=dict(namespace="anchor",key="b"*64),
            root_authority_sha256="c"*64,read_grant_sha256="d"*64)
        manifest.update(consumer="mailbox_root",selector=selector,response_profile="mailbox_root_service_v1")
        reference=self.fixture["entries"]["root"]["ref"]
        manifest["children"]=[dict(index=i,role=role,ref=reference) for i,role in enumerate(sorted(proof.MAILBOX_ROOT_ROLES))]
        manifest["children"].append(dict(index=len(manifest["children"]),role="history.raw_pack",ref=self.fixture["packs"][0]["ref"]))
        return manifest,dict(consumer="mailbox_root",expected_source_state="root",selector=selector)

    def test_mailbox_root_proof_manifest_requires_complete_roles_and_unique_locators(self):
        manifest,options=self.mailbox_manifest()
        self.verify(self.response(manifest).raw,**options)
        duplicate=copy.deepcopy(manifest)
        row=copy.deepcopy(next(v for v in duplicate["children"] if v["role"]=="mailbox.slot"))
        row["index"]=len(duplicate["children"]);duplicate["children"].append(row)
        with self.assertRaises(wire.RepairWireError):
            self.response(duplicate)
        another=copy.deepcopy(duplicate);another["children"][-1]["ref"]["key"]="f"*64
        self.verify(self.response(another).raw,**options)
        missing=copy.deepcopy(manifest);missing["children"]=[v for v in missing["children"] if v["role"]!="current.status.root_read"]
        for i,row in enumerate(missing["children"]):
            row["index"]=i
        with self.assertRaises(wire.RepairWireError):
            self.response(missing)
        with self.assertRaises(wire.RepairWireError):
            self.verify(self.response(manifest).raw)

    def mailbox_feed_manifest(self):
        # Container fixture only; the HTTP test validates real feed originals.
        manifest=copy.deepcopy(self.manifest)
        selector=dict(root_key_sha256='a'*64,slot_key_sha256='b'*64,feed_ref=dict(namespace='feed',key='c'*64),
            slot_sha256='d'*64,read_grant_sha256='e'*64,maintenance_root_sha256='f'*64)
        manifest.update(consumer='mailbox_feed',selector=selector,response_profile='mailbox_feed_service_v1')
        reference=self.fixture['entries']['root']['ref']
        manifest['children']=[dict(index=i,role=role,ref=reference) for i,role in enumerate(sorted(proof.MAILBOX_FEED_ROLES))]
        for ref in (self.fixture['packs'][0]['ref'],dict(namespace='meta',key='0'*64,raw_sha256='0'*64,size=1)):
            manifest['children'].append(dict(index=len(manifest['children']),role='history.raw_pack',ref=ref))
        return manifest,dict(consumer='mailbox_feed',expected_source_state='feed',selector=selector)

    def test_mailbox_feed_manifest_requires_complete_roles_and_two_packs(self):
        manifest,options=self.mailbox_feed_manifest()
        self.verify(self.response(manifest).raw,**options)
        missing=copy.deepcopy(manifest);missing['children'].pop()
        with self.assertRaises(wire.RepairWireError):self.response(missing)
        with self.assertRaises(wire.RepairWireError):self.verify(self.response(manifest).raw)

    def mailbox_feed_with_ack_manifest(self):
        manifest,options=self.mailbox_feed_manifest()
        for role in sorted(proof.MAILBOX_ACK_CONFIGURATION_ROLES):
            manifest['children'].append(dict(index=len(manifest['children']),role=role,ref=self.fixture['entries']['root']['ref']))
        return manifest,options

    def test_mailbox_ack_configuration_roles_are_all_or_none(self):
        manifest,options=self.mailbox_feed_with_ack_manifest()
        self.verify(self.response(manifest).raw,**options)
        manifest['children'].pop()
        with self.assertRaises(wire.RepairWireError):self.response(manifest)

    def test_mailbox_body_request_binds_core_object_and_transport_profile(self):
        manifest,options=self.mailbox_feed_manifest()
        held=self.verify(self.response(manifest).raw,**options)
        index=next(v['index'] for v in manifest['children'] if v['role']=='member.core')
        reference=dict(namespace='object',key='a'*64,raw_sha256='b'*64,size=200000)
        args=dict(subject=self.subject,target=self.target,at=self.now,expires_at=self.now+20,
            child_index=index,offset=100000,requested_bytes=65536,policy=self.policy,budget=wire.RepairBudget(self.policy))
        packet=proof.make_mailbox_body_request(self.fixture['signers']['owner'],held,envelope_ref=reference,**args)
        verify=dict(expected_subject=self.subject,expected_target=self.target,at=self.now,
            policy=self.policy,budget=wire.RepairBudget(self.policy))
        entry=dict(raw=packet.raw,ref=packet.ref.as_dict())
        self.assertEqual(proof.verify_mailbox_body_request(entry,held,**verify).payload['envelope_ref'],reference)
        with self.assertRaises(wire.RepairWireError):proof.verify_bootstrap_child_request(entry,held,**verify)
        for changes in (dict(child_index=0),dict(offset=200000),dict(requested_bytes=65537)):
            with self.assertRaises(wire.RepairWireError):
                proof.make_mailbox_body_request(self.fixture['signers']['owner'],held,envelope_ref=reference,
                    **dict(args,**changes,budget=wire.RepairBudget(self.policy)))

    def assertCode(self, code, callback, *args, **kwargs):
        with self.assertRaises(wire.RepairWireError) as caught:
            callback(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_inline_response_contains_and_binds_both_actual_originals(self):
        checked = self.verify()
        self.assertEqual(len(checked.manifest.value["children"]), 21)
        self.assertEqual(checked.handle.payload["manifest_ref"], checked.manifest_ref.as_dict())
        self.assertEqual(checked.manifest.raw, canonical_bytes(self.manifest))
        with self.assertRaises(TypeError):
            checked.manifest.value["children"][0]["ref"]["key"] = "0"*64

    def empty_manifest(self):
        value=copy.deepcopy(self.manifest)
        ref=self.fixture["entries"]["root"]["ref"]
        rows=[(role,ref) for role in sorted(proof.EMPTY_FIXED_ROLES)]
        rows.extend(("history.raw_pack",dict(namespace="meta",key=digest,raw_sha256=digest,size=2))
                    for digest in ("ae"*32,"bf"*32))
        value["children"]=[dict(index=index,role=role,ref=reference) for index,(role,reference) in enumerate(rows)]
        return value

    def test_empty_phase_is_explicit_with_the_existing_owner_profile(self):
        response=self.response(self.empty_manifest())
        self.assertCode("repair_proof_mismatch",self.verify,response.raw)
        checked=self.verify(response.raw,expected_source_state="empty")
        self.assertEqual(len(checked.manifest.value["children"]),22)
        self.assertEqual(checked.manifest.value["response_profile"],"ack_owner_service_v1")
        self.assertCode("repair_proof_mismatch",self.verify,self.response().raw,
                        expected_source_state="empty")
        self.assertCode("repair_invalid_proof",self.verify,response.raw,expected_source_state="arbitrary")

    def test_empty_container_requires_exact_head_and_both_history_pack_generations(self):
        for role in ("ack.head","history.raw_pack"):
            manifest=self.empty_manifest()
            index=next(i for i,item in enumerate(manifest["children"]) if item["role"]==role)
            manifest["children"].pop(index)
            for index,item in enumerate(manifest["children"]):
                item["index"]=index
            self.assertCode("repair_invalid_proof",self.response,manifest)
        manifest=self.empty_manifest()
        manifest["response_profile"]="ack_owner_empty_service_v1"
        self.assertCode("repair_proof_mismatch",self.response,manifest)

    def occupied_manifest(self):
        value=copy.deepcopy(self.manifest)
        ref=self.fixture["entries"]["root"]["ref"]
        rows=[(role,dict(ref,namespace="object") if role=="recipient.receipt" else ref)
              for role in sorted(proof.OCCUPIED_FIXED_ROLES)]
        rows.extend(("history.raw_pack",dict(namespace="meta",key=digest,raw_sha256=digest,size=2))
                    for digest in ("ae"*32,"bf"*32,"ce"*32))
        value["children"]=[dict(index=index,role=role,ref=reference) for index,(role,reference) in enumerate(rows)]
        return value

    def test_occupied_phase_requires_explicit_expectation_and_three_complete_generations(self):
        response=self.response(self.occupied_manifest())
        checked=self.verify(response.raw,expected_source_state="occupied")
        self.assertEqual(len(checked.manifest.value["children"]),25)
        self.assertEqual(checked.manifest.value["response_profile"],"ack_owner_service_v1")
        for state in ("unbound","empty"):
            self.assertCode("repair_proof_mismatch",self.verify,response.raw,expected_source_state=state)
        for role in ("current.status.ack_disclosure","history.raw_pack"):
            manifest=self.occupied_manifest()
            manifest["children"].pop(next(index for index,item in enumerate(manifest["children"]) if item["role"]==role))
            for index,item in enumerate(manifest["children"]):
                item["index"]=index
            self.assertCode("repair_invalid_proof",self.response,manifest)

    def test_only_the_actual_receipt_role_can_use_an_object_reference(self):
        for role in ("ack.commit","ack.disclosure","current.status.ack_disclosure","history.raw_pack"):
            manifest=self.occupied_manifest()
            next(item for item in manifest["children"] if item["role"]==role)["ref"] = dict(
                self.fixture["entries"]["root"]["ref"],namespace="object")
            with self.subTest(role=role),self.assertRaises(wire.RepairWireError):
                self.response(manifest)

    def test_parent_raw_locators_and_independent_target_are_bound(self):
        for name in self.parents:
            changed = dict(self.parents[name], key="0"*64)
            self.assertCode("repair_proof_mismatch", self.verify, **{name:changed})
        self.assertCode("repair_proof_mismatch", self.verify, expected_target=ack_unbound_fixture()["expected"]["expected_target"])
        self.assertCode("repair_invalid_probe", self.verify, at=self.now+30)

    def test_missing_future_or_duplicate_role_cannot_form_this_source_profile(self):
        for change in ("missing", "unknown", "duplicate", "pack_locator"):
            m = copy.deepcopy(self.manifest)
            if change == "missing":
                m["children"].pop()
            elif change == "unknown":
                m["children"][0]["role"] = "recipient.receipt"
            elif change == "duplicate":
                m["children"][1]["role"] = m["children"][0]["role"]
            else:
                next(c for c in m["children"] if c["role"]=="history.raw_pack")["ref"]["key"]="0"*64
            self.assertCode("repair_invalid_proof", self.response, m)

    def test_encoded_and_decoded_inline_bytes_share_the_grant_cap(self):
        response = self.response()
        self.assertCode("repair_proof_too_large", self.verify, response.raw, max_proof_bytes=len(response.raw))
        self.assertCode("repair_invalid_proof", self.verify, response.raw, max_proof_items=20)
        data = json.loads(response.raw)
        del data["manifest_raw_base64url"]
        self.assertCode("repair_invalid_proof", self.verify, canonical_bytes(data))

    def test_manifest_swap_cannot_keep_original_handle(self):
        a = json.loads(self.response().raw)
        changed = copy.deepcopy(self.manifest)
        changed["service_generation"] = 2
        b = json.loads(self.response(changed).raw)
        a["manifest_raw_base64url"] = b["manifest_raw_base64url"]
        self.assertCode("repair_ref_mismatch", self.verify, canonical_bytes(a))

    def test_child_request_is_signed_for_exact_handle_range_and_subject(self):
        checked = self.verify()
        options = dict(subject=self.subject,target=self.target,at=self.now,expires_at=self.now+20,
                       child_index=0,offset=0,requested_bytes=32,policy=self.policy,budget=wire.RepairBudget(self.policy))
        request = proof.make_bootstrap_child_request(self.fixture["signers"]["owner"],checked,**options)
        verified = proof.verify_bootstrap_child_request(entry(request),checked,expected_subject=self.subject,
            expected_target=self.target,at=self.now,policy=self.policy,budget=wire.RepairBudget(self.policy))
        self.assertEqual(verified.raw,request.raw)
        self.assertNotIn("bootstrap_grant_sha256", verified.payload)
        self.assertCode("repair_proof_mismatch", proof.verify_bootstrap_child_request,entry(request),checked,
            expected_subject=self.target,expected_target=self.target,at=self.now,policy=self.policy,budget=wire.RepairBudget(self.policy))
        for change in ({"requested_bytes":0},{"offset":9007199254740991},{"child_index":99}):
            self.assertCode("repair_invalid_range" if change!={"requested_bytes":0} else "repair_invalid_integer",
                proof.make_bootstrap_child_request,self.fixture["signers"]["owner"],checked,**(options|change))


if __name__ == "__main__":
    unittest.main()
