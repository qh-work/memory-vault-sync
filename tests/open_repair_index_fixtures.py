"""New explicit synthetic publication permissions over a real saved ACK source."""
import copy
import hashlib
import json
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from memory_vault import canonical_bytes
from memory_vault_trust import Identity
from memory_vault_network_crypto import EncryptionIdentity
import memory_vault_open_provider as provider
import memory_vault_open_repair_index as index
import memory_vault_open_repair_wire as wire
from tests.open_repair_ack_fixtures import reference, signed_entry
from tests import test_open_repair_state as source_tests
from tests.test_open_repair_occupied import OpenRepairOccupiedTests


class IndexFixture:
    def __init__(self, *, source_maintainer=True, root_publish=True, index_max_meta_bytes=None):
        original_setup = source_tests.RepairStateTests.owner_setup
        def setup(instance):
            # This is a new source: the owner names the real R before signing.
            target = instance.state.target
            if source_maintainer:
                instance.fixture["docs"]["root"]["payload"]["maintainers"] = [
                    dict(signing_key_id=target["signing_key"]["key_id"], encryption_key_id=target["encryption_key"]["key_id"])]
            if not root_publish:
                instance.fixture["docs"]["root"]["payload"]["operation_mask"] &= ~16
            return original_setup(instance)
        self.case = OpenRepairOccupiedTests()
        with patch.object(source_tests.RepairStateTests, "owner_setup", setup):
            self.case.setUp()
        self.result = self.case.put()
        self.h, self.f = self.case.h, self.case.h.fixture
        self.source = self.case.verify(self.result)
        self.policy = self.h.state.policy
        self.directory = Identity(Ed25519PrivateKey.generate())
        self.directory_encryption = EncryptionIdentity.generate()
        self.directory_keys = dict(signing_key=self.directory.public_descriptor(), encryption_key=self.directory_encryption.public_descriptor())
        self.epoch = "synthetic_directory_epoch"
        self.at = 2_000_000_020
        self.publisher = self.h.state.target
        self.publisher_id = dict(signing_key_id=self.publisher["signing_key"]["key_id"], encryption_key_id=self.publisher["encryption_key"]["key_id"])
        self.directory_id = dict(signing_key_id=self.directory.key_id, encryption_key_id=self.directory_encryption.key_id)
        self.slot = self.f["expected"]["expected_ack_slot"]
        self.root = self.slot["root_key"]
        self.until = 2_000_000_500
        raw = canonical_bytes(provider.issue_fact(self.f["signers"]["target"], ref=self.root["anchor_ref"],
            storage_epoch=self.f["expected"]["target_storage_epoch"], custody_id="ack_"+self.source.commit.ref.raw_sha256,
            revision=1, issued_at=2_000_000_009, expires_at=self.until))
        self.fact = dict(raw=raw, ref=reference(raw,"index-fact"))
        self.scope = dict(kind="ack_occupied", ack_slot=self.slot, grant_ref=self.case.case.write["ref"],
            binding_ref=self.case.case.bound["binding"]["ref"], receipt_ref=self.case.receipt["ref"], original_ack_commit_ref=self.result["commit"]["ref"])
        caps = copy.deepcopy(self.f["docs"]["root"]["payload"]["budget"])
        if index_max_meta_bytes is not None:
            if type(index_max_meta_bytes) is not int or not 0 < index_max_meta_bytes <= caps["max_meta_bytes"]:
                raise ValueError("index_max_meta_bytes must narrow the original source budget")
            caps["max_meta_bytes"] = index_max_meta_bytes
        caps["max_live_bytes"] = 0
        self.intent = dict(kind="resource.index_intent",allocation_id="synthetic_index_allocation",job_id="synthetic_index_job",
            root_key=self.root,caller=self.publisher,target=self.directory_keys,target_storage_epoch=self.epoch,purpose="provider_index",
            scope=self.scope,advertised_custody_ref=self.result["commit"]["ref"],provider_fact_ref=self.fact["ref"],
            historical_manifest_ref=self.result["manifest"]["ref"],budget=caps,windows={name:self.until for name in provider.WINDOWS})
        self.intent_digest = hashlib.sha256(canonical_bytes(self.intent)).hexdigest()
        budget = wire.RepairBudget(self.policy)
        self.head = index.occupied.verify_ack_occupied_head(self.result["head"],self.source,expected_target=self.publisher,policy=self.policy,budget=budget)
        self.rows = index.source_original_inventory(self.source,self.head,policy=self.policy,budget=budget)
        self.consents = {}
        for variant, role in (("owner","owner"),("receipt_writer","writer")):
            signer = self.f["signers"][role]
            originals,scopes = index._permissions(self.rows,signer.key_id,self.policy,budget)
            payload = dict(schema_version=index.SCHEMA,kind="ack.index_consent",signing_key=signer.public_descriptor(),
                variant=variant,issued_at=2_000_000_010,expires_at=self.until,consent_id="synthetic_index_"+variant,revision=1,
                ack_slot=self.slot,root_authority_ref=self.f["entries"]["root"]["ref"],grant_ref=self.case.case.write["ref"],
                binding_ref=self.case.case.bound["binding"]["ref"],receipt_ref=self.case.receipt["ref"],original_disclosure_ref=self.case.disclosure["ref"],
                original_ack_commit_ref=self.result["commit"]["ref"],historical_manifest_ref=self.result["manifest"]["ref"],
                publisher=self.publisher_id,target=self.directory_keys,target_storage_epoch=self.epoch,operation_mask=16,
                reservation_disclosure=dict(intent_sha256=self.intent_digest,until=self.until),
                post_assignment_disclosure=dict(originals=originals,status_scopes=scopes,until=self.until))
            self.consents[role] = signed_entry(payload,signer,"index-consent-"+role)
        self.current = []
        for role, revision in (("owner",3),("writer",2),("target",2)):
            signer = self.f["signers"][role]
            _,scopes = index._permissions(self.rows,signer.key_id,self.policy,budget)
            self.current.append(self.status(signer,scopes,revision,"current-"+role))
        # Publication-only Q scopes cannot be returned under an older owner
        # bootstrap or B disclosure. Keep every Signed T intact and give each
        # issuer/root original its own increasing revision, across both uses.
        for role, revision in (("owner",4),("writer",3)):
            scope=dict(scope_kind="authority",scope_id=self.authority(self.consents[role],"ack.index_consent"))
            self.current.append(self.status(self.f["signers"][role],[scope],revision,"publication-current-"+role))
        self.allocation = signed_entry(dict(schema_version=index.SCHEMA,kind="resource.allocate",signing_key=self.publisher["signing_key"],
            issued_at=2_000_000_011,expires_at=self.until,request_id="synthetic_index_allocate",target_node_key_id=self.directory.key_id,
            target_storage_epoch=self.epoch,intent=self.intent,intent_sha256=self.intent_digest), self.f["signers"]["target"],"index-allocate")
        self.resource = dict(node_key_id=self.directory.key_id,storage_epoch=self.epoch,lease_id="synthetic_index_lease",resource_id="synthetic_index_resource")
        self.offer = signed_entry(dict(schema_version=index.SCHEMA,kind="resource.offer",signing_key=self.directory.public_descriptor(),
            issued_at=2_000_000_012,reservation_until=2_000_000_060,offer_id="synthetic_index_offer",allocation_request_ref=self.allocation["ref"],
            intent=self.intent,intent_sha256=self.intent_digest,resource=self.resource,target_encryption_key=self.directory_keys["encryption_key"],
            reservation_generation=1,budget=caps,windows=self.intent["windows"]),self.directory,"index-offer")
        self.assignment = signed_entry(dict(schema_version=index.SCHEMA,kind="maintenance.assignment",signing_key=self.publisher["signing_key"],
            issued_at=2_000_000_013,expires_at=self.until,assignment_id="synthetic_index_assignment",job_id=self.intent["job_id"],root_key=self.root,
            parent_root_ref=self.f["entries"]["root"]["ref"],parent_assignment_ref=None,depth=2,subject=self.directory_id,
            target_node_key_id=self.directory.key_id,target_storage_epoch=self.epoch,operation_mask=16,scope=self.scope,
            resource_intent_sha256=self.intent_digest,resource_offer_ref=self.offer["ref"],resource=self.resource,bootstrap_grant_refs=[],
            budget=caps,windows=self.intent["windows"]),self.f["signers"]["target"],"index-assignment")
        originals,scopes = index._permissions(self.rows,self.f["signers"]["target"].key_id,self.policy,budget)
        self.request = signed_entry(dict(schema_version=index.SCHEMA,kind="ack.index_publish",signing_key=self.publisher["signing_key"],
            issued_at=2_000_000_014,expires_at=self.until,request_id="synthetic_index_publish",subject=self.publisher_id,target=self.directory_id,
            target_storage_epoch=self.epoch,allocation_request_ref=self.allocation["ref"],resource_offer_ref=self.offer["ref"],
            assignment_ref=self.assignment["ref"],owner_consent_ref=self.consents["owner"]["ref"],recipient_consent_ref=self.consents["writer"]["ref"],
            provider_fact_ref=self.fact["ref"],source_head_ref=self.result["head"]["ref"],historical_manifest_ref=self.result["manifest"]["ref"],
            original_ack_commit_ref=self.result["commit"]["ref"],stage_result_ref=reference(b"synthetic pending stage result","stage-result"),
            source_disclosure=dict(originals=originals,status_scopes=scopes,until=self.until)),self.f["signers"]["target"],"index-publish")
        assignment_scope = dict(scope_kind="assignment",scope_id=hashlib.sha256(canonical_bytes(dict(kind="assignment",root_key=self.root,
            assignment_kind="maintenance.assignment",assignment_sha256=self.assignment["ref"]["raw_sha256"]))).hexdigest())
        resource_scope = dict(scope_kind="resource",scope_id=hashlib.sha256(canonical_bytes(dict(kind="resource",root_key=self.root,resource=self.resource))).hexdigest())
        self.directory_statuses = [self.status(self.f["signers"]["target"],[assignment_scope],3,"assignment-status",minimum=0),
            self.status(self.directory,[resource_scope],1,"directory-status")]

    def close(self):
        self.case.tearDown()

    def authority(self,entry,kind):
        return hashlib.sha256(canonical_bytes(dict(kind="authority",root_key=self.root,authority_kind=kind,authority_sha256=entry["ref"]["raw_sha256"]))).hexdigest()

    def status(self,signer,scopes,revision,name,minimum=1):
        return signed_entry(dict(schema_version="memory-vault-open-authority/v1",kind="authority.status",signing_key=signer.public_descriptor(),
            scope_key=dict(root_key=self.root,issuer_key_id=signer.key_id),revision=revision,issued_at=2_000_000_014,valid_until=self.until,
            entries=sorted([dict(**scope,minimum_document_revision=minimum,status="active",operation_mask=127) for scope in scopes],
                key=lambda item:(item["scope_kind"],item["scope_id"]))),signer,name)

    def inputs(self):
        budget=wire.RepairBudget(self.policy)
        resolver=wire.LocalRawResolver(self.policy,budget)
        for namespace,key,raw in self.h.db.execute("""SELECT o.namespace,o.opaque_key,o.raw FROM open_repair_ack_objects o JOIN open_repair_ack_pins p
            ON p.namespace=o.namespace AND p.opaque_key=o.opaque_key WHERE p.resource_id=? AND p.role IN ('pack','empty:pack','occupied:pack')""",(self.h.resource_id,)):
            resolver.put(namespace,key,bytes(raw))
        args=(self.result["manifest"],resolver,self.result["commit"],self.result["head"],self.fact,self.intent,self.consents["owner"],self.consents["writer"])
        kwargs=dict(expected_ack_slot=self.slot,expected_owner=self.f["expected"]["expected_owner"],
            expected_receipt_writer=self.case.case.expected["expected_receipt_writer"],expected_message_id=self.case.case.expected["expected_message_id"],
            expected_envelope_ref=self.case.case.expected["expected_envelope_ref"],expected_source=self.publisher,
            source_storage_epoch=self.f["expected"]["target_storage_epoch"],expected_directory=self.directory_keys,directory_storage_epoch=self.epoch,
            current_statuses=self.current,at=self.at,limit_policy=self.f["expected"]["limit_policy"],policy=self.policy,budget=budget)
        return args,kwargs

    def verify(self,*,admission=False):
        args,kwargs=self.inputs()
        if admission:
            kwargs.update(allocation_entry=self.allocation,offer_entry=self.offer,assignment_entry=self.assignment,
                publication_request_entry=self.request,directory_statuses=self.directory_statuses)
        result=(index.verify_ack_index_admission if admission else index.verify_ack_index_plan)(*args,**kwargs)
        return result,kwargs["budget"].snapshot()
