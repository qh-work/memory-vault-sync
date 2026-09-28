"""Prepare an original source's explicit directory publication outside locks.

Publication uses its own A/B authorizations. Owner READ or an index lease never
substitutes for them. The existing shared authority ledger records refusals and
rechecks immutable source bytes before any request leaves the source.
"""
from types import MappingProxyType

import memory_vault_open_repair_access as access
import memory_vault_open_repair_ack as ack
import memory_vault_open_repair_empty as empty
import memory_vault_open_repair_index as index
from memory_vault_open_repair_index_journal import AckIndexJournal
import memory_vault_open_repair_occupied as occupied
import memory_vault_open_repair_occupied_state as occupied_state
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_state as storage
import memory_vault_open_repair_wire as wire


class AckIndexSourceAccess(access.RepairAckAccess):
    def initialize(self):
        super().initialize()
        AckIndexJournal(self.state).initialize()

    def _snapshot(self, resource_id):
        row, stamp, pins = occupied_state._OccupiedAccess._snapshot(self,resource_id)
        if row["status"] != "occupied":
            wire._fail("repair_index_source_inactive")
        return row, stamp, pins

    def prepare(self, resource_id, *, provider_fact_entry, intent,
                owner_consent_entry, recipient_consent_entry, current_statuses,
                expected_directory, directory_storage_epoch, policy=None, budget=None):
        if (policy is None) != (budget is None):
            wire._fail("repair_invalid_context")
        policy = self.state.policy if policy is None else policy
        budget = wire.RepairBudget(policy) if budget is None else budget
        wire._context(policy,budget)
        # No source or consent signature runs before this durable reservation.
        # It shares the already signed source budget with all other consumers.
        with AckIndexJournal(self.state).preparation_work(resource_id,budget):
            return self._prepare(resource_id,provider_fact_entry=provider_fact_entry,intent=intent,
                owner_consent_entry=owner_consent_entry,recipient_consent_entry=recipient_consent_entry,
                current_statuses=current_statuses,expected_directory=expected_directory,
                directory_storage_epoch=directory_storage_epoch,policy=policy,budget=budget)

    def _prepare(self, resource_id, *, provider_fact_entry, intent,
                owner_consent_entry, recipient_consent_entry, current_statuses,
                expected_directory, directory_storage_epoch, policy, budget):
        with self.state._lock:
            if self.db.in_transaction:
                wire._fail("repair_storage_transaction")
            row, stamp, pins = self._snapshot(resource_id)
            now = self.state._now()
        binding, commit = dict(stamp[1]), dict(stamp[3])
        originals, roles = {}, {}
        resolver = wire.LocalRawResolver(policy,budget)
        for role,namespace,key,digest,size,raw in (*pins,*stamp[5]):
            ref = wire.RawRef(namespace,key,digest,size)
            frozen = wire._snapshot(bytes(raw),policy,budget)
            if len(frozen)!=ref.size or budget._hash(frozen)!=ref.raw_sha256:
                wire._fail("repair_storage_corrupt")
            entry = dict(raw=frozen,ref=ref.as_dict())
            if ref in originals and originals[ref]!=frozen:
                wire._fail("repair_storage_corrupt")
            originals[ref] = frozen
            roles.setdefault(role,[]).append(entry)
            if role in ("pack","empty:pack","occupied:pack"):
                if resolver.put(namespace,key,frozen).ref!=ref:
                    wire._fail("repair_storage_corrupt")

        def by_reference(raw):
            ref = wire.raw_ref(wire.parse_new_wire(bytes(raw),policy,budget).value)
            if ref not in originals:
                wire._fail("repair_local_original_mismatch")
            return dict(raw=originals[ref],ref=ref.as_dict())

        def one(role):
            if len(roles.get(role,()))!=1:
                wire._fail("repair_storage_corrupt")
            return roles[role][0]

        owner = wire.parse_new_wire(bytes(row["owner_keys"]),policy,budget).value
        writer = wire.parse_new_wire(bytes(binding["writer_keys"]),policy,budget).value
        write = wire.parse_new_wire(one("empty:ack.write_grant")["raw"],policy,budget).value["payload"]
        root = wire.parse_new_wire(one("ack.root_authority")["raw"],policy,budget).value["payload"]
        source_manifest = by_reference(commit["manifest_ref"])
        source_commit = by_reference(commit["commit_ref"])
        source_head = by_reference(commit["head_ref"])
        plan = index.verify_ack_index_plan(source_manifest,resolver,source_commit,source_head,
            provider_fact_entry,intent,owner_consent_entry,recipient_consent_entry,
            expected_ack_slot=root["ack_slot"],expected_owner=owner,expected_receipt_writer=writer,
            expected_message_id=write["message_id"],expected_envelope_ref=write["envelope_ref"],
            expected_source=self.state.target,source_storage_epoch=self.state.node["payload"]["storage_epoch"],
            expected_directory=expected_directory,directory_storage_epoch=directory_storage_epoch,
            current_statuses=current_statuses,at=now,limit_policy=self.state.limits,policy=policy,budget=budget)
        self._validate_source(row,stamp,roles,plan,writer,policy,budget)
        prepared = access._Preparation()
        capacity = plan.source.predecessor.predecessor.resources.originals["active"].payload["budget"]
        self._prepared[prepared] = dict(resource_id=resource_id,stamp=stamp,pins=pins,action="index.publish",
            root_digest=budget._hash(wire._canonical(root["ack_slot"]["root_key"],budget)),
            obligations=tuple(dict(item,role="current.status") for item in plan.obligations),statuses=plan.statuses,
            status_refs={item.canonical_sha256:wire._canonical(item.ref.as_dict(),budget) for item in plan.statuses},
            basis=(),expected_generation=None,expires=plan.publish_until,code=plan.denial_code,
            subject=MappingProxyType(dict(plan.intent["caller"])),selector=MappingProxyType(dict(plan.intent["scope"])),
            grant_ref=wire.raw_ref(one("ack.root_authority")["ref"]),limits=MappingProxyType(dict(self.state.limits)),
            capacity=capacity,source=plan.source,plan=plan,checked=False,proof=(),
            originals=MappingProxyType(originals),source_manifest=source_manifest,
            source_commit=source_commit,source_head=source_head,owner=owner,writer=writer,
            slot=root["ack_slot"],message_id=write["message_id"],envelope_ref=write["envelope_ref"])
        return prepared

    def prepare_assignment(self, prepared, *, allocation_entry,offer_entry,assignment_entry,
                           directory_statuses,policy=None,budget=None):
        """Extend a real prepared source with complete pre-stage M→D authority.

        No caller-created wrapper, future publication request or stage result is
        accepted. All new signatures stay outside the short floor transaction.
        """
        if (policy is None)!=(budget is None):
            wire._fail("repair_invalid_context")
        policy=self.state.policy if policy is None else policy
        budget=wire.RepairBudget(policy) if budget is None else budget
        wire._context(policy,budget)
        held=self._get(prepared)
        with self.state._transaction():
            decision=self.check_locked(prepared)
        if not decision.allowed:
            wire._fail(decision.code)
        with AckIndexJournal(self.state).preparation_work(held["resource_id"],budget):
            resolver=wire.LocalRawResolver(policy,budget)
            for role,namespace,key,digest,size,raw in (*held["pins"],*held["stamp"][5]):
                if role in ("pack","empty:pack","occupied:pack"):
                    resolver.put(namespace,key,bytes(raw))
            plan=held["plan"]
            entry=lambda item:dict(raw=item.raw,ref=item.ref.as_dict())
            checked=index.verify_ack_index_assignment(held["source_manifest"],resolver,held["source_commit"],held["source_head"],
                entry(plan.fact),plan.intent,entry(plan.owner_consent),entry(plan.recipient_consent),
                expected_ack_slot=held["slot"],expected_owner=held["owner"],expected_receipt_writer=held["writer"],
                expected_message_id=held["message_id"],expected_envelope_ref=held["envelope_ref"],expected_source=self.state.target,
                source_storage_epoch=self.state.node["payload"]["storage_epoch"],expected_directory=plan.intent["target"],
                directory_storage_epoch=plan.intent["target_storage_epoch"],current_statuses=[entry(item) for item in plan.statuses],
                at=self.state._now(),limit_policy=self.state.limits,policy=policy,budget=budget,
                allocation_entry=allocation_entry,offer_entry=offer_entry,assignment_entry=assignment_entry,directory_statuses=directory_statuses)
            next_prepared=access._Preparation()
            self._prepared[next_prepared]=dict(held,plan=checked.plan,assignment=checked,
                obligations=tuple(dict(item,role="current.status") for item in checked.obligations),statuses=checked.statuses,
                status_refs={item.canonical_sha256:wire._canonical(item.ref.as_dict(),budget) for item in checked.statuses},
                expires=checked.publish_until,code=checked.denial_code,checked=False,proof=())
            return next_prepared

    def assignment(self,prepared):
        held=self._get(prepared)
        if "assignment" not in held:
            wire._fail("repair_index_assignment_missing")
        return held["assignment"]

    def _validate_source(self,row,stamp,roles,plan,writer,policy,budget):
        """Recheck actual standalone pins/ledgers using the already verified H.

        The pure verifier authenticates pack members. It must not hide a missing
        or incorrectly assigned standalone role in this source's durable state.
        """
        source=plan.source
        bound,prior=source.predecessor,source.predecessor.predecessor
        tables=[]
        for prefix,required,manifest in (("",ack.ROLES|{"manifest","custody","pack"},prior.manifest),
                ("empty:",empty.ROLES|{"manifest","custody","head","binding","pack"},bound.manifest),
                ("occupied:",occupied.ROLES|{"manifest","commit","head","pack"},source.manifest)):
            table={role[len(prefix):]:values for role,values in roles.items()
                if role.startswith(prefix) and (bool(prefix) or not role.startswith(("empty:","occupied:")))}
            if table.keys()!=required or any(len(v)!=1 for name,v in table.items() if name!="pack"):
                wire._fail("repair_storage_corrupt")
            if any(table[item.role][0]!=dict(raw=item.original.raw,ref=item.original.ref.as_dict()) for item in manifest.roles):
                wire._fail("repair_storage_corrupt")
            used={wire.raw_ref(item["pack_ref"]) for item in manifest.manifest.value["roles"]}
            if {wire.raw_ref(item["ref"]) for item in table["pack"]}!=used or len(table["pack"])!=len(used):
                wire._fail("repair_unused_pack")
            tables.append(table)
        old,new,held=tables
        binding,reservation,commit,job=(dict(stamp[i]) for i in (1,2,3,4))
        def saved_ref(raw):
            return wire.parse_new_wire(bytes(raw),policy,budget).value
        if (old["custody"][0]!=self._saved(row,"custody",policy,budget)
                or old["manifest"][0]["ref"]!=saved_ref(row["manifest_ref"])
                or new["history.ack_unbound"][0]!=old["manifest"][0]
                or new["ack.unbound_custody"][0]!=old["custody"][0]
                or new["binding"][0]!=new["ack.binding"][0]
                or held["history.ack_empty"][0]!=new["manifest"][0]
                or held["ack.empty_custody"][0]!=new["custody"][0]):
            wire._fail("repair_storage_corrupt")
        for names,table,record in (("binding manifest custody head",new,binding),("manifest commit head",held,commit)):
            if any(table[name][0]["ref"]!=saved_ref(record[name+"_ref"]) for name in names.split()):
                wire._fail("repair_storage_corrupt")
        setup=wire.parse_new_wire(bytes(row["activation_inputs"]),policy,budget).value
        exact={"resource.ack_allocate":self._saved(row,"allocation",policy,budget),
            "resource.ack_offer":self._saved(row,"offer",policy,budget),
            "resource.ack_active":self._saved(row,"active",policy,budget),
            "historical.status.ack_resource":self._saved(row,"source_status",policy,budget)}
        for role,name in (("ack.root_authority","root"),("ack.read_grant","read"),
                ("bootstrap.ack_owner","bootstrap"),("resource.ack_activation","activation")):
            exact[role]=dict(raw=setup[name]["raw"].encode(),ref=setup[name]["ref"])
        if any(old[role][0]!=entry for role,entry in exact.items()):
            wire._fail("repair_local_original_mismatch")
        head=occupied._signed(new["head"][0],self.state.target["signing_key"],"ack.head",
            resource.COMMON|{"ack_slot","generation","observed_at","retain_until","state","root_authority_ref","grant_ref","binding_ref"},policy,budget)
        h=head.payload
        slot=source.commit.payload["ack_slot"]
        if (h["state"]!="empty" or wire.u53(h["generation"],1)!=1 or h["ack_slot"]!=slot
                or h["observed_at"]!=bound.stored_at or h["retain_until"]!=bound.retain_until
                or any(h[name]!=bound.custody.payload[name] for name in ("root_authority_ref","grant_ref","binding_ref"))):
            wire._fail("repair_storage_corrupt")
        write,offer=(bound.authorities.originals[name] for name in ("write","bootstrap"))
        expected=dict(receipt_writer=writer,message_id=write.payload["message_id"],envelope_ref=write.payload["envelope_ref"],
            read_until=bound.read_until,retain_until=bound.retain_until)
        if (binding["grant_id"]!=slot["grant_id"] or binding["generation"]!=1 or binding["write_digest"]!=write.ref.raw_sha256
                or binding["request_digest"]!=budget._hash(wire._canonical(dict(write=write.ref.as_dict(),bootstrap=offer.ref.as_dict(),expected=expected),budget))):
            wire._fail("repair_binding_ledger_missing")
        receipt=source.inputs["receipt"]
        request=dict(receipt=receipt.ref.as_dict(),disclosure=source.inputs["disclosure"].ref.as_dict(),
            put=source.inputs["put"].ref.as_dict(),read_until=source.read_until,retain_until=source.retain_until)
        expected_job=occupied_state.RepairAckOccupiedState._job(row["resource_id"],{name:held[name][0] for name in ("manifest","commit","head")})
        if (commit["receipt_digest"]!=receipt.ref.raw_sha256 or commit["grant_id"]!=slot["grant_id"]
                or commit["generation"]!=2 or commit["live_bytes"]!=len(receipt.raw)
                or saved_ref(commit["receipt_ref"])!=receipt.ref.as_dict()
                or commit["request_digest"]!=budget._hash(wire._canonical(request,budget))
                or job["kind"]!="ack.head.publish" or job["state"]!="pending"
                or bytes(job["raw"])!=wire._canonical(expected_job,budget)
                or saved_ref(job["head_ref"])!=held["head"][0]["ref"]
                or commit["job_bytes"]!=len(job["raw"])+storage.ROW_CHARGE):
            wire._fail("repair_receipt_ledger_missing")
        caps=prior.resources.originals["active"].payload["budget"]
        charge=caps["max_live_bytes"]+caps["max_meta_bytes"]+caps["max_job_bytes"]+caps["max_replay_records"]*storage.REPLAY_CHARGE+storage.ROW_CHARGE
        if (reservation["digest"]!=row["request_digest"] or reservation["charge_bytes"]!=charge
                or reservation["retain_until"]!=row["retain_until"] or reservation["owner"]!=row["owner"]
                or reservation["operation_id"]!=row["allocation_id"] or commit["live_bytes"]>caps["max_live_bytes"]
                or commit["job_bytes"]>caps["max_job_bytes"] or caps["max_jobs"]<1):
            wire._fail("repair_capacity_reservation_missing")

    def plan(self, prepared):
        return self._get(prepared)["plan"]

    def parties(self, prepared):
        """Independent full party keys already authenticated for this source."""
        held = self._get(prepared)
        return MappingProxyType(dict(owner=held["owner"], receipt_writer=held["writer"]))

    def originals(self, prepared):
        """Local-only frozen source originals; permission is checked before IO."""
        return self._get(prepared)["originals"]
