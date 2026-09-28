"""The exact receipt writer's current permission to inspect an empty source.

The source proof is inherited from the full original empty event, but the
current permission is the independent A-signed offer grant for B. The owner's
read grant remains a historical activation input and gives B no current right.
"""
import memory_vault_open_repair_empty as empty
from memory_vault_open_repair_empty_access import RepairAckEmptyAccess


PROFILE = "ack_offer_service_v1"
CURRENT_ROLES = ("current.status.ack_root", "current.status.ack_write",
    "current.status.ack_offer_bootstrap", "current.status.ack_slot", "current.status.ack_resource")
FIXED_PROOF_ROLES = empty.ROLES | {"history.ack_empty", "ack.empty_custody", "ack.head"} | frozenset(CURRENT_ROLES)


class RepairAckOfferAccess(RepairAckEmptyAccess):
    def _current_authority(self, checked, owner, slot, action, now, policy, budget):
        prior, authorities = checked.predecessor, checked.authorities
        root, active = (prior.resources.originals[name].payload for name in ("root", "active"))
        write = authorities.originals["write"].payload
        grant_original = authorities.originals["bootstrap"]
        grant = grant_original.payload
        permitted = empty._obligations(prior, authorities, owner, self.state.target, slot, policy, budget)
        role_map = {"historical.status." + name[len("current.status."):]: name for name in CURRENT_ROLES}
        obligations = []
        for item in permitted:
            if item["role"] not in role_map:
                continue
            mask = 1 if item["role"] == "historical.status.ack_write" else 3
            if action == "challenge" and item["role"] in ("historical.status.ack_root", "historical.status.ack_offer_bootstrap"):
                mask |= 8
            obligations.append(item | dict(role=role_map[item["role"]], mask=mask))
        expires = min(root["expires_at"], write["expires_at"], grant["expires_at"], grant["proof_until"],
            grant["probe_until"] if action == "challenge" else grant["proof_until"], checked.read_until,
            prior.descriptor.payload["expires_at"],
            *(item["windows"][name] for item in (root, active) for name in ("admit_until", "read_until", "retain_until")),
            write["windows"]["admit_until"], write["windows"]["retain_until"])
        mask = 11 if action == "challenge" else 3
        code = None
        if (not all(item["issued_at"] <= now for item in (root, write, grant)) or now >= expires
                or root["operation_mask"] & mask != mask or write["operation"] != "receipt.put"):
            code = "repair_access_expired"
        return grant_original, permitted, obligations, expires, code
