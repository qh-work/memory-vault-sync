#!/usr/bin/env python3
"""All-synthetic local A/B/C/D epistemic demo; no external model or network.

Four logical Agent facades use the existing single Vault and six-operation
API. This tests declared experience semantics, not actual independent actors.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from memory_vault import canonical_bytes
from memory_vault_agent import Agent
from memory_vault_client import CONFIG_SCHEMA
from memory_vault_storage import atomic_write


def invoke(agent: Agent, **request):
    response = agent.handle(request)
    if not response.get("ok"):
        raise RuntimeError(f"Synthetic {request['op']} failed: {response.get('error')}")
    return response["result"]


def read_all(agent: Agent, **selector):
    result = invoke(agent, op="recall", include_experience=True, **selector)
    hits = list(result["hits"])
    while result.get("next_cursor"):
        result = invoke(agent, op="recall", cursor=result["next_cursor"])
        hits.extend(result["hits"])
    return hits


def run_demo():
    with tempfile.TemporaryDirectory(prefix="memory-vault-experience-synthetic-") as directory:
        root = Path(directory).resolve()
        config = root / "client.json"
        atomic_write(config, canonical_bytes({
            "schema_version": CONFIG_SCHEMA,
            "vault_path": str(root / "vault.sqlite3"),
            "capture_visible_turns": False,
        }), replace=False)
        agents = {label: Agent(config) for label in "ABCD"}
        discovery = invoke(agents["D"], op="discover")
        assert not discovery["network_accessed"]

        a = invoke(agents["A"], op="remember", kind="observation",
            request_id="req_demo_experience_a_observation",
            text="Synthetic method X failed in environment V1; A observed this directly.",
            experience={"epistemic_type": "observation", "source_agent": "synthetic-A",
                "observed_under": {"environment": "V1"},
                "retry_predicate": "Recheck if the environment changes.",
                "evidence_refs": ["synthetic:log-A-V1"]})["memory_id"]

        inherited = read_all(agents["B"], memory_id=a)[0]
        assert inherited["experience"]["source"]["claimed_source_agent"] == "synthetic-A"
        b_hearsay = invoke(agents["B"], op="remember", kind="observation",
            request_id="req_demo_experience_b_hearsay",
            text="Synthetic method X failed under V1 according to A; B has only received this report.",
            experience={"epistemic_type": "observation", "source_agent": "synthetic-B",
                "source_memory_refs": [a], "observed_under": {"environment": "V1"}})["memory_id"]
        retelling = read_all(agents["B"], memory_id=b_hearsay)[0]["experience"]
        assert retelling["epistemic_type"] == "hearsay"
        assert {"type": "heard_from", "target": a} in retelling["relations"]

        b = invoke(agents["B"], op="remember", kind="observation",
            request_id="req_demo_experience_b_experiment",
            text="Synthetic method X failed under V1 in B's separate experiment.",
            experience={"epistemic_type": "experiment", "source_agent": "synthetic-B",
                "observed_under": {"environment": "V1"},
                "evidence_refs": ["synthetic:log-B-V1"],
                "relations": [{"type": "independently_confirms", "target": a}]})["memory_id"]

        received_by_c = read_all(agents["C"], query="Synthetic method X")
        assert {a, b}.issubset({hit["memory_id"] for hit in received_by_c})
        c = invoke(agents["C"], op="remember", kind="observation",
            request_id="req_demo_experience_c_counterexperiment",
            text="Synthetic method X succeeded under V2 in C's experiment; the V1 failure is conditional.",
            experience={"epistemic_type": "experiment", "source_agent": "synthetic-C",
                "observed_under": {"environment": "V2"},
                "evidence_refs": ["synthetic:log-C-V2"],
                "relations": [{"type": "contradicts", "target": a},
                              {"type": "contradicts", "target": b}]})["memory_id"]

        hits = read_all(agents["D"], query="Synthetic method X")
        by_id = {hit["memory_id"]: hit for hit in hits}
        assert {a, b_hearsay, b, c}.issubset(by_id)
        assert by_id[a]["experience"]["observed_under"] == {"environment": "V1"}
        assert by_id[c]["experience"]["observed_under"] == {"environment": "V2"}
        assert all(by_id[memory_id]["status"] == "current" for memory_id in (a, b_hearsay, b, c))
        summary = by_id[a]["experience"]["provenance_summary"]
        assert summary["propagation_count"] == 1
        assert summary["unique_origin_roots"] == 3
        assert summary["independent_confirmation_count"] == 1
        assert summary["contradiction_count"] == 1
        assert summary["independence_verified"] is False
        assert summary["truth_score"] is None
        assert not summary["truncated"]
        labels = [("A: direct observation under V1", a),
                  ("B: received hearsay under V1", b_hearsay),
                  ("B: claimed independent confirmation under V1", b),
                  ("C: contradiction under V2", c)]
        return {
            "demo": "synthetic logical agents; one existing local Vault",
            "network_accessed": False,
            "real_models_exercised": False,
            "authenticated_independent_actors": False,
            "reader": "synthetic-D",
            "views": [{"label": label, "memory_id": memory_id,
                       "status": by_id[memory_id]["status"],
                       "experience": by_id[memory_id]["experience"]}
                      for label, memory_id in labels],
            "provenance_summary": summary,
            "conclusion": "Preserve the distinct V1 and V2 evidence; no permanent global verdict.",
            "checks_passed": True,
        }


if __name__ == "__main__":
    print(json.dumps(run_demo(), ensure_ascii=False, indent=2))
