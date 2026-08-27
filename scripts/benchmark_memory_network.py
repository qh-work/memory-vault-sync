#!/usr/bin/env python3
"""Run a credential-free synthetic benchmark of the local memory index."""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "plugins" / "memory-vault-sync" / "scripts"
sys.path.insert(0, str(RUNTIME))

from memory_vault_runtime import memory_network  # noqa: E402
from memory_vault_runtime.protocol import jcs_json_bytes, sha256_bytes  # noqa: E402


def _documents(index: int) -> list[memory_network.IndexedDocument]:
    source_key = sha256_bytes(f"synthetic-source-{index % 200}".encode("ascii"))
    (episode_path, episode), (event_path, event) = (
        memory_network.build_episode_packet(
            source_key_sha256=source_key,
            turn_key=sha256_bytes(f"synthetic-turn-{index}".encode("ascii"))[:32],
            source_sequence=index // 200,
            prompt=(
                f"合成记忆 {index}：增量同步使用提交游标、内容寻址和本地关联索引。"
            ),
            assistant=f"已保存合成记忆标记 coral-{index}。",
            created_at="2026-08-12T00:00:00Z",
        )
    )
    return [
        memory_network.IndexedDocument(
            path=episode_path,
            blob_sha=sha256_bytes(jcs_json_bytes(episode))[:40],
            value=episode,
            source_sequence=int(episode["source_sequence"]),
        ),
        memory_network.IndexedDocument(
            path=event_path,
            blob_sha=sha256_bytes(jcs_json_bytes(event))[:40],
            value=event,
            source_sequence=int(event["source"]["source_sequence"]),
        ),
    ]


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    position = min(len(ordered) - 1, int((len(ordered) - 1) * fraction))
    return ordered[position]


def benchmark(episodes: int, query_iterations: int) -> dict[str, object]:
    generated: list[memory_network.IndexedDocument] = []
    for index in range(episodes):
        generated.extend(_documents(index))
    with tempfile.TemporaryDirectory(prefix="memory-network-benchmark-") as raw:
        index_path = Path(raw) / "memory-network.sqlite3"
        index = memory_network.AssociativeIndex(index_path)
        started = time.perf_counter()
        applied = index.apply(generated, remote_head="1" * 40)
        cold_seconds = time.perf_counter() - started

        incremental_documents = _documents(episodes)
        started = time.perf_counter()
        incremental = index.apply(
            incremental_documents,
            remote_head="2" * 40,
        )
        incremental_seconds = time.perf_counter() - started

        query_seconds: list[float] = []
        hit_counts: list[int] = []
        for iteration in range(query_iterations):
            query = (
                f"coral-{episodes - 1}"
                if iteration % 2 == 0
                else "怎样让记忆增量同步使用提交游标"
            )
            started = time.perf_counter()
            hits = index.query(query, limit=8)
            query_seconds.append(time.perf_counter() - started)
            hit_counts.append(len(hits))
        stats = index.stats()
        database_bytes = sum(
            path.stat().st_size
            for path in index_path.parent.glob(f"{index_path.name}*")
            if path.is_file()
        )
    return {
        "schema_version": "memory-network-synthetic-benchmark/v1",
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
        },
        "input": {
            "episodes": episodes,
            "documents": len(generated),
            "query_iterations": query_iterations,
            "private_data_used": False,
        },
        "cold_index": {
            "seconds": round(cold_seconds, 6),
            "documents_applied": applied["documents"],
            "fragments_applied": applied["fragments"],
            "database_bytes": database_bytes,
        },
        "one_turn_incremental": {
            "seconds": round(incremental_seconds, 6),
            "documents_applied": incremental["documents"],
            "fragments_applied": incremental["fragments"],
        },
        "local_query": {
            "median_seconds": round(statistics.median(query_seconds), 6),
            "p95_seconds": round(_percentile(query_seconds, 0.95), 6),
            "maximum_seconds": round(max(query_seconds), 6),
            "minimum_hit_count": min(hit_counts),
            "network_accessed": False,
        },
        "final_index": stats,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--episodes", type=int, default=5000)
    parser.add_argument("--query-iterations", type=int, default=25)
    args = parser.parse_args()
    if not 1 <= args.episodes <= 1_000_000:
        parser.error("--episodes must be between 1 and 1000000")
    if not 1 <= args.query_iterations <= 10_000:
        parser.error("--query-iterations must be between 1 and 10000")
    print(
        json.dumps(
            benchmark(args.episodes, args.query_iterations),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
