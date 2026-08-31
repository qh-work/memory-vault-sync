#!/usr/bin/env python3
"""Exercise a selected built plugin using only new synthetic local data.

Uses the actual package launcher, not modules imported from this checkout.
Does not install a plugin, inspect host transcripts, connect a network or open
the user's client configuration. All temporary writers stop before backup.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile


def records(path: Path) -> dict[str, str]:
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as db:
        return dict(db.execute("SELECT memory_id,record_json FROM memories"))


def verify(plugin: Path, python: str) -> dict:
    launcher = plugin / "scripts" / "launcher.py"
    if not launcher.is_file() or launcher.is_symlink():
        raise ValueError("built_plugin_launcher_required")
    version = json.loads((plugin / ".codex-plugin/plugin.json").read_text())["version"]
    with tempfile.TemporaryDirectory(prefix="memory-vault-package-synthetic-") as temporary:
        root = Path(temporary).resolve()
        config, vault = root / "client.json", root / "vault.sqlite3"
        config.write_text(json.dumps({"schema_version": "memory-vault-client-config/v1",
                                     "vault_path": str(vault), "capture_visible_turns": True}) + "\n")
        config.chmod(0o600)

        def call(*arguments: str, body: dict | None = None) -> dict:
            # -I ignores PYTHONPATH and user-site code. The verified launcher
            # chooses only its own hash-checked runtime directory.
            process = subprocess.run([python, "-I", "-B", str(launcher), "--config", str(config), *arguments],
                input=b"" if body is None else json.dumps(body, ensure_ascii=False).encode() + b"\n",
                cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            if process.returncode != 0:
                raise ValueError("packaged_command_failed:" + arguments[0])
            value = json.loads(process.stdout)
            if value.get("ok") is False:
                raise ValueError("packaged_request_failed:" + value["error"]["code"])
            return value

        discovery = call("agent", "request", body={"op": "discover"})
        if vault.exists() or discovery["result"]["network_accessed"]:
            raise ValueError("discovery_created_state_or_used_network")
        sample = {"op": "remember", "request_id": "req_package_synthetic_01", "kind": "fact",
                  "text": "Synthetic package evidence: independent memory persists across runtimes."}
        saved = call("agent", "request", body=sample)
        if call("agent", "request", body=sample) != saved:
            raise ValueError("packaged_retry_changed_result")
        memory_id = saved["result"]["memory_id"]
        recalled = call("agent", "request", body={"op": "recall", "memory_id": memory_id})
        if recalled["result"]["hits"][0]["text"] != sample["text"]:
            raise ValueError("packaged_recall_changed_text")

        event = {"session_id": "synthetic-package-session", "turn_id": "synthetic-package-turn"}
        call("hook", "user-prompt-submit", body={**event, "hook_event_name": "UserPromptSubmit",
                                                   "prompt": "Synthetic packaged hook user message."})
        response = call("hook", "stop", body={**event, "hook_event_name": "Stop",
                                               "last_assistant_message": "Synthetic packaged hook final reply."})
        if "saved_local" not in response.get("systemMessage", ""):
            raise ValueError("packaged_hook_not_saved")
        before = records(vault)
        if len(before) != 3:
            raise ValueError("packaged_hook_record_count")
        call("hook", "stop", body={**event, "hook_event_name": "Stop",
                                   "last_assistant_message": "Synthetic packaged hook final reply."})
        if records(vault) != before:
            raise ValueError("packaged_hook_retry_duplicated_history")

        backup, restored = root / "backup", root / "restored"
        call("manage", "backup-client", "--output", str(backup), "--include", "hooks", "--quiesced")
        call("manage", "restore-client", "--backup", str(backup), "--output", str(restored), "--accept-unsigned")
        restored_config = json.loads((restored / "client.json").read_text())
        after = records(Path(restored_config["vault_path"]))
        if before != after or records(vault) != before:
            raise ValueError("packaged_restore_changed_canonical_history")
        if restored_config.get("capture_visible_turns") or restored_config.get("sync_config_path"):
            raise ValueError("packaged_restore_activated_permissions")
        manifest = json.loads((plugin / "runtime/MANIFEST.json").read_text())
        return {"version": version, "launcher_sha256": hashlib.sha256(launcher.read_bytes()).hexdigest(),
                "runtime_modules": len(manifest["modules"]), "canonical_records_preserved": len(before),
                "local_save_recall": True, "exact_retries": True, "hook_capture": True,
                "backup_restore_same_bytes": True, "restored_capture_disabled": True,
                "private_data_used": False, "network_used": False, "host_installed": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plugin-root", required=True, type=Path)
    parser.add_argument("--python", default="python3")
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.plugin_root.absolute(), args.python), sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        # Inputs are synthetic, but still avoid leaking captured output/paths.
        print(json.dumps({"ok": False, "code": str(exc) if isinstance(exc, ValueError) else "package_verification_failed"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
