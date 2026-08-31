"""Explicit encrypted endpoint snapshots; restored transport is inert evidence.

Canonical memory uses the existing Vault backup/restore implementation. Network
tables travel as bounded data and are rebuilt from local SQL literals. No
service, hook, capture, delivery, trust enrollment or model call starts here.
"""
from __future__ import annotations

from contextlib import ExitStack, closing, contextmanager
import argparse
import hashlib
import os
from pathlib import Path
import re
import secrets
import sqlite3
import tempfile
import time
from typing import Any, Mapping, Sequence

from memory_vault import MemoryError, canonical_bytes, strict_json_loads
import memory_vault_backup as vault_backup
import memory_vault_storage as storage
from memory_vault_network import MAX_QUEUE_BYTES, MAX_QUARANTINE_BYTES, NetworkClient, origin
from memory_vault_network_admin import backup_keys, restore_keys
from memory_vault_network_control import _aesgcm, generate_recovery_secret, verify_request, verify_roster
from memory_vault_network_crypto import PublicKeyTrust, b64url, unb64url, document_sha256, object_fields, opaque, verify_envelope

PACKAGE_SCHEMA = "memory-vault-endpoint-backup/v1"
SECRET_SCHEMA = "memory-vault-endpoint-backup-secret/v1"
TRANSPORT_SCHEMA = "memory-vault-endpoint-transport/v1"
RESTORED_SCHEMA = "memory-vault-network-restored-endpoint/v1"
CHUNK_BYTES = 1024 * 1024
MAX_CHUNKS = 4096
MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
MAX_TRANSPORT_BYTES = 1536 * 1024 * 1024
MAX_ROW_BYTES = 32 * 1024 * 1024
MAX_METADATA_BYTES = 2 * 1024 * 1024
FILES = ("memory/manifest.json", "memory/memory.sqlite3", "transport.ndjson", "keys-package.json", "keys-secret.json")
SQL = {
    "state": "CREATE TABLE state(key TEXT PRIMARY KEY,value TEXT NOT NULL)",
    "outbox": "CREATE TABLE outbox(request_id TEXT PRIMARY KEY,message_id TEXT NOT NULL UNIQUE,input_sha TEXT NOT NULL,body BLOB NOT NULL,envelope BLOB,roster BLOB,receipts TEXT NOT NULL DEFAULT '{}',recipients BLOB)",
    "inbox": "CREATE TABLE inbox(message_id TEXT PRIMARY KEY,digest TEXT NOT NULL,sender TEXT NOT NULL,body BLOB NOT NULL,result TEXT NOT NULL)",
    "acknowledgements": "CREATE TABLE acknowledgements(message_id TEXT NOT NULL,recipient TEXT NOT NULL,receipt BLOB NOT NULL,PRIMARY KEY(message_id,recipient))",
    "quarantine": "CREATE TABLE quarantine(message_id TEXT PRIMARY KEY,digest TEXT NOT NULL UNIQUE,sender TEXT NOT NULL,envelope BLOB NOT NULL,code TEXT NOT NULL)",
}
COLUMNS = {
    "state": ("key", "value"),
    "outbox": ("request_id", "message_id", "input_sha", "body", "envelope", "roster", "receipts", "recipients"),
    "inbox": ("message_id", "digest", "sender", "body", "result"),
    "acknowledgements": ("message_id", "recipient", "receipt"),
    "quarantine": ("message_id", "digest", "sender", "envelope", "code"),
}
BLOBS = {"outbox": {"body", "envelope", "roster", "recipients"}, "inbox": {"body"},
         "acknowledgements": {"receipt"}, "quarantine": {"envelope"}, "state": set()}
NULLABLE = {"outbox": {"envelope", "roster", "recipients"}}
ROW_LIMITS = {"state": 16384, "outbox": 1024, "inbox": 4096, "acknowledgements": 16384, "quarantine": 128}


def _require(condition: Any, code: str = "endpoint_backup_invalid") -> None:
    if not condition:
        raise MemoryError(code)


def _path(path: Path) -> Path:
    return vault_backup.absolute(Path(path))


def _check(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise MemoryError("endpoint_backup_time_budget", retryable=True)


def _timeout(deadline: float) -> int:
    _check(deadline)
    return max(1, min(300, int(deadline - time.monotonic()) + 1))


def _read(path: Path, maximum: int) -> bytes:
    fd = storage.open_file(path, os.O_RDONLY, private=True)
    with os.fdopen(fd, "rb") as source:
        before = os.fstat(source.fileno())
        size = before.st_size
        _require(size <= maximum, "endpoint_backup_size_limit")
        value = source.read(maximum + 1)
        _require(len(value) == size and len(value) <= maximum
                 and vault_backup._fingerprint(before) == vault_backup._fingerprint(os.fstat(source.fileno())), "endpoint_backup_source_changed")
    return value


@contextmanager
def _new_file(path: Path):
    fd = storage.open_file(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, private=True)
    with os.fdopen(fd, "wb") as output:
        yield output
        output.flush()
        os.fsync(output.fileno())


def _new_json(path: Path, value: Any) -> None:
    storage.atomic_write(path, canonical_bytes(value) + b"\n", replace=False)


def _new_directory(path: Path) -> None:
    _require(not os.path.lexists(path), "endpoint_backup_new_path_required")
    path.mkdir(mode=0o700)
    storage.check_private_directory(path)


def _overlap(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def _header_context(header: Mapping[str, Any]) -> bytes:
    return canonical_bytes({key: header[key] for key in ("schema_version", "network_id", "package_id", "enc", "chunk_bytes", "total_chunks", "nonce_prefix")})


def _chunk_aad(header: Mapping[str, Any], name: str, index: int) -> bytes:
    return canonical_bytes({"context": b64url(_header_context(header)), "file": name, "chunk": index})


def _file_entries(stage: Path, deadline: float) -> list[dict[str, Any]]:
    result, total, chunks = [], 0, 0
    for name in FILES:
        _check(deadline)
        digest, size = hashlib.sha256(), 0
        fd = storage.open_file(stage / name, os.O_RDONLY, private=True)
        with os.fdopen(fd, "rb") as source:
            while value := source.read(CHUNK_BYTES):
                _check(deadline)
                size += len(value)
                _require(size <= (MAX_TRANSPORT_BYTES if name == "transport.ndjson" else vault_backup.MAX_DATABASE_BYTES
                                  if name == "memory/memory.sqlite3" else MAX_METADATA_BYTES), "endpoint_backup_size_limit")
                digest.update(value)
        total += size
        count = (size + CHUNK_BYTES - 1) // CHUNK_BYTES
        _require(size > 0 and total <= MAX_TOTAL_BYTES and chunks + count <= MAX_CHUNKS, "endpoint_backup_size_limit")
        result.append({"name": name, "bytes": size, "sha256": digest.hexdigest(), "first_chunk": chunks, "chunks": count})
        chunks += count
    return result


def _seal(stage: Path, destination: Path, secret_path: Path, network_id: str, deadline: float) -> dict[str, Any]:
    entries = _file_entries(stage, deadline)
    secret, prefix = generate_recovery_secret(), secrets.token_bytes(4)
    cipher = _aesgcm()(unb64url(secret, maximum=32, size=32))
    header = {"schema_version": PACKAGE_SCHEMA, "network_id": network_id, "package_id": secrets.token_hex(16),
              "enc": "A256GCM", "chunk_bytes": CHUNK_BYTES, "total_chunks": sum(item["chunks"] for item in entries),
              "nonce_prefix": b64url(prefix)}
    _new_directory(destination)
    for entry in entries:
        fd = storage.open_file(stage / entry["name"], os.O_RDONLY, private=True)
        digest, size = hashlib.sha256(), 0
        with os.fdopen(fd, "rb") as source:
            for index in range(entry["first_chunk"], entry["first_chunk"] + entry["chunks"]):
                _check(deadline)
                value = source.read(CHUNK_BYTES)
                _require(bool(value), "endpoint_backup_source_changed")
                digest.update(value)
                size += len(value)
                encrypted = cipher.encrypt(prefix + index.to_bytes(8, "big"), value, _chunk_aad(header, entry["name"], index))
                storage.atomic_write(destination / f"{index:06d}.bin", encrypted, replace=False)
            _require(not source.read(1) and size == entry["bytes"] and digest.hexdigest() == entry["sha256"], "endpoint_backup_source_changed")
    manifest = {"files": entries, "activation_disabled": True, "capture_disabled": True,
                "consistency": "sqlite_write_locks_and_config_recheck", "all_host_files_globally_quiesced": False}
    encrypted_manifest = cipher.encrypt(prefix + (2**64 - 1).to_bytes(8, "big"), canonical_bytes(manifest), _header_context(header))
    _check(deadline)
    _new_json(secret_path, {"schema_version": SECRET_SCHEMA, "network_id": network_id,
                            "package_id": header["package_id"], "secret": secret})
    # Publishing the final authenticated manifest commits the package. A
    # failed operation can leave ciphertext parts, never a silently valid set.
    _new_json(destination / "manifest.json", {**header, "manifest": b64url(encrypted_manifest)})
    return {"files": len(entries), "chunks": header["total_chunks"], "plaintext_bytes": sum(item["bytes"] for item in entries)}


def _unseal(package: Path, secret_path: Path, stage: Path, network_id: str, deadline: float) -> dict[str, Any]:
    from cryptography.exceptions import InvalidTag
    header = object_fields(strict_json_loads(_read(package / "manifest.json", 65536)),
        {"schema_version", "network_id", "package_id", "enc", "chunk_bytes", "total_chunks", "nonce_prefix", "manifest"})
    _require(header["schema_version"] == PACKAGE_SCHEMA and header["network_id"] == network_id and header["enc"] == "A256GCM"
             and header["chunk_bytes"] == CHUNK_BYTES and type(header["total_chunks"]) is int
             and 1 <= header["total_chunks"] <= MAX_CHUNKS and isinstance(header["package_id"], str)
             and re.fullmatch(r"[0-9a-f]{32}", header["package_id"]) is not None)
    secret = object_fields(strict_json_loads(_read(secret_path, 4096)), {"schema_version", "network_id", "package_id", "secret"})
    _require(secret["schema_version"] == SECRET_SCHEMA and secret["network_id"] == network_id
             and secret["package_id"] == header["package_id"], "endpoint_backup_secret_mismatch")
    cipher = _aesgcm()(unb64url(secret["secret"], maximum=32, size=32))
    prefix = unb64url(header["nonce_prefix"], maximum=4, size=4)
    try:
        decoded = cipher.decrypt(prefix + (2**64 - 1).to_bytes(8, "big"), unb64url(header["manifest"], maximum=32768), _header_context(header))
        manifest = object_fields(strict_json_loads(decoded), {"files", "activation_disabled", "capture_disabled", "consistency", "all_host_files_globally_quiesced"})
        _require(manifest["activation_disabled"] is True and manifest["capture_disabled"] is True
                 and manifest["consistency"] == "sqlite_write_locks_and_config_recheck" and manifest["all_host_files_globally_quiesced"] is False
                 and isinstance(manifest["files"], list) and len(manifest["files"]) == len(FILES))
        position, total = 0, 0
        for name, entry in zip(FILES, manifest["files"]):
            object_fields(entry, {"name", "bytes", "sha256", "first_chunk", "chunks"})
            maximum = MAX_TRANSPORT_BYTES if name == "transport.ndjson" else vault_backup.MAX_DATABASE_BYTES if name == "memory/memory.sqlite3" else MAX_METADATA_BYTES
            _require(entry["name"] == name and type(entry["bytes"]) is int and 1 <= entry["bytes"] <= maximum
                     and type(entry["first_chunk"]) is int and entry["first_chunk"] == position
                     and type(entry["chunks"]) is int and entry["chunks"] == (entry["bytes"] + CHUNK_BYTES - 1) // CHUNK_BYTES
                     and isinstance(entry["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is not None)
            total += entry["bytes"]
            position += entry["chunks"]
            _require(total <= MAX_TOTAL_BYTES and position <= MAX_CHUNKS, "endpoint_backup_size_limit")
        _require(position == header["total_chunks"])
        expected = {"manifest.json", *(f"{index:06d}.bin" for index in range(position))}
        actual = set()
        for path in package.iterdir():
            _check(deadline)
            _require(path.name in expected and len(actual) <= MAX_CHUNKS, "endpoint_backup_file_set_mismatch")
            actual.add(path.name)
        _require(actual == expected, "endpoint_backup_file_set_mismatch")
        storage.private_directory(stage / "memory")
        for entry in manifest["files"]:
            digest, size = hashlib.sha256(), 0
            with _new_file(stage / entry["name"]) as output:
                for index in range(entry["first_chunk"], entry["first_chunk"] + entry["chunks"]):
                    _check(deadline)
                    encrypted = _read(package / f"{index:06d}.bin", CHUNK_BYTES + 16)
                    value = cipher.decrypt(prefix + index.to_bytes(8, "big"), encrypted, _chunk_aad(header, entry["name"], index))
                    expected_size = min(CHUNK_BYTES, entry["bytes"] - size)
                    _require(len(value) == expected_size, "endpoint_backup_chunk_mismatch")
                    output.write(value)
                    digest.update(value)
                    size += len(value)
            _require(size == entry["bytes"] and digest.hexdigest() == entry["sha256"], "endpoint_backup_checksum_mismatch")
    except InvalidTag:
        raise MemoryError("endpoint_backup_decryption_failed") from None
    return manifest


def _schema(connection: sqlite3.Connection) -> None:
    seen = set()
    for kind, name, table, sql in connection.execute("SELECT type,name,tbl_name,sql FROM sqlite_master"):
        if kind == "index" and sql is None and table in SQL and re.fullmatch("sqlite_autoindex_" + table + r"_[0-9]+", name):
            continue
        _require(kind == "table" and name in SQL and table == name and isinstance(sql, str)
                 and vault_backup._sql(sql) == vault_backup._sql(SQL[name]), "endpoint_backup_transport_schema")
        seen.add(name)
    _require(seen == set(SQL), "endpoint_backup_transport_schema")


@contextmanager
def _writer_lock(path: Path, deadline: float):
    info = vault_backup.regular(path)
    for suffix in ("-wal", "-shm", "-journal"):
        sibling = Path(str(path) + suffix)
        if os.path.lexists(sibling):
            vault_backup.regular(sibling)
    with closing(sqlite3.connect(path.as_uri() + "?mode=rw", uri=True, timeout=0.5, isolation_level=None)) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        try:
            # SQLite enforces this reservation across processes, independently
            # of cooperative application lock files. No source rows are edited.
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            current = vault_backup.regular(path)
            _require((info.st_dev, info.st_ino) == (current.st_dev, current.st_ino), "endpoint_backup_source_changed")
        except sqlite3.OperationalError:
            raise MemoryError("endpoint_backup_database_busy", retryable=True) from None
        finally:
            if connection.in_transaction:
                connection.rollback()


def _export_transport(client: NetworkClient, connection: sqlite3.Connection, output: Path, deadline: float) -> dict[str, int]:
    _schema(connection)
    counts = {table: connection.execute("SELECT COUNT(*) FROM " + table).fetchone()[0] for table in SQL}
    _require(all(0 <= count <= ROW_LIMITS[table] for table, count in counts.items()), "endpoint_backup_row_limit")
    total = 0
    with _new_file(output) as stream:
        header = {"schema_version": TRANSPORT_SCHEMA, "binding": client._binding, "counts": counts}
        line = canonical_bytes(header) + b"\n"
        stream.write(line)
        total += len(line)
        for table, columns in COLUMNS.items():
            for row in connection.execute("SELECT rowid," + ",".join(columns) + " FROM " + table + " ORDER BY rowid"):
                _check(deadline)
                values = []
                for column, value in zip(columns, row[1:]):
                    if column in BLOBS[table] and value is not None:
                        _require(isinstance(value, bytes) and len(value) <= 8 * CHUNK_BYTES, "endpoint_backup_invalid_transport_row")
                        values.append({"base64": b64url(value)})
                    else:
                        _require((value is None and column in NULLABLE.get(table, set()))
                                 or (isinstance(value, str) and len(value.encode()) <= MAX_METADATA_BYTES), "endpoint_backup_invalid_transport_row")
                        values.append(value)
                line = canonical_bytes({"table": table, "rowid": row[0], "values": values}) + b"\n"
                total += len(line)
                _require(len(line) <= MAX_ROW_BYTES and total <= MAX_TRANSPORT_BYTES, "endpoint_backup_size_limit")
                stream.write(line)
    return counts


def _transport_bounds(connection: sqlite3.Connection, deadline: float) -> None:
    """Reject oversized source cells before loading any row into Python."""
    for table, columns in COLUMNS.items():
        _check(deadline)
        count = connection.execute("SELECT COUNT(*) FROM " + table).fetchone()[0]
        _require(count <= ROW_LIMITS[table], "endpoint_backup_row_limit")
        for column in columns:
            maximum = 8 * CHUNK_BYTES if column in BLOBS[table] else MAX_METADATA_BYTES
            row = connection.execute("SELECT 1 FROM " + table + " WHERE length(CAST(" + column + " AS BLOB))>? LIMIT 1", (maximum,)).fetchone()
            _require(row is None, "endpoint_backup_size_limit")
    for table, expression, maximum in (("outbox", "length(body)+COALESCE(length(envelope),0)", MAX_QUEUE_BYTES),
                                       ("inbox", "length(body)", MAX_QUEUE_BYTES),
                                       ("quarantine", "length(envelope)", MAX_QUARANTINE_BYTES)):
        size = connection.execute("SELECT COALESCE(SUM(" + expression + "),0) FROM " + table).fetchone()[0]
        _require(size <= maximum, "endpoint_backup_size_limit")


def _validate_transport(connection: sqlite3.Connection, client: NetworkClient, memory: sqlite3.Connection, deadline: float) -> None:
    from memory_vault_nodes import verify_directory
    from memory_vault_network_crypto import public_signing_key
    own = PublicKeyTrust([client.identity.public_descriptor()])
    for row in connection.execute("SELECT * FROM outbox"):
        _check(deadline)
        opaque(row["request_id"])
        expected_id = "msg_" + hashlib.sha256(canonical_bytes([client.network_id, client.identity.key_id, row["request_id"]])).hexdigest()
        _require(row["message_id"] == expected_id and re.fullmatch(r"[0-9a-f]{64}", row["input_sha"]) is not None, "endpoint_backup_invalid_outbox")
        content = object_fields(strict_json_loads(row["body"]), {"schema_version", "text", "share"})
        _require(content["schema_version"] == "memory-vault-network-content/v1" and isinstance(content["text"], str)
                 and len(content["text"].encode()) <= 16384, "endpoint_backup_invalid_outbox")
        if content["share"] is not None:
            unb64url(content["share"], maximum=2 * CHUNK_BYTES)
        recipients = strict_json_loads(row["recipients"]) if row["recipients"] is not None else None
        if recipients is not None:
            _require(isinstance(recipients, list) and 1 <= len(recipients) <= 16
                     and all(isinstance(key, str) for key in recipients) and len(set(recipients)) == len(recipients), "endpoint_backup_invalid_outbox")
            for key in recipients:
                opaque(key)
        receipts = strict_json_loads(row["receipts"])
        _require(isinstance(receipts, dict) and len(receipts) <= 2, "endpoint_backup_invalid_outbox")
        if row["envelope"] is None:
            _require(row["roster"] is None and not receipts, "endpoint_backup_invalid_outbox")
            continue
        _require(row["roster"] is not None, "endpoint_backup_invalid_outbox")
        envelope, roster = strict_json_loads(row["envelope"]), strict_json_loads(row["roster"])
        payload = verify_envelope(envelope, own, network_id=client.network_id)
        verify_roster(roster, client.issuers, network_id=client.network_id, allow_expired=True)
        _require(payload["message_id"] == row["message_id"] and payload["sender_key_id"] == client.identity.key_id
                 and payload["roster_sha256"] == document_sha256(roster) and payload["roster_version"] == roster["payload"]["version"]
                 and (recipients is None or set(recipients) == set(payload["recipient_key_ids"])), "endpoint_backup_invalid_outbox")
        for relay, receipt in receipts.items():
            origin(relay)
            _require(isinstance(receipt, dict) and receipt.get("state") == "stored" and receipt.get("message_id") == row["message_id"]
                     and receipt.get("envelope_sha256") == document_sha256(envelope), "endpoint_backup_invalid_outbox")
    for row in connection.execute("SELECT * FROM inbox"):
        _check(deadline)
        opaque(row["message_id"])
        opaque(row["sender"])
        _require(re.fullmatch(r"[0-9a-f]{64}", row["digest"]) is not None, "endpoint_backup_invalid_inbox")
        content = object_fields(strict_json_loads(row["body"]), {"schema_version", "text", "share"})
        result = strict_json_loads(row["result"])
        _require(content["schema_version"] == "memory-vault-network-content/v1" and isinstance(content["text"], str)
                 and len(content["text"].encode()) <= 16384 and isinstance(result, dict)
                 and result.get("state") == "validated_saved" and result.get("understood") is False
                 and result.get("message_id") == row["message_id"] and result.get("sender_key_id") == row["sender"], "endpoint_backup_invalid_inbox")
        if content["share"] is not None:
            unb64url(content["share"], maximum=2 * CHUNK_BYTES)
        if result.get("text_memory_id") is not None:
            match = memory.execute("SELECT text FROM memories WHERE memory_id=?", (result["text_memory_id"],)).fetchone()
            _require(match is not None and match[0] == content["text"], "endpoint_backup_memory_reference_missing")
    for row in connection.execute("SELECT * FROM acknowledgements"):
        _check(deadline)
        outbound = connection.execute("SELECT envelope,roster FROM outbox WHERE message_id=?", (row["message_id"],)).fetchone()
        _require(outbound is not None and outbound["envelope"] is not None, "endpoint_backup_invalid_receipt")
        roster, envelope, receipt = strict_json_loads(outbound["roster"]), strict_json_loads(outbound["envelope"]), strict_json_loads(row["receipt"])
        peers = PublicKeyTrust([member["signing_key"] for member in roster["payload"]["members"]])
        verified = verify_request(receipt, peers, network_id=client.network_id, action="ack", now=receipt["payload"]["issued_at"])
        _require(receipt["proof"]["key_id"] == row["recipient"] and row["recipient"] in envelope["recipient_key_ids"]
                 and verified["body"] == {"message_id": row["message_id"], "envelope_sha256": document_sha256(envelope), "state": "validated_saved"},
                 "endpoint_backup_invalid_receipt")
    for row in connection.execute("SELECT * FROM quarantine"):
        _check(deadline)
        envelope = strict_json_loads(row["envelope"])
        _require(isinstance(envelope, dict) and envelope.get("message_id") == row["message_id"] and envelope.get("sender_key_id") == row["sender"]
                 and document_sha256(envelope) == row["digest"] and row["code"] in
                 {"network_invalid_content_json", "network_invalid_content", "network_invalid_content_share_encoding"}, "endpoint_backup_invalid_quarantine")
    for key, value in connection.execute("SELECT key,value FROM state"):
        _check(deadline)
        decoded = strict_json_loads(value)
        if key == "configuration_binding":
            _require(decoded == client._binding, "endpoint_backup_binding_mismatch")
        elif key == "roster":
            verify_roster(decoded, client.issuers, network_id=client.network_id, allow_expired=True)
        elif key == "pump_cursor":
            _require(type(decoded) is int and 0 <= decoded <= 2**53 - 1)
        elif key == "node_directory":
            verify_directory(decoded, client.issuers, network_id=client.network_id, allow_expired=True)
        elif key == "node_status_issued_at":
            _require(type(decoded) is int and 0 <= decoded <= 2**53 - 1)
        elif key.startswith("node:"):
            object_fields(decoded, {"signing_key", "base_url", "storage_epoch"})
            public_signing_key(decoded["signing_key"])
            opaque(decoded["storage_epoch"])
            _require(origin(decoded["base_url"]) == origin(key[len("node:"):]), "endpoint_backup_invalid_node_binding")
            # This is a historical incarnation cache. It is not current node
            # authorization; a fresh signed directory/challenge is mandatory.
        elif key.startswith("cursor:"):
            origin(key[len("cursor:"):])
            object_fields(decoded, {"cursor", "receipt_cursor"})
            _require(type(decoded["cursor"]) is int and 0 <= decoded["cursor"] <= 4096
                     and type(decoded["receipt_cursor"]) is int and 0 <= decoded["receipt_cursor"] <= 4096 * 32)
        elif key.startswith("ack:") or key.startswith("join:"):
            action = key.split(":", 1)[0]
            request = verify_request(decoded, own, network_id=client.network_id, action=action, now=decoded["payload"]["issued_at"])
            if action == "ack":
                body = request["body"]
                received = connection.execute("SELECT digest FROM inbox WHERE message_id=?", (body.get("message_id"),)).fetchone()
                _require(received is not None and body == {"message_id": body["message_id"], "envelope_sha256": received[0], "state": "validated_saved"}
                         and key.endswith(":" + body["message_id"]), "endpoint_backup_invalid_receipt")
                origin(key[len("ack:"):-len(body["message_id"]) - 1])
        else:
            raise MemoryError("endpoint_backup_unknown_state")


def _restore_transport(source: Path, client: NetworkClient, deadline: float) -> dict[str, int]:
    fd = storage.open_file(source, os.O_RDONLY, private=True)
    with os.fdopen(fd, "rb") as stream, client.db() as connection, closing(client.client_config.vault()._connect()) as memory:
        connection.execute("BEGIN IMMEDIATE")
        _require(all(connection.execute("SELECT COUNT(*) FROM " + table).fetchone()[0] == (1 if table == "state" else 0) for table in SQL),
                 "endpoint_backup_restore_requires_empty_state")
        connection.execute("DELETE FROM state")
        connection.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        header = object_fields(strict_json_loads(stream.readline(MAX_METADATA_BYTES + 1)), {"schema_version", "binding", "counts"})
        _require(header["schema_version"] == TRANSPORT_SCHEMA and isinstance(header["binding"], dict)
                 and set(header["binding"]) == set(client._binding) and isinstance(header["counts"], dict)
                 and set(header["counts"]) == set(SQL), "endpoint_backup_transport_schema")
        _require(all(header["binding"][key] == value for key, value in client._binding.items() if key != "client_config_path"), "endpoint_backup_binding_mismatch")
        _require(all(type(count) is int and 0 <= count <= ROW_LIMITS[table] for table, count in header["counts"].items()), "endpoint_backup_row_limit")
        counts, total, binding_seen = dict.fromkeys(SQL, 0), 0, False
        while line := stream.readline(MAX_ROW_BYTES + 1):
            _check(deadline)
            total += len(line)
            _require(len(line) <= MAX_ROW_BYTES and total <= MAX_TRANSPORT_BYTES, "endpoint_backup_size_limit")
            row = object_fields(strict_json_loads(line), {"table", "rowid", "values"})
            table = row["table"]
            _require(isinstance(table, str) and table in COLUMNS and type(row["rowid"]) is int and 1 <= row["rowid"] <= 2**53 - 1
                     and isinstance(row["values"], list) and len(row["values"]) == len(COLUMNS[table]), "endpoint_backup_invalid_transport_row")
            counts[table] += 1
            _require(counts[table] <= ROW_LIMITS[table], "endpoint_backup_row_limit")
            values = []
            for column, value in zip(COLUMNS[table], row["values"]):
                if value is None:
                    _require(column in NULLABLE.get(table, set()), "endpoint_backup_invalid_transport_row")
                elif column in BLOBS[table]:
                    value = unb64url(object_fields(value, {"base64"})["base64"], maximum=8 * CHUNK_BYTES)
                else:
                    _require(isinstance(value, str) and len(value.encode()) <= MAX_METADATA_BYTES, "endpoint_backup_invalid_transport_row")
                values.append(value)
            if table == "state" and values[0] == "configuration_binding":
                _require(strict_json_loads(values[1]) == header["binding"], "endpoint_backup_binding_mismatch")
                values[1] = canonical_bytes(client._binding).decode()
                binding_seen = True
            connection.execute("INSERT INTO " + table + "(rowid," + ",".join(COLUMNS[table]) + ") VALUES(" + ",".join("?" for _ in range(len(values) + 1)) + ")",
                               [row["rowid"], *values])
        _require(counts == header["counts"] and binding_seen, "endpoint_backup_transport_count_mismatch")
        _transport_bounds(connection, deadline)
        _validate_transport(connection, client, memory, deadline)
        marker = strict_json_loads(_read(client.config_path.parent / "recovery-state.json", MAX_METADATA_BYTES))
        current = connection.execute("SELECT value FROM state WHERE key='roster'").fetchone()
        _require((strict_json_loads(current[0]) if current else None) == marker["last_verified_roster"], "endpoint_backup_checkpoint_mismatch")
        nodes = connection.execute("SELECT value FROM state WHERE key='node_directory'").fetchone()
        _require((strict_json_loads(nodes[0]) if nodes else None) == marker.get("last_verified_node_directory"), "endpoint_backup_checkpoint_mismatch")
    return counts


def backup_endpoint(*, network_config: Path, output: Path, secret_file: Path,
                    timeout: int = 60, client_config: Path | None = None) -> Mapping[str, Any]:
    """Freeze committed endpoint data, then encrypt outside the source locks."""
    deadline = vault_backup._deadline(timeout)
    config_path, destination, secret_path = _path(network_config), _path(output), _path(secret_file)
    _require(not _overlap(destination, secret_path), "endpoint_backup_secret_must_be_separate")
    _require(not os.path.lexists(destination) and not os.path.lexists(secret_path), "endpoint_backup_new_path_required")
    vault_backup._private_parent(destination.parent)
    vault_backup._private_parent(secret_path.parent)
    with NetworkClient(config_path) as client:
        if client_config is not None:
            _require(client.client_config.path == _path(client_config), "network_client_config_mismatch")
        config = strict_json_loads(_read(config_path, 65536))
        sources = {config_path: 65536, client.client_config.path: 65536,
                   client.client_config.identity_path: 4096, client.client_config.trust_path: 1024 * 1024,
                   _path(Path(config["encryption_key_path"])): 16384}
        source_db = _path(client.directory / "network.sqlite3")
        memory_db = _path(client.client_config.vault_path)
        _require(not _overlap(source_db, memory_db), "endpoint_backup_separate_databases_required")
        _require(all(not _overlap(target, source) for target in (destination, secret_path)
                     for source in (*sources, source_db, memory_db)), "endpoint_backup_source_path_overlap")
        before = {path: _read(path, bound) for path, bound in sources.items()}
        with tempfile.TemporaryDirectory(prefix="endpoint-snapshot-", dir=destination.parent) as temporary:
            stage = Path(temporary)
            # Both reservations coexist before either snapshot is taken. A
            # concurrent writer can fail/retry; source transactions are never
            # forcefully stopped. Config files are checked separately below.
            with ExitStack() as locks:
                transport = locks.enter_context(_writer_lock(source_db, deadline))
                memory = locks.enter_context(_writer_lock(memory_db, deadline))
                _schema(transport)
                _transport_bounds(transport, deadline)
                _validate_transport(transport, client, memory, deadline)
                vault_result = vault_backup.backup_database(memory_db, stage / "memory", timeout=_timeout(deadline))
                counts = _export_transport(client, transport, stage / "transport.ndjson", deadline)
                keys = backup_keys(network_config=config_path, output=stage / "keys-package.json", secret_file=stage / "keys-secret.json")
                _require(all(_read(path, bound) == before[path] for path, bound in sources.items()), "endpoint_backup_source_changed")
                with NetworkClient(config_path) as checked:
                    _require(checked._binding == client._binding, "endpoint_backup_source_changed")
            sealed = _seal(stage, destination, secret_path, client.network_id, deadline)
        return {"state": "endpoint_backup_created", "package": str(destination), "secret_file": str(secret_path),
                "network_id": client.network_id, "member_key_id": client.identity.key_id, "transport_rows": counts,
                "memory_records": vault_result["records"], **sealed, "keep_secret_separately": True,
                "offline_outbox_included": True, "frozen_envelopes_preserved": True,
                "issuer_key_shared_with_endpoint": keys["issuer_key_shared_with_endpoint"],
                "consistency": "sqlite_write_locks_and_config_recheck", "all_host_files_globally_quiesced": False,
                "network_accessed": False}


def restore_endpoint(*, package: Path, secret_file: Path, directory: Path,
                     confirm_network_id: str, issuer_public: Path, authority_url: str,
                     relays: Sequence[str], memory_trust: Path | None = None,
                     accept_unsigned: bool = False, timeout: int = 60) -> Mapping[str, Any]:
    """Restore the same identity and queues to a NEW, capture-off endpoint.

    Restored Vault admission is decided only by an independently selected
    trust registry, never the archived registry. Cache entries and receipts
    remain historical evidence. No network operation is performed here.
    """
    from memory_vault_trust import MAX_TRUST_STORE_BYTES, TrustStore
    deadline = vault_backup._deadline(timeout)
    network_id = opaque(confirm_network_id)
    root, secret_path, destination = _path(package), _path(secret_file), _path(directory)
    independent_issuer = _path(issuer_public)
    _require(not _overlap(root, secret_path), "endpoint_backup_secret_must_be_separate")
    _require(not os.path.lexists(destination), "endpoint_backup_new_path_required")
    _require(all(not _overlap(destination, source) for source in (root, secret_path, independent_issuer)), "endpoint_backup_source_path_overlap")
    _require(not _overlap(independent_issuer, root), "endpoint_backup_independent_issuer_required")
    selected_trust = None if memory_trust is None else _path(memory_trust)
    if selected_trust is not None:
        _require(not _overlap(selected_trust, root) and not _overlap(selected_trust, destination), "endpoint_backup_independent_trust_required")
    authority_url = origin(authority_url)
    _require(not isinstance(relays, (str, bytes)) and 1 <= len(relays) <= 2, "network_one_or_two_relays_required")
    destinations = [origin(value) for value in relays]
    _require(len(set(destinations)) == len(destinations), "network_duplicate_relay")
    _require(type(accept_unsigned) is bool, "invalid_unsigned_acceptance")
    storage.check_private_directory(root)
    vault_backup._private_parent(destination.parent)
    with tempfile.TemporaryDirectory(prefix="endpoint-recovery-", dir=destination.parent) as temporary:
        stage = Path(temporary)
        _unseal(root, secret_path, stage, network_id, deadline)
        # Snapshot the operator's current registry exactly once. The same
        # validated bytes decide restored admission and future runtime trust;
        # a later file replacement cannot silently create two trust policies.
        runtime_trust = None
        trust_snapshot = None
        if selected_trust is not None:
            trust_snapshot = stage / "current-memory-trust.json"
            runtime_trust = _read(selected_trust, MAX_TRUST_STORE_BYTES)
            with _new_file(trust_snapshot) as output:
                output.write(runtime_trust)
            TrustStore(trust_snapshot).status()
        _new_directory(destination)
        _new_directory(destination / "vault")
        vault_path = destination / "vault" / "memory.sqlite3"
        memory = vault_backup.restore_database(stage / "memory", vault_path, trust_store=trust_snapshot,
                                               accept_unsigned=accept_unsigned, timeout=_timeout(deadline))
        restored = restore_keys(package=stage / "keys-package.json", secret_file=stage / "keys-secret.json",
            directory=destination / "endpoint", vault=vault_path, confirm_network_id=network_id,
            issuer_public=independent_issuer, authority_url=authority_url, relays=destinations)
        with NetworkClient(Path(restored["network_config"])) as client:
            if runtime_trust is None:
                # The identity itself was explicitly restored, so local
                # self-authored writes remain possible. Historical remote
                # authors require fresh explicit enrollment by the operator.
                self_trust = stage / "self-memory-trust.json"
                TrustStore(self_trust).add(client.identity.public_descriptor())
                runtime_trust = _read(self_trust, MAX_TRUST_STORE_BYTES)
            storage.atomic_write(client.client_config.trust_path, runtime_trust, replace=True)
            counts = _restore_transport(stage / "transport.ndjson", client, deadline)
            _check(deadline)
            marker_path = client.config_path.parent / "recovery-state.json"
            marker = strict_json_loads(_read(marker_path, MAX_METADATA_BYTES))
            marker.update(schema_version=RESTORED_SCHEMA, old_delivery_cursors_restored=True,
                          offline_outbox_restored=True, vault_restored_by_this_command=True)
            storage.atomic_write(marker_path, canonical_bytes(marker) + b"\n", replace=True)
            return {"state": "endpoint_restored_inactive", "network_config": str(client.config_path),
                    "client_config": str(client.client_config.path), "vault": str(vault_path),
                    "network_id": network_id, "member_key_id": client.identity.key_id, "transport_rows": counts,
                    "memory": memory, "activation_disabled": True, "capture_visible_turns": False,
                    "automatic_sending_enabled": False, "requires_fresh_issuer_status": True,
                    "runtime_memory_trust": "operator_selected_snapshot" if selected_trust is not None else "restored_identity_only",
                    "offline_outbox_restored": True, "frozen_envelopes_preserved": True,
                    "cached_results_are_historical": True, "network_accessed": False}


def main(argv: Sequence[str] | None = None, *, client_config: Path | None = None) -> int:
    """Independent management CLI; it never starts an agent or a worker."""
    from memory_vault import failure, success, write_response
    from memory_vault_trust import TrustError
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    backup = commands.add_parser("backup", help="encrypt the canonical Vault, identity and complete endpoint queue")
    backup.add_argument("--network-config", required=True, type=Path)
    backup.add_argument("--output", required=True, type=Path, help="new encrypted package directory")
    backup.add_argument("--secret-file", required=True, type=Path, help="new recovery key file outside package")
    backup.add_argument("--timeout", type=int, default=60)
    restore = commands.add_parser("restore", help="restore an inactive endpoint only into a new directory")
    restore.add_argument("--package", required=True, type=Path)
    restore.add_argument("--secret-file", required=True, type=Path)
    restore.add_argument("--directory", required=True, type=Path)
    restore.add_argument("--confirm-network-id", required=True)
    restore.add_argument("--issuer-public", required=True, type=Path)
    restore.add_argument("--authority-url", required=True)
    restore.add_argument("--relay", required=True, action="append")
    restore.add_argument("--memory-trust", type=Path, help="independently chosen current Vault trust registry")
    restore.add_argument("--accept-unsigned", action="store_true")
    restore.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args(argv)
    try:
        if args.action == "backup":
            result = backup_endpoint(network_config=args.network_config, output=args.output, secret_file=args.secret_file,
                                     timeout=args.timeout, client_config=client_config)
        else:
            result = restore_endpoint(package=args.package, secret_file=args.secret_file, directory=args.directory,
                confirm_network_id=args.confirm_network_id, issuer_public=args.issuer_public,
                authority_url=args.authority_url, relays=args.relay, memory_trust=args.memory_trust,
                accept_unsigned=args.accept_unsigned, timeout=args.timeout)
        write_response(success(result))
        return 0
    except (MemoryError, TrustError) as exc:
        write_response(failure(exc.code, retryable=getattr(exc, "retryable", False)))
    except sqlite3.DatabaseError:
        write_response(failure("endpoint_backup_database_unavailable", retryable=True))
    except OSError:
        write_response(failure("endpoint_backup_storage_unavailable", retryable=True))
    except (KeyError, TypeError, ValueError, UnicodeError):
        write_response(failure("endpoint_backup_invalid"))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
