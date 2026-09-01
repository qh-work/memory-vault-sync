#!/usr/bin/env python3
"""Verify and run the isolated synthetic Memory Vault network trial."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tempfile
import venv


MANIFEST_SCHEMA = "memory-vault-network-test-package/v1"
TRUST_SCHEMA = "memory-vault-trial-service-trust/v1"
MAX_MANIFEST_BYTES = 256 * 1024
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_PACKAGE_BYTES = 32 * 1024 * 1024
MAX_FILES = 128


class TrialBootstrapError(Exception):
    """A bounded, user-safe bootstrap failure."""


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise TrialBootstrapError("duplicate_json_key")
        result[key] = value
    return result


def _json(path: Path, maximum: int) -> object:
    if path.is_symlink() or not path.is_file():
        raise TrialBootstrapError("package_file_missing_or_unsafe")
    data = path.read_bytes()
    if not data or len(data) > maximum:
        raise TrialBootstrapError("package_file_size_invalid")
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                TrialBootstrapError("non_json_constant")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TrialBootstrapError("invalid_json") from exc


def _safe_name(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 240:
        raise TrialBootstrapError("invalid_package_member")
    name = PurePosixPath(value)
    if (name.is_absolute() or "\\" in value or ":" in value or "\x00" in value
            or any(part in {"", ".", ".."} for part in name.parts)):
        raise TrialBootstrapError("invalid_package_member")
    return value


def _verify_package(root: Path) -> dict[str, object]:
    manifest_path = root / "TRIAL_MANIFEST.json"
    manifest = _json(manifest_path, MAX_MANIFEST_BYTES)
    required = {
        "schema_version", "version", "source_commit", "private_state_included",
        "synthetic_data_only", "service_configured", "checksums_are_publisher_signatures",
        "files",
    }
    if (not isinstance(manifest, dict) or set(manifest) != required
            or manifest.get("schema_version") != MANIFEST_SCHEMA
            or manifest.get("private_state_included") is not False
            or manifest.get("synthetic_data_only") is not True
            or manifest.get("checksums_are_publisher_signatures") is not False
            or not isinstance(manifest.get("service_configured"), bool)):
        raise TrialBootstrapError("invalid_trial_manifest")
    files = manifest.get("files")
    if not isinstance(files, dict) or not 1 <= len(files) <= MAX_FILES:
        raise TrialBootstrapError("invalid_trial_inventory")
    declared: dict[str, str] = {}
    for raw_name, raw_digest in files.items():
        name = _safe_name(raw_name)
        if (not isinstance(raw_digest, str) or len(raw_digest) != 64
                or any(character not in "0123456789abcdef" for character in raw_digest)):
            raise TrialBootstrapError("invalid_trial_inventory")
        declared[name] = raw_digest
    observed: set[str] = set()
    for candidate in root.rglob("*"):
        if candidate.is_symlink():
            raise TrialBootstrapError("symlink_in_trial_package")
        if candidate.is_dir():
            continue
        name = candidate.relative_to(root).as_posix()
        if name == "TRIAL_MANIFEST.json":
            continue
        if name not in declared:
            raise TrialBootstrapError("unexpected_trial_package_member")
        observed.add(name)
    if observed != set(declared):
        raise TrialBootstrapError("missing_trial_package_member")
    total = 0
    for name, expected in declared.items():
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise TrialBootstrapError("package_file_missing_or_unsafe")
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            raise TrialBootstrapError("trial_package_member_too_large")
        total += size
        if total > MAX_PACKAGE_BYTES:
            raise TrialBootstrapError("trial_package_too_large")
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise TrialBootstrapError("trial_package_hash_mismatch")
    return manifest


def _verify_service_trust(root: Path, manifest: dict[str, object]) -> Path:
    path = root / "service-trust.json"
    value = _json(path, 64 * 1024)
    if not isinstance(value, dict) or value.get("schema_version") != TRUST_SCHEMA:
        raise TrialBootstrapError("invalid_trial_service_trust")
    if value == {"schema_version": TRUST_SCHEMA, "state": "unconfigured"}:
        if manifest.get("service_configured") is not False:
            raise TrialBootstrapError("trial_service_state_mismatch")
        raise TrialBootstrapError("trial_service_not_configured")
    if set(value) != {"schema_version", "enrollment_url", "service"}:
        raise TrialBootstrapError("invalid_trial_service_trust")
    if manifest.get("service_configured") is not True:
        raise TrialBootstrapError("trial_service_state_mismatch")
    # The endpoint performs full URL, key, network and descriptor validation.
    # The bootstrap only distinguishes the exact active shape from the explicit
    # fail-closed template before it installs anything or opens the network.
    if not isinstance(value.get("enrollment_url"), str) or not isinstance(value.get("service"), dict):
        raise TrialBootstrapError("invalid_trial_service_trust")
    return path


def _clean_environment() -> dict[str, str]:
    environment = {
        key: value for key, value in os.environ.items()
        if not key.upper().startswith(("PIP_", "PYTHON"))
        and key not in {"VIRTUAL_ENV", "VIRTUAL_ENV_PROMPT"}
    }
    environment.update({
        "PIP_CONFIG_FILE": os.devnull,
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INPUT": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
    })
    return environment


def _venv_python(directory: Path) -> Path:
    if os.name == "nt":
        return directory / "Scripts" / "python.exe"
    return directory / "bin" / "python"


def _help() -> None:
    print("Usage: python3 run.py --service HTTPS_URL --run-code CODE [--keep-state]")
    print()
    print("Runs one isolated, wholly synthetic Memory Vault endpoint trial.")
    print("No Docker, plugin installation, existing Vault, or user memory is used.")
    print("The package creates a temporary private virtual environment and removes it afterward.")


def _run(arguments: list[str]) -> int:
    if any(item in {"-h", "--help"} for item in arguments):
        _help()
        return 0
    if any(item == "--service-trust" or item.startswith("--service-trust=") for item in arguments):
        raise TrialBootstrapError("service_trust_override_forbidden")
    if not ((3, 10) <= sys.version_info[:2] < (3, 15)):
        raise TrialBootstrapError("python_3_10_to_3_14_required")
    script = Path(__file__)
    if script.is_symlink():
        raise TrialBootstrapError("symlink_bootstrap_forbidden")
    root = script.resolve().parent
    manifest = _verify_package(root)
    trust = _verify_service_trust(root, manifest)
    endpoint = root / "runtime" / "memory_vault_trial.py"
    lock = root / "requirements-network-lock.txt"
    environment = _clean_environment()
    workspace = Path(tempfile.mkdtemp(prefix="memory-vault-trial-bootstrap-")).resolve()
    try:
        os.chmod(workspace, 0o700)
        environment_directory = workspace / "venv"
        venv.EnvBuilder(with_pip=True, clear=False, symlinks=False).create(environment_directory)
        python = _venv_python(environment_directory)
        install = subprocess.run(
            [str(python), "-I", "-m", "pip", "install", "--disable-pip-version-check",
             "--no-input", "--only-binary", ":all:", "--require-hashes", "-r", str(lock)],
            stdin=subprocess.DEVNULL,
            cwd=workspace,
            env=environment,
            timeout=600,
        )
        if install.returncode != 0:
            raise TrialBootstrapError("locked_dependency_install_failed")
        command = [str(python), "-I", "-B", str(endpoint),
                   "--service-trust", str(trust), *arguments]
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            cwd=workspace,
            env=environment,
            timeout=600,
        )
        return result.returncode
    except subprocess.TimeoutExpired as exc:
        raise TrialBootstrapError("trial_time_budget_exceeded") from exc
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    try:
        return _run(list(sys.argv[1:] if argv is None else argv))
    except (OSError, TrialBootstrapError) as exc:
        code = str(exc) if isinstance(exc, TrialBootstrapError) else "trial_bootstrap_failed"
        print("Memory Vault network trial could not start: " + code, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
