# Controlled full-client updates, with the old installation preserved

The full client separates release inspection/staging from explicit managed
runtime activation. Memory text, MCP tools and sync packets cannot enable either
workflow. Ordinary plugin installs do not self-update. An independently opted-in
managed installation may schedule a finite update worker on an approved host
event. No workflow edits the host's settings, marketplace, hook trust, record
signing registry, existing private plugin or Vault.

From the packaged plugin root, these are **commands for the operator to run**;
they were not executed while preparing this release:

```bash
python3 scripts/launcher.py update check
python3 scripts/launcher.py update stage --version 0.25.0 --out /absolute/private/staged-update
```

`check` reads stable release metadata from the fixed public
`qh-work/memory-vault-sync` GitHub repository. It writes no local state and
loads no GitHub credential. `stage` pins an explicit version, reads the release
manifest, verifies the full-client ZIP's size/hash, validates its bounded
inventory and each listed runtime module's hash, and extracts into a **new**
directory under a private parent. Existing output is refused. Downloaded modules are never imported,
executed or automatically installed. Failure may leave a new incomplete staging
directory for inspection, not overwrite the current package.

Downloads use certificate-verified HTTPS, an allowlist of GitHub release hosts,
redirect checking, bounded metadata/archive sizes and a shared staging deadline
(default 120 seconds, configurable 1–300, plus bounded socket operations). Archive paths,
symlinks, duplicates, encryption and excessive expansion are refused. A
`STAGED.json` receipt is written only after the complete package is staged.

Use the actually published version; `0.25.0` above denotes this development
target. Source implementation and synthetic cases are included, but runtime
tests and a production publisher-key ceremony have not been performed here.

## Independently pinned publisher trust

Checksums are **not publisher authentication**. Unsigned staging explicitly
reports `publisher_signature_verified=false`. Optional profile
`memory-vault-tuf-style-rsa-pss/v2` restores v0.21's bounded RSA-PSS/SHA-256
verification capability without its Git control plane. It verifies root,
timestamp, snapshot and targets with disjoint role keys and thresholds. It is a
narrow profile, not full TUF certification or an audited cipher implementation.

Obtain a public root and its fingerprint through an independent approved channel:

```bash
python3 scripts/launcher.py update configure-trust --root-file /absolute/reviewed/root.json --trust-store /absolute/private/update-trust.json --expected-sha256 INDEPENDENT_ROOT_SHA256
python3 scripts/launcher.py update trust-status --trust-store /absolute/private/update-trust.json
python3 scripts/launcher.py update stage --version 0.25.0 --out /absolute/private/signed-stage --trust-store /absolute/private/update-trust.json
```

The initial root is never downloaded/trusted automatically; self-signature alone
does not establish who should be trusted. Existing stores cannot be overwritten
by bootstrap. No private signing key is imported or generated.

Signed staging requires timestamp.json, snapshot.json, targets.json and any
sequential N.root.json rotations from the release, or an explicit
`--metadata-directory`. Missing metadata, bad thresholds, expiry, future dates,
clock/version rollback, equivocation, mixed snapshots and target mismatches fail
closed. At most 32 sequential rotations are accepted with both previous and new
root quorums. Thresholds and role separation count distinct physical RSA
public keys `(n, e)`, not differently wrapped copies of the same PEM key.
Trust floors advance after complete staging. v2 binds the exact
full-client ZIP hash/length/version/source commit; the old Git-oriented trust
store is not silently transplanted. Record-signing trust remains separate.

**No production root or signed metadata channel is provisioned by default.**
Signed mode against an unsigned release fails closed. A release checksum is not
a completed publisher-signing ceremony.

## Isolated installation and activation

The host's native approved plugin update remains one choice. Alternatively:

```bash
python3 scripts/launcher.py install --installation /absolute/private/managed-client initialize --staged /absolute/private/staged-update --request-id req_install_example_0001 --expected-sha256 REVIEWED_ARCHIVE_SHA256
```

For signed staging, supply an independently pinned `--trust-store` instead of
relying on a manually reviewed archive hash. It must remain outside the
installation. Initialization requires a new directory and leaves existing
installations unchanged. The operator then connects the host normally to:

```text
python3 -I -B /absolute/private/managed-client/launcher.py --config /absolute/private/client.json mcp
```

Use this stable launcher for approved hook/host/compat/protocol commands too.
It does not approve hooks or establish automatic ChatGPT Work lifecycle support.

Versions live under releases/<archive-sha256>/. Activation rechecks the archive
and current signed chain, writes a prepared/committed journal, then atomically
selects code for future invocations. Running processes keep their code. Exact
retries return historical receipts without reactivating old code or treating
expired signatures as current trust. Activating an identical current target does
not erase the useful previous version. Old files are never automatically deleted.
If a crash moved the active pointer but did not finish the receipt, recovery
verifies the exact installed bytes and completes only that historical receipt,
even if metadata has since expired. If the pointer never moved, activation
still requires a currently valid candidate. Neither case replays a past
authorization to select new code.

New staged/installed files create each missing directory with private modes,
including intermediate archive directories; pre-existing modes are never
silently repaired. Files use protected temporary-file publication rather than
writing a partial final member. A caught write error cleans up that temporary
file, allowing the exact approved archive to be retried without poisoning an
immutable member path. This does not repair already truncated files, silently
remove unknown temporary files after a hard process kill, or certify power-loss
recovery. Unexpected existing bytes remain a visible refusal; the previously
active runtime is not overwritten.

The launcher checks its executable inventory and refuses unlisted files,
including __pycache__; disabling cache writes alone does not prevent reading
cached code. Both launchers also clear an external Python bytecode-cache prefix before
handing off to runtime code. Use `-I -B` as shown: the launcher cannot undo
code already executed by interpreter startup or site customization.
Windows initialization also pins/copies a native storage helper. The bootstrap
loads verified source bytes, not a module named in a memory or an
import cache. Bootstrap/helper updates require a new explicit installation.
See [platform scope](PLATFORMS.md).

## Optional finite automatic updates and rollback

```bash
python3 scripts/launcher.py install --installation /absolute/private/managed-client automatic --enabled yes
python3 scripts/launcher.py install --installation /absolute/private/managed-client apply
python3 scripts/launcher.py install --installation /absolute/private/managed-client automatic --enabled no
python3 scripts/launcher.py install --installation /absolute/private/managed-client status
python3 scripts/launcher.py install --installation /absolute/private/managed-client rollback --request-id req_rollback_example_0001 --expected-generation 2 --approve-rollback
```

Automatic mode is separate operator opt-in and requires pinned publisher trust.
Only the managed launcher's approved SessionStart path schedules a finite worker;
the hook makes no release network request. Checks coalesce to one per hour.
There is no startup service, persistent polling loop, log suppression or elevation.
Content-free update-events.ndjson diagnostics are retained; a full log stops new
workers for operator review. A change to declared host integration requires
explicit `activate --approve-host-contract-change`; automation cannot approve it.

Use the actual current generation for rollback. It selects retained code,
pauses automatic updates and never lowers signature trust floors or rewinds
memory. A deliberate re-enable creates a new logical update attempt. Backup
data before a separately requested schema migration: code rollback is not a
database rollback. See [recovery](BACKUP.md).
