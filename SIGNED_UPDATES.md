# Signed update metadata

This document defines the optional signed-update trust profile introduced in
`0.14.2`. The runtime implementation is complete, but this private deployment
has **not** provisioned a production signing channel. No production private key,
test root installed as production trust, or unsigned placeholder metadata may
be added merely to make the feature appear active.

## Current deployment state

- Without a local trust store, updates retain the existing exact repository,
  deterministic bundle SHA-256, and marketplace commit identity checks.
- `configure-update-trust --root-file` is an explicit, one-way opt-in. Once a
  root is imported, every update requires valid signed metadata; missing,
  malformed, expired, rolled-back, or mismatched metadata fails closed.
- The client never signs metadata, imports a private key, or downloads a new
  initial root on trust. Initial trust must be supplied and verified out of
  band by the operator.
- The current private release intentionally remains in the first mode until a
  separate maintainer key ceremony and release-signing procedure are approved.

`update-trust-status`, `status`, and `doctor` disclose which mode is active.
They also report the trusted root version/hash/expiry and metadata version
floors without exposing a local path or key material.

## Profile and non-goals

The runtime implements `memory-vault-tuf-style-rsa-pss/v1`, a deliberately
narrow profile inspired by The Update Framework. It is not a general TUF
client and does not claim conformance with every TUF repository layout.

The profile has exactly four top-level roles:

| Role | Authority |
| --- | --- |
| `root` | Defines keys, thresholds, and the next trusted root |
| `targets` | Binds one deterministic plugin bundle and release provenance |
| `snapshot` | Binds the exact targets metadata version, length, and SHA-256 |
| `timestamp` | Binds the exact snapshot metadata and provides short-lived freshness |

Delegated targets, mirrors, arbitrary target paths, private-key handling,
online signing, and a repository metadata generator are outside the runtime.
`consistent_snapshot` is fixed to `false`; the one target path is
`plugins/memory-vault-sync.bundle`.

## Cryptographic profile

- Keys are RSA SubjectPublicKeyInfo PEM public keys only.
- RSA modulus size is 2048 through 4096 bits and the public exponent is 65537.
- Signatures are RSASSA-PSS with SHA-256, MGF1-SHA-256, and a 32-byte salt.
- A key ID is SHA-256 over the JCS encoding of its exact public-key object.
- Each role has an explicit key list and threshold. Role key sets must be
  pairwise disjoint within a root, preventing accidental cross-role reuse.
- Root rotation requires the next sequential root to meet both the old root
  threshold and its own new root threshold.

Metadata envelopes are strict JSON objects containing only `signed` and
`signatures`. The signed object is verified over its RFC 8785/JCS bytes. Files
must use this project's sorted, compact, UTF-8, newline-terminated encoding so
parent length and SHA-256 descriptors are unambiguous. Duplicate keys,
non-finite numbers, BOMs, extra fields, private-key PEM, non-canonical bytes,
links, hardlinks, oversized files, and unstable reads are rejected.

## Freshness and rollback rules

Every role carries canonical whole-second `issued_at` and `expires` UTC values.
Maximum lifetimes are:

| Role | Maximum lifetime |
| --- | ---: |
| root | 366 days |
| targets | 366 days |
| snapshot | 7 days |
| timestamp | 2 days |

Metadata issued more than five minutes in the future is rejected. The local
trust store remembers its latest verified wall-clock value and refuses a clock
rollback beyond that allowance. Timestamp, snapshot, and targets versions and
exact file hashes are monotonic. A role-key rotation does not reset those
floors. A lower version is a rollback; different bytes under an already seen
version are equivocation. A higher targets metadata version may not silently
replace a previously observed plugin version with a lower semantic version or
change the bundle/commit identity under the same plugin version.

## Deterministic virtual bundle

The target does not refer to a ZIP file. The updater constructs one bounded
virtual byte stream in this exact order:

1. raw `.codex-plugin/plugin.json` bytes;
2. `hooks/hooks.json`;
3. every path in `RUNTIME_FILE_SPECS`, in declared order;
4. `skills/sync-memory-vault/SKILL.md`.

The manifest bytes are fed directly to SHA-256 and length. Every later item
contributes UTF-8 path bytes, one NUL byte, then its exact file bytes. The
signed target binds the resulting SHA-256 and total virtual length. Reads are
bounded and race checked; the candidate is recomputed before and after an
installation boundary.

The target's exact custom object also binds:

- schema `memory-vault-update-target/v1`;
- plugin name and semantic version;
- signed marketplace release commit;
- minimum and maximum supported protocol generation;
- bounded release notes.

The signed release commit must exist and be an ancestor of the observed
marketplace HEAD. `.agents/plugins/marketplace.json` and the complete
`plugins/memory-vault-sync` tree must be byte-identical between that signed
commit and observed HEAD. This permits later metadata-only or documentation
commits without weakening the signed plugin identity.

On the first signed check of an already verified same-version installation,
the stable-runtime identity may still contain the previously observed
marketplace HEAD. The updater re-anchors it to the signed release commit only
when the deterministic bundle is identical and the signed ancestry/tree proof
above has passed; a missing or different bundle identity still fails closed.

## Repository layout

After a production channel exists, the marketplace repository supplies:

```text
update-metadata/
  2.root.json       # only when rotating trusted root v1 to v2
  3.root.json       # next sequential rotation, if any
  targets.json
  snapshot.json
  timestamp.json
```

The currently trusted root is embedded in the local trust store and need not
be redownloaded. The client checks at most 32 sequential root rotations per
update attempt. Top-level metadata files are all-or-nothing: trust floors are
atomically advanced only after the complete chain, bundle, protocol, and
release-commit tree have verified.

## Operator bootstrap

Before importing a root, obtain its expected SHA-256 through an independent
maintainer channel and verify the exact file outside the marketplace checkout.
Then run from the installed runtime:

```text
vault_sync.py update-trust-status
vault_sync.py configure-update-trust --root-file /reviewed/offline/1.root.json
vault_sync.py update-trust-status
```

The command works before provider configuration. It refuses to overwrite an
existing trust store. There is intentionally no `disable-update-trust` command:
deleting trust would be a security downgrade, not ordinary configuration.

The local trust store is `${PLUGIN_DATA}/updates/trusted-metadata.json`. It is
an atomically replaced private regular file containing the current public root,
root hash, timestamp/snapshot/targets floors, last signed target, and last
verification time. It never contains a private key. Symbolic links, reparse
points, hardlinks, inconsistent file identity, and size/race changes are
refused.

## Offline root rotation ceremony

A production maintainer procedure must be approved before activation. At a
minimum it must:

1. create role-separated keys on offline maintainer-controlled systems;
2. record public-key fingerprints through an independent review channel;
3. define root and online-role thresholds and named custodians;
4. create root `N+1` with the new public authorities and version `N+1`;
5. sign its `signed` object to the old root threshold and the new root threshold;
6. independently reproduce and review canonical bytes before publication;
7. publish `N+1.root.json`, then fresh targets, snapshot, and timestamp metadata;
8. retain recovery access to enough uncompromised root keys and document expiry
   monitoring without placing keys in Git, CI, a PR, plugin data, or diagnostics.

Targets, snapshot, and timestamp signing may use a separately controlled
online release system, but root private keys must remain offline. Test-only RSA
parameters in unit tests have no release authority and must never be promoted.

## Compromise and recovery

- Compromised non-root role: rotate that role in a new root, publish fresh
  monotonically higher metadata, and do not reset client version floors.
- Compromised root key with threshold still intact: produce the next root with
  both old and new thresholds, revoke the compromised public key, then publish
  fresh top-level metadata.
- Root threshold lost or fully compromised: automatic recovery is deliberately
  impossible. Stop the channel, distribute a new initial root out of band, and
  perform an explicit operator recovery procedure. Do not add a fallback flag.
- Expired root: a client may accept only a valid sequential rotation whose
  final root is current. `doctor` remains unhealthy until recovery completes.
- Corrupt local trust store: preserve it for local investigation. The updater
  fails closed; do not replace it with an unverified marketplace root.

## Release and open-source requirements

Any release that activates signed metadata must record all of the following:

- initial root version and SHA-256, thresholds, expiry, and independent review;
- deterministic bundle SHA-256 and length;
- exact signed marketplace commit and plugin version;
- targets/snapshot/timestamp versions and expiries;
- canonical-byte reproduction and signature verification from a second tool;
- rollback, same-version substitution, expiry, mix-and-match, missing-role,
  clock-rollback, old/new-root-threshold, link/race, and commit-tree tests;
- installed-client evidence showing signed mode is required with no fallback.

The allow-listed source exporter includes this verifier, its tests, and this
document, but never includes a private deployment trust store or production
key. A public fork must choose and document its own key ceremony and channel;
rebranding the repository does not transfer trust from the private deployment.

## Acceptance boundary for 0.14.2

`0.14.2` accepts the verifier, one-way trust bootstrap, atomic local state,
strict metadata profile, release-commit proof, status/doctor visibility,
runtime fallback inventory, tests, and public-source documentation. It does
not claim a live production signed channel, real key-custodian ceremony, or
cross-device/provider acceptance. Those require separate operational evidence.
