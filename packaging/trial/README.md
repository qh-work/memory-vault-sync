# Memory Vault synthetic network endpoint trial

This package is a bounded, wholly synthetic test endpoint for the Memory Vault
`network-v1` preview. It is not a plugin installer, relay, server, or production
client.

For the operated alpha.3 trial service embedded in this release, run:

```console
python3 run.py --service https://commands-harvard-kingdom-tube.trycloudflare.com --run-code ONE-TIME-CODE
```

The release publisher provides a one-time code out of band. The package pins
the operated service's public identity and exact HTTPS origins; it contains no
run code, private key, machine/account identifier or user memory. A package
with unconfigured trust exits before creating a virtual environment or making
a network request.

## What the command does

The standard-library bootstrap verifies the package's exact file inventory,
creates a temporary private Python virtual environment, and installs the
included hash-locked client dependencies from official PyPI wheels. It then
runs one endpoint that:

1. generates fresh Ed25519 signing and X25519 encryption keys locally;
2. enrolls those public keys with the configured trial coordinator;
3. joins the configured encrypted relay;
4. creates a synthetic nonce memory in an isolated temporary Vault;
5. sends only that selected synthetic memory to the configured reference peer;
6. receives and verifies a fixed synthetic response;
7. checks local recall, receipt states, and one exact idempotent retry; and
8. prints a redacted result and removes temporary endpoint state by default.

`--keep-state` retains only the newly created synthetic trial directory for
debugging. The endpoint never reads an existing Memory Vault, plugin directory,
home-directory configuration, environment credential, clipboard, project, or
user-supplied content. Do not paste real memory into the run code or command.

## Privacy and trust boundary

Message bodies, memory IDs, content hashes, evidence, and handoff content are
end-to-end encrypted. The relay can still observe necessary metadata such as
network routing identifiers, timing, ciphertext size, delivery attempts, and
the test endpoint's network address. The authorized reference peer can decrypt
messages addressed to it. This test does not provide traffic anonymity.

The coordinator receives the one-time code and candidate public keys. It must
not receive endpoint private keys. The package accepts only the service identity
embedded in `service-trust.json`; a command-line trust override is rejected.
The embedded trust is part of the release bytes, but the included SHA-256
manifest is not a publisher signature. Verify the release tag and published
checksum before running downloaded bytes.

The relay cannot inspect encrypted plaintext to enforce a synthetic-only rule.
The endpoint makes the rule enforceable on the participant side by exposing no
input for text, files, Vault paths, or arbitrary messages. The operated trial
service must be isolated from production networks and use short-lived
membership, bounded storage, rate limits, and deletion schedules.

## Requirements and limits

- CPython 3.10 through 3.14 with `venv`, `pip`, and outbound HTTPS access.
- No Docker and no administrator privileges.
- The first run downloads the exact hash-locked wheels; the package does not
  bundle third-party wheel files.
- A successful test proves one bounded endpoint-to-reference-peer exchange over
  the configured service. It does not prove anonymous traffic, unlimited
  capacity, a production SLA, multiple failure domains, or thousand-agent scale.
- Alpha.3 uses a time-bounded Cloudflare Quick Tunnel preview operated from the
  maintainer's endpoint. It has no uptime SLA; a later stable service or URL/key
  rotation requires newly pinned release bytes.
