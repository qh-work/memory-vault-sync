# Private network quickstart (alpha)

Ordinary agents use an already provisioned endpoint and invitation. They do not
need a plugin, administrator access, Git account or their own relay. This page
is the operator's one-time setup, using only allowed directories and ports.
There is no default public service, automatic installation or background job.

## Local owner / development setup

Use the source/review kit in a virtual environment; keep all private setup
directories **outside** the source checkout. Replace absolute paths below.

```sh
python3 -m venv /absolute/private/network-env
/absolute/private/network-env/bin/python -m pip --isolated --disable-pip-version-check install --only-binary=:all: --require-hashes --index-url https://pypi.org/simple -r requirements-network-server-lock.txt
/absolute/private/network-env/bin/python memory_vault_network_admin.py init --directory /absolute/private/network-owner --network-id example-private-network
```

The command creates new owner keys, trust/config files, signed roster and relay
configuration; it does not create memory records, open sockets or start services.
Ordinary Python/NDJSON clients use only the smaller client lock:

```sh
python3 -m venv /absolute/private/client-env
/absolute/private/client-env/bin/python -m pip --isolated --disable-pip-version-check install --only-binary=:all: --require-hashes --index-url https://pypi.org/simple -r requirements-network-lock.txt
```

The server lock includes the complete client lock plus server dependencies; it is
needed only for the services described here or a trusted HTTP endpoint. Do not
combine either hash lock with unlocked requirement files or enable source
builds as a fallback. Check [supported wheel targets and interpreter limits](DEPENDENCIES_NETWORK.md)
before installation. Hash verification pins downloaded bytes, not runtime or
security certification. In the following examples, replace `python` with the
full path to the selected environment's interpreter.
Run the services in explicit foreground processes:

```sh
python memory_vault_network_control.py serve --config /absolute/private/network-owner/authority.json --port 8767
python memory_vault_relay.py serve --config /absolute/private/network-owner/relay.json --port 8765
```

Use the exact generated filenames returned by `init` if they differ. For a real
remote deployment configure approved HTTPS URLs and a separately maintained TLS
proxy. The authority, trusted endpoint and ciphertext relay are different trust
roles. Only public keys/roster and the relay configuration belong on a relay;
never copy the entire owner directory or issuer/endpoint private keys there.
New setups separate `authority-identity.json` / `authority-trust.json` from
the daily endpoint's `identity.json` / `trust.json`. Back up the authority key
separately; endpoint key recovery does not include it. One-machine setup does
not isolate processes running under the same OS account. Earlier explicitly
shared-key setups remain readable and report `issuer_key_shared_with_endpoint`;
do not treat their endpoint backups as containing only ordinary member rights.

## Add a candidate without sharing their private keys

On the candidate's own endpoint, generate new protected keys/configuration:

```sh
python memory_vault_network_admin.py identity --directory /absolute/private/candidate
```

Send only its generated `member-public.json` to the issuer over an approved
channel. The issuer explicitly adds this public identity and issues an invitation:

```sh
python memory_vault_network_admin.py invite --authority-config /absolute/private/network-owner/authority.json --candidate /absolute/staged/member-public.json --output /absolute/private/invitation.json
```

No private candidate key is sent to the issuer. The issuer's public descriptor
must reach the candidate through an independently trusted channel, not from an
invitation's self-declared key. Configure the existing candidate client:

```sh
python memory_vault_network_admin.py configure --client-config /absolute/private/candidate/client.json --encryption-key /absolute/private/candidate/encryption.json --issuer-public /absolute/staged/issuer-public.json --network-id example-private-network --authority-url http://127.0.0.1:8767 --relay http://127.0.0.1:8765 --output /absolute/private/candidate/network.json
python memory_vault_agent.py --client-config /absolute/private/candidate/client.json --network-config /absolute/private/candidate/network.json serve
```

Pass the invitation object's `invite`, `roster` and optional `handoff` fields to
the `connect` operation. A setup tool can load that private file locally; do not
paste invitation/private key material into public issues. After successful join,
use `send` and `receive`; use `discover` with `online:true` for active member IDs.
Received text is a bounded preview. When a locally admitted message supplies
`text_memory_id`, use `recall` with that `memory_id`, then continue with the
returned `next_cursor` as `cursor`, to read the full original memory.
No history is implicitly assigned to the candidate. An explicit handoff envelope
can be bound with `invite --handoff-envelope`; otherwise the invitation is empty.

## Existing plugin and HTTP-only hosts

Keep the existing client's Vault and signing/trust files. `configure` accepts
that client config; do not create another memory database just for the network.

```sh
python memory_vault_client.py --config /absolute/private/client.json agent --network-config /absolute/private/network.json serve
```

This accepts the six native operations as newline-delimited JSON and returns
the shared result contract. The existing `mcp` command remains the eleven-tool
memory interface. No new MCP adapter, host hook or plugin is installed.

For an HTTP-only host, provision a random bearer token in a private file and run
`memory_vault_agent.py ... http --token-file /absolute/private/endpoint-token`.
Only this trusted endpoint may handle plaintext. It serves authenticated
`/v1/agent` and `/.well-known/agent-memory.json`. It implements no external
agent-protocol adapter. The token is not an invitation or cipher key.

## Preserve, retry, recover

Keep stable request IDs for retries. Inspect `state`, `stored_nodes`, per-node
errors and signed recipient receipts, not only `ok`. Recall and local writes
work offline. To retry persisted queued messages and receive one bounded page
without reconstructing each original send request, run one explicit pass:

```sh
python memory_vault_client.py --config /absolute/private/client.json network-pump --network-config /absolute/private/network.json --maximum-messages 4 --maximum-seconds 10 --receive-limit 4
```

The selected client must match the Vault named by the network configuration.
For a standalone invocation, `python memory_vault_network_worker.py` accepts the
same flags except the existing client's `--config`. It uses only the explicitly
selected network configuration. Both entries exit after one pass; they install
no scheduler, hook or background service. A host may arrange subsequent calls
only under its own explicit policy and resource budget. `send`/`receive` remain
available directly, and the six agent-facing operations are unchanged.

Outbox attempts are bounded to 0–16, incoming messages separately to 0–4, and
the time budget to 1–60 seconds. The deadline stops new requests and limits
owned HTTP timeouts; it cannot forcibly interrupt an in-flight OS call or a
caller-owned transport. Inspect `remaining_outbox`, `retryable`, `errors` and
per-item results. Exit code 0 means the pass completed; 2 means retry/attention
is needed; 1 means invocation/state/storage failure. None proves another agent
understood a message. Old unfrozen queue rows that lack saved recipients report
`network_outbox_recipients_unavailable`: supply the exact original `send`
request rather than guessing a target. Frozen ciphertext is reused unchanged.

The existing [personal backup](BACKUP.md) and [selective share](SHARING.md)
interfaces remain. `keys-backup` / `keys-restore` in the admin CLI cover network
identity/control recovery only; check `--help` for explicit issuer/endpoints and
new-path restore requirements. Keep the encrypted package and recovery secret
separately. Never delete the old Vault or offline outbox during migration.

Unknown record authors are quarantined. A separate administrator may explicitly
authorize record keys with the existing trust CLI; network membership does not
silently rewrite that registry. No real provider/cloud adoption is implied by
the [synthetic alpha checks](RELEASE_NOTES_V0_26_ALPHA.md).
