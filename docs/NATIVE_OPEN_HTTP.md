# Native open HTTP contact preview

Version 0.28.0-alpha.0.1 extends the routing preview with native TypeScript
HTTP transport, participant orchestration, a standalone node and the open
contact path in the existing six-operation Agent. It uses the same signed
control/index formats, protected `network.sqlite3`, identities and client
configuration as Python. This is not the full alpha.1 consent/delivery/repair
milestone, a real-model campaign or a public service installation.

## Entry points

Use the existing Node 22.19+ runtime and locked JOSE dependency described in
[the native guide](NETWORK_TYPESCRIPT.md). The normal node config is unchanged:

```sh
node --experimental-strip-types clients/typescript/network/open-node.ts --config /absolute/private/open-node.json
```

The listener remains restricted to loopback and nonprivileged ports. An owner
must separately provide HTTPS termination for public use. Directory service
is closed unless the private `index_policy` explicitly enables a finite quota.
No command here generates identities, changes permissions or starts a service
automatically. Existing POSIX protected-storage limits remain; native Windows
storage, browsers and other JavaScript runtimes are not claimed.

```ts
import {Agent} from './clients/typescript/network/agent.ts';
const agent = new Agent('/absolute/private/client.json', '/absolute/private/open.json');
await agent.handle({op:'connect'});
const result = await agent.handle({op:'discover', online:true, key_id:knownOwnerKeyId});
```

The exact `memory-vault-open-client-config/v1` fields remain
`schema_version`, `client_config_path`, `state_directory`, `encryption_key_path`,
`seeds`, and `allow_loopback`. There are at most two initial signed introductions.
The selected client config must match the Agent's client config. No authority,
roster, private relay pool or injected transport is accepted for this profile.
Discovery without a target returns `target_key_required`, not a member list.
Offline remember/recall/discovery never construct a network client.

For explicit contact provisioning, `OpenParticipant` accepts the existing
signing identity document, absolute state directory and
`{seeds, descriptor?, allow_loopback?, index_policy?}`. Its asynchronous methods
are `join()`, `maintain()`, `findContact(ownerKeyId)` and
`publishContact(signedContact, leaseSeconds=300)`. Call `close()` when finished.
`issueContact` in `open-control.ts` creates the existing owner-signed document.
Publication is deliberate; connecting or remembering does not publish a contact.
The desired three distinct socket/key leases may be degraded and never prove
three physical fault domains. A directory receipt for withdrawal acknowledges
that withdrawal, not continued availability.

## Preserved boundaries

- All resolved addresses must pass the destination policy before any connection.
  Only validated literal addresses reach sockets. TLS checks the original
  hostname; redirects, ambient credentials, proxies and compression are refused.
  DNS has three outstanding OS slots even when callers time out. RPC bodies
  remain bounded at 64 KiB and the original lookup/maintenance budgets apply.
- Incoming sockets, rates, headers, body bytes and whole-exchange time are
  finite. This is local resource containment, not hostile Internet acceptance.
- Cache and self-announcements are introductions, never endpoint proof.
  Higher cached seed revisions retain the original probe position. Persistent
  revision, revocation and conflict floors still gate the fresh challenge.
  An exact proven announcement cannot refill pending work; a failed endpoint
  needs a new successful challenge before regaining that status.
- No discovery or publication writes Memory records, changes source bytes,
  grants trust or authorizes sharing/execution. Open `send`, `receive`, message
  reads, batch reads and invitation admission fail explicitly. Existing
  private-profile encrypted queues and record proofs remain available.

## Reproduction and evidence limits

`python -m unittest tests.test_open_typescript_http` uses real Ed25519, locked
JOSE, owned temporary SQLite and actual sockets. It tests bidirectional contact
publication, the native Agent, eight mixed processes with cold multi-hop
discovery, original bootstrap exit, endpoint restart and a directory opened by
the other language. Parent-response traces are checked against signed replies.
The harness does not supply a global graph, preload a target route or change
source caps. Additional checks cover TLS hostname mismatch, complete DNS
answer rejection, pinned sockets, deadline/capacity refusal, replayed
announcements, old seed revisions, closed index and unchanged local records.
Native drivers forbid child-process delegation before importing project code.

`tests.test_open_typescript_state` separately checks Python/TypeScript durable
floor/index parity: replay, renewal, expiry, revocation, same-revision conflict,
capacity refusal, transaction failure and alternate-language restart.
The retained private Agent HTTP regressions check that the shared schema and
config extraction preserve existing ciphertext and record proofs.

Test presence is not a passing run. CI records exact source, method outcomes
and runtime versions; match those to the release's manifest and checksums.
Eight local processes share one machine and one observed /24. They are not
eight models, eight physical fault domains, global reliability or a rerun of
the earlier 100-node logical experiment. Descriptor renewal/address changes,
first-contact consent, encrypted mailboxes/receipts, finite ciphertext leases
and sender-offline replica repair remain future work.
