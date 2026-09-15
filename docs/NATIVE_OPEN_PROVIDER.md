# Native provider discovery and directory publication

This development candidate adds native TypeScript access to the existing
`memory-vault-open-provider/v1` directory protocol. It is newer than the published
alpha.0.5 archives. Use the matching source and review evidence for this candidate.

The provider client shares the running participant's protected transport database,
signing identity and X25519 identity. It does not create another Vault. No Python
subprocess is used by the TypeScript client; the directory and provider endpoints
in the current integration use the Python node with explicit provider opt-in.

An advertisement identifies an opaque reference and an observed provider. It
does not prove that ciphertext exists or authorize reading, copying, delivering,
trusting or executing it. The client cannot sign for an absent root owner.

## Native API

Import `OpenProviderClient` from `clients/typescript/network/open-provider-client.ts`
or the network package's `./open-provider-client` export. Wire constructors and
validators are exported by `./open-provider`. The caller supplies an already
configured `OpenParticipant` and its authorized encryption identity.

```typescript
const provider = new OpenProviderClient(participant, encryptionIdentity);

// Owner B reserves real directory resources and authorizes this exact P/ref.
const prepared = await provider.authorizePublication(
  ref, rootKey, publisherDualId, allocationId,
  {directory_count: 1, resource_seconds: 600, lease_seconds: 180},
);

// P publishes its signed provider.fact with the returned owner authorization.
const published = await provider.publish(
  ref, rootKey, signedProviderFact, publicationId,
  {directory_count: 1, authorizations: prepared.authorizations},
);

// A reader obtains responsive candidates and the signed directory observations.
const found = await provider.find(ref, {maximum_candidates: 8, maximum_directories: 3});
```

`ref` is `{namespace, key}` with an opaque 64-hex key, not a content hash.
`rootKey` is the existing provider RootKey and has an exact owner DualID.
`publisherDualId` binds both signing and encryption keys. A publishing participant
must have a valid node descriptor; the fact must bind its signing key and storage
epoch. Its reachable node must answer both target-key challenges.

When P also owns the root, `publish` can omit `authorizations` and reserve its own
directory resources first. When P differs from B, only B's exact signed bundles
are accepted. Changing the publisher, encryption key, root, reference, resource
or grant digest cannot reuse those bundles. Each private resource/publication
request requires a fresh in-process proof of the target's signing and encryption
keys before the root or grants are disclosed.

All methods accept the existing finite `LookupBudget` through their `budget`
option; `call(node, action, body, budget)` and `proveTarget(node, budget)` take it
directly. One invocation keeps the same request/time/byte budget across directory
lookups, proof, allocation and publication. A transport failure keeps the maximum
response reservation charged and marks `response_bytes_are_upper_bound`.
This per-call lookup budget is not the future durable repair campaign ledger.

The default directory reservation requests zero live-object bytes, 98,304 metadata
bytes, one indexed item, eight requests and eight replay records. The real node's
finite policy can refuse it. Index leases never become object custody leases.

## Durable retry and observation boundaries

The first publication body is frozen before the remote write. Repeating the same
logical allocation after a restart recovers the same index lease through
`provider.result`; a conflicting ref, fact or grant under that local identifier
is refused. Expired grants or resources are not extended by a retry. Transport
state is bound to both local keys and cannot be reopened with a different pair.

Facts are tracked with bounded durable revision and conflict floors. A lower
revision is rejected; different bytes at the same revision persist a conflict.
Returned observations must still match active current floors and valid index
leases. `observed` means that the directory returned eligible signed facts and
the provider answered the dual-key challenge. It does not mean a message was
stored, delivered or saved by its recipient.

This candidate's focused fixtures use real local Python HTTP nodes, native Node
and locked JOSE with synthetic identities. They cover owner/third-party
publication, dual-key refusals and restart result recovery. They are wired into
the open-network CI list; only an actual completed run establishes a pass.
Native TypeScript node-side provider hosting remains unimplemented.

Cross-node mailbox repair, independent ACK repair, durable campaign budgets and
custody GC are separate work in the source checkout's proposed
`docs/proposals/OPEN_DELIVERY_REPAIR_R3.md` repair contract. That proposal is not an
implemented wire protocol or an approval to migrate an old delivery lease.
