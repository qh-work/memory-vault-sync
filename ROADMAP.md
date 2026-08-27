# Roadmap

The roadmap preserves one non-negotiable architecture: memory is an independent
evidence network. Tasks, projects, conversations, devices, models, and agents
may reference memory but never own it or determine its lifecycle or visibility.

## 0.21 — public-install hardening

- make first-run configuration explicitly unconfigured instead of pointing at
  the public source repository;
- add a guided setup check for a separate private GitHub/GitLab data repository;
- finish clean Windows installation acceptance;
- reduce migration-only task code and schemas in the default public surface;
- split the oversized runtime core into independently auditable modules.

## 0.22 — portable trust bootstrap

- integrate an audited OS key-store adapter;
- define signed first-device checkpoints and fingerprint verification;
- add enrollment, rotation, revocation, and recovery ceremony documentation;
- keep identities opaque and independent from tasks, projects, and chats.

## 0.23 — encrypted selective transfer

- ship an audited encryption-provider adapter;
- encrypt evidence/relation-closed selective bundles before publication;
- verify recipient, epoch, closure, replay, and atomic import failure cases;
- retain a readable local canonical memory format and deterministic fallback.

## 0.24 — encrypted replication and recovery

- publish ciphertext-only replication catalogs signed by active devices;
- support multiple authorized devices, revocation, epoch rotation, and disaster
  recovery without placing private keys in Git, CI, plugin data, or memory;
- prove restore and revoked-device rejection across macOS, Windows, and Linux.

## 0.25 — scalable cognitive views

- generate taskless continuity/handoff views from immutable evidence;
- add deterministic hierarchical summaries as disposable caches;
- improve multilingual semantic retrieval while preserving local-only recall,
  provenance, conflict visibility, and lexical fallback;
- stream very large histories directly from verified Git objects with bounded
  memory use.

External task managers, agent runtimes, policy engines, authorization services,
and execution gateways remain separate systems. Memory may provide evidence to
them, but it never grants permission or starts execution.
