# v0.26.0-alpha.1 development: native communication around shared memory

This is a repository-local update draft, not an already posted announcement.
The alpha adds optional native communication while retaining the existing
client and its [P01–P14](../docs/V0_25_PARITY_PLAN.md) acceptance ledger.

Two equal routes remain: implement the language/storage-independent agreement,
or use the authorized client. Both exchange identical taskless memory records.
No Task/Git ownership or monolithic runtime is reintroduced.

The source now includes the old production host bridge, complete bounded local
retrieval/graph views, signed resumable transfer and blocked-send review, legacy
packs/checkpoints, full recovery, managed updates/rollback, selected sharing,
external trust/encryption boundaries and native protected storage adapters.

The optional network adds six native agent operations, independent issuer/member
credentials, encrypted selected-memory delivery, bounded rejection, recovery
and explicit one-pass outbox/inbox pumping. It reuses existing canonical memory
and trust; it has no external agent-protocol adapter or automatic service.
Client dependencies and operator server dependencies have separate hash locks.

Source implementation is **not runtime evidence**. The
[validation index](../docs/VALIDATION.md) pins limited offline synthetic results
to exact source commits; they do not transfer between versions. The current
[alpha evidence](../docs/RELEASE_NOTES_V0_26_ALPHA.md) separates synthetic
network/crypto and loopback-process checks from real-model and deployment
acceptance. Full P01–P14, live-cloud, real-host/cross-device, native Windows,
performance and broader recovery/update-crash acceptance remain open. The
planned thousand-agent workload, horizontal sharding and federation are not
certified by this alpha. The separate review kit supplies synthetic material
for independently authorized reviewers; no installation or public release is
implied by this draft.

Start with [AI_START_HERE.md](../AI_START_HERE.md),
[the capability map](../docs/PARITY.md),
[the reviewer handoff](../docs/REVIEW_HANDOFF.md), or
[the small two-mode contribution](CONTRIBUTOR_TASK.md). Report exact commit,
profiles, host/runtime, commands and observed results; distinguish not-run from
pass/fail. No claim of deployment, another AI's use or endorsement is implied.
