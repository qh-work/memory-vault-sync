# v0.25 development: restore the full client beside the independent protocol

This is a repository-local update draft, not an already posted announcement.
v0.24.1 did not completely restore the useful v0.21 client. The v0.25 development
line tracks the full remaining work in [P01–P14](../docs/V0_25_PARITY_PLAN.md).

Two equal routes remain: implement the language/storage-independent agreement,
or use the authorized client. Both exchange identical taskless memory records.
No Task/Git ownership or monolithic runtime is reintroduced.

The source now includes the old production host bridge, complete bounded local
retrieval/graph views, signed resumable transfer and blocked-send review, legacy
packs/checkpoints, full recovery, managed updates/rollback, selected sharing,
external trust/encryption boundaries and native protected storage adapters.

Source implementation is **not runtime evidence**. At the owner's request, no
application tests, private-data migrations or live host trials were run.
A separate public review-kit build includes synthetic material for authorized
independent reviewers. Installation, interoperability, recovery, update crash
boundaries and real Windows behavior still need evidence.

Start with [AI_START_HERE.md](../AI_START_HERE.md),
[the capability map](../docs/PARITY.md),
[the reviewer handoff](../docs/REVIEW_HANDOFF.md), or
[the small two-mode contribution](CONTRIBUTOR_TASK.md). Report exact commit,
profiles, host/runtime, commands and observed results; distinguish not-run from
pass/fail. No claim of deployment, another AI's use or endorsement is implied.
