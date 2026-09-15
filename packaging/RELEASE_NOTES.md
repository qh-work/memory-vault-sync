# Memory Vault v0.28.0-alpha.0.5 — current-fact continuation scorer

Adds a runnable, operator-controlled continuation scorer to the downloadable
review kit. Five blinded synthetic cases require the recipient to read the
current fact source before submitting an answer. A correct guess without a
source-owned read fails; so does answering unknown when evidence is available.
An old-but-still-correct control prevents rejecting every old observation from
passing. The first submission is frozen, and later reads cannot repair it.

[Download the review kit](https://github.com/qh-work/memory-vault-sync/releases/download/v0.28.0-alpha.0.5/memory-vault-review-v0.28.0-alpha.0.5.zip)
and follow [the continuation guide](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.5/docs/CONTINUATION_TRIAL.md).
After extraction, run from the review-kit directory:

```sh
python3 -B scripts/continuation_trial.py --output /absolute/private/new-trial --seconds 900
```

Python 3.10+ and its standard library are sufficient. The output directory must
be new, with an existing parent. The fixture listens only on loopback. Give each
isolated candidate one assignment; keep source code, hidden case labels and the
operator report outside the candidate's access. This records source responses
and synthetic proposed actions, not model understanding or real-world actions.
The full client and protocol archives include the guide; the runnable scorer
and its tests are in the review kit.

The alpha.0.4 fix for `open_delivery_not_authorized` after recipient approval is
retained. Agents can use Python or native TypeScript to exchange encrypted chat
and selected original memories after explicit approval, with storage and
recipient-save receipts. Use the [open-network quickstart](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.5/docs/OPEN_NETWORK_QUICKSTART.md)
and [full client archive](https://github.com/qh-work/memory-vault-sync/releases/download/v0.28.0-alpha.0.5/memory-vault-client-v0.28.0-alpha.0.5.zip).
Operators upgrading a node older than alpha.0.4 must update and restart its Python
runtime while preserving identity, configuration and network.sqlite3. No database
migration is needed; existing finite approvals and expiry checks still apply.

Validation scope: the unchanged scorer passed 13 focused synthetic checks on
`640e65a574245f709c44c56bf14231584b7201a1`. The retained delivery fix passed three
Python and two native TypeScript local HTTP regressions on
`f87a1d295beb2ff8134a77d9978333a529da55e5`. These historical results are separate
from this release's source/byte packaging checks. No new runtime suite, CI pass,
6 Pro review, external-model trial or global acceptance is claimed.

This is an experimental prerelease. Participants operate their own nodes and
exchange real signed introductions; no project-operated public server is
supplied. Delivery remains bound to the original approved node and finite lease.
Replacement-node repair and independent receipt repair remain unfinished.
Canonical memory and delivery protocols are unchanged in this packaging release.
