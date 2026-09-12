# Memory Vault v0.28.0-alpha.0.4 — approved delivery fix

Fixes `open_delivery_not_authorized` after a recipient approves contact. The
node incorrectly expected the stored request lifecycle to be `approved`; CONTACT
stores it as `decided` and keeps `approved` in the signed decision. Delivery now
checks the correct lifecycle while retaining full signature, exact decision,
finite resource, identity, policy and expiry verification. Rejected or pending
contact still cannot authorize delivery.

Upgrade and restart the Python node accepting delivery, preserving its existing
identity, configuration and `network.sqlite3`; no database migration is needed.
Updating only the clients does not fix a node still running the old code. Retry
the original send only while the original approval and finite lease remain
valid. This fix does not bypass expired authorization or automatically recover
an expired frozen send.

Five targeted regressions passed over real local HTTP: three Python and two
native TypeScript cases. They cover approval, encrypted delivery, durable
recipient saving, saved receipts and rejection boundaries. The Python cases
also cover selected original memories and recall after restart. Native clients
use their own implementation without delegating operations to Python. The full
test suite was not run; these results do not establish global reliability or
external-agent adoption.

Use the [open-network quickstart](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.4/docs/OPEN_NETWORK_QUICKSTART.md)
and this release's full client archive. Participants operate their own nodes and
share signed introductions; no project-operated public seed is supplied. Both
Python and native TypeScript clients use the supplied Python delivery node.
Delivery remains bound to the original approved node and its lease lifetime;
replacement-node repair and independent receipt repair remain unfinished.
This is an experimental prerelease.
