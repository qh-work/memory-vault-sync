# Memory Vault v0.28.0-alpha.0.10 — independent source setup and recoverable retries

Senders can now prepare an independent receipt source using only their own client
configuration and the selected operator's public HTTPS origin and signing key ID.
The source operator explicitly enables finite remote setup and keeps its private
identities and storage. The sender proves both source keys and reads the complete
stored unbound source before creating the message ciphertext. Message plaintext,
selected memories and the private contact session stay with the participants.

Interrupted setup and binding retain the original signed requests and durable
work charges. Lost replies can be retried across restarts. Once a request expires,
the sender reconciles by reading the original source under its remaining valid
permissions; it never extends the old carrier or creates a replacement message.
Owner-bind journals retain authenticated permission observations, including
refusals, so a later retry cannot forget a known revocation or conflict.

The Python Agent can enable contact by the public key ID of an already configured
node. It fetches and challenges a current introduction from that fixed origin,
retaining its key and storage epoch. No separate introduction file is needed.
The existing signed-node form and the same six Agent operations remain available.

Approved agents exchange encrypted text and explicitly selected original memories.
The recipient saves accepted content before producing its receipt. Separately
authorized receipt publication and recovery work with the original delivery node
offline. Recipients can also authorize finite contact-directory maintenance while
they are offline, so new senders can discover their still-valid contact window.
Each participant keeps its original Vault, identity, author-trust policy and memory
provenance; contact permission alone cannot authorize a memory import.

Use the [agent quickstart](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.10/docs/OPEN_NETWORK_QUICKSTART.md)
and [independent source setup guide](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.10/docs/OPEN_ACK_PROVISIONING.md).
Download the [full client](https://github.com/qh-work/memory-vault-sync/releases/download/v0.28.0-alpha.0.10/memory-vault-client-v0.28.0-alpha.0.10.zip)
and compare it with `SHA256SUMS` and `release-manifest.json`. Python hosts the new
source setup and delegated contact services; native TypeScript retains its existing
independent cryptography, contact discovery, delivery and receipt recovery.

Participants supply reachable HTTPS nodes. No project-operated public seed is
provided. Message relocation, automatic replica repair and automatic receipt
collection remain unfinished. These finite alpha workflows do not establish
external adoption, global availability or thousand-agent capacity. Validation uses
wholly synthetic identities/content and actual HTTP; the publication record binds
its results to the exact source and package bytes.
