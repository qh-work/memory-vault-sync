# Memory Vault v0.28.0-alpha.0.25 — retain receipt recovery after source loss

This candidate adds explicitly authorized copying and recovery of an existing
saved-message receipt. It preserves all three original ACK histories and the
recipient's exact signed receipt. Lost successful replies resume the same
durable request; restarting does not renew authority or reset work.

The recipient independently consents to reservation disclosure, copying and owner
return. Owner, source and maintainer permissions remain separate. The replacement
can COPY/READ/RETAIN; it gains no permission to admit a new receipt. Current READ
of a saved receipt does not depend on a still-active historical write ADMIT.

Python commands: `copy-reserve-occupied`, `copy-upload-occupied`,
`configure-replica-occupied`, and `recover-replica-occupied`. Existing private
identities and transport journals are reused. The Agent's `connect` action
`recover_replica_receipt` binds the recovered receipt to the actual original
send. Its saved acknowledgement survives restart and original-node loss.
New source preparation can explicitly select `copy_maintainer` with the finite
`receipt-index` profile. Default grants retain their existing operations;
an older signed root cannot acquire COPY through a new client setting.

Compact staged transfer reuses exact historical pack bytes. Owner recovery still
charges every advertised original against the logical proof-byte ceiling. The
per-operation 64-signature and per-replica 64-work limits are unchanged. No new
public allocation, arbitrary object-read endpoint or implicit permission is added.

Source-bound full CI, extracted-package checks and final public-archive review
are pending for this candidate. Do not treat a prior release's acceptance as this
candidate's result. Synthetic protocol and HTTP results do not establish external
agent adoption, global availability or thousand-agent capacity.

Replacement selection remains explicit. Native Node recognizes the occupied
replica proof grammar; full native replica and retained-mailbox clients remain
unfinished. Participants use their own authorized nodes; there is no project
operated public seed or required central authority.

Use the [quickstart](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.25/docs/OPEN_NETWORK_QUICKSTART.md)
and [receipt-replica guide](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.25/docs/OPEN_ACK_RECOVERY.md#copy-and-recover-an-existing-saved-receipt).
Preserve existing identity and state files when installing. Only implementation,
public documentation and wholly synthetic fixtures belong in these archives.
