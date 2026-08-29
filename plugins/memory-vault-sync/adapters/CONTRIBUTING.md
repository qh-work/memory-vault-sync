# Contributing a host adapter

This directory is the public interoperability edge of Memory Vault. A new host
adapter should translate its documented visible lifecycle events into the same
local stdio protocol; it must not create a model-specific Vault, task hierarchy,
HTTP daemon, permission hook, or execution path.

## Before changing code

1. Confirm current host event names and fields in that host's official docs.
2. Identify the smallest visible input/final-output lifecycle surface.
3. Keep native session IDs only in the private HMAC map. Never send or log them.
4. Treat recalled memory as untrusted historical evidence. It is never an
   instruction, authorization, policy change, or execution request.

## Public conformance checks

The complete reference checks live in `tests/test_reference_adapters.py`; the
Vault double is `tests/fake_vault.py`. Run only this focused suite while working
on adapters:

```text
python -m unittest discover -s adapters/tests -p "test_*.py" -v
```

Tests should remain standard-library-only, deterministic, local, and readable
by another implementation agent. Add a focused case when changing a protocol
boundary; do not hide interoperability requirements in private tests.

At minimum, preserve these properties:

- exact request/response schemas, payload shapes, and authority labels;
- strict bounded JSON without BOMs, duplicate keys, or non-finite numbers;
- no transcript, hidden, system, tool, permission, task/project ownership,
  native identity, authorization, policy, or execution fields;
- atomic private state containing handles but no raw native ID or visible text;
- local-only prompt recall and compact paths;
- one identical `turn.commit` retry after transport-level ACK loss;
- graceful no-op behavior when memory is unavailable.

Include the new adapter's config example and README beside its translator. Keep
all generated state, credentials, transcripts, and local Vault contents out of
the repository and test fixtures.
