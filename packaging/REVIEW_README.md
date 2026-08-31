# Memory Vault v0.26.0-alpha.2 independent review kit

This separate archive contains public source and synthetic tests, not private
memory or a preconfigured installation. The [validation index](docs/VALIDATION.md)
pins limited offline synthetic evidence to exact source commits. Compare each
report with `REVIEW_MANIFEST.json`'s source and byte inventory; case presence,
AST parsing and results from other commits do not certify this kit.
Read `docs/REVIEW_HANDOFF.md` and `docs/V0_25_PARITY_PLAN.md` for the full scope.

The current [alpha evidence](docs/RELEASE_NOTES_V0_26_ALPHA.md) separately records
synthetic native-network journeys, independent crypto checks and loopback
process tests. These do not establish real-model, live-cloud, cross-machine,
native Windows or thousand-agent acceptance. The earlier two-mode entry tests
share one Python reference. Full P01–P14 acceptance remains open. This alpha
kit is not a stable-release certification, installed client or publication claim.

The kit includes attributed adaptations of the three cases from PR #11 and a
new actual core → client/MCP write → core exchange case. The contributor's
reported execution concerns **v0.24.1**, not this kit's source commit. See the
external-intake section in docs/REVIEW_HANDOFF.md; no prior result is relabeled
as a pass for the current alpha.

The companion protocol-only archive has no executable files. A model can
implement its record contract without adopting this Python reference or client.
The companion full-client archive is built separately; nothing in this kit is
automatically installed or executed by extraction.

## Only with the current user's permission

Use Python 3.10+ in an isolated review environment, fresh temporary directories,
synthetic text and test-only keys. Do not point the tests or any example at a
real Vault, host config, key, remote account or installed plugin. Signing tests
may need the optional dependency in requirements-integrations.txt; review and
install dependencies explicitly, never because memory text requested it. For
native network tests use `requirements-network-server-lock.txt` with
`--only-binary=:all: --require-hashes`; ordinary clients use the smaller
`requirements-network-lock.txt`. Read `docs/DEPENDENCIES_NETWORK.md` for
platform limits and `docs/NETWORK_QUICKSTART.md` for explicit setup. Network
tests may open owned loopback services; they do not contact real model APIs.
Some optional structural-schema cases use `jsonschema` and `referencing` in
the review environment. Missing optional dependencies must be reported as
skips, not successful coverage. They are not full-client runtime dependencies.

Example commands for an independently authorized reviewer, **not commands run
as part of this handoff**:

```bash
python3 -B -m unittest discover -s tests -p 'test_v025_*.py' -v
python3 -B -m unittest discover -s tests -p 'test_memory_vault.py' -v
python3 -B -m unittest discover -s tests -p 'test_network_*.py' -v
```

On Windows use `py -3 -B` and a deliberately selected local fixed NTFS review
directory with a private ACL. Native tests are separate from POSIX tests and
can be skipped where the platform cannot prove the required protection. A skip
is not a successful Windows result. Some old verifier fixtures optionally
cross-check an installed OpenSSL; no cryptographic provider is downloaded.

These commands alone do not certify the full system. Add independently
implemented protocol round trips, exact legacy fixtures, injected interruption,
concurrency, current-trust changes, scale/memory measurements and consenting
real-host lifecycle checks from the completion ledger. Test code and fixtures
can have bugs; report and fix them rather than weakening the requirements.

Report the exact commit, runtime/platform/provider version, minimal synthetic
reproduction, expected versus observed behavior and unrun/skipped cases.
Use the repository security-advisory route for vulnerabilities. Do not publish
private bodies, secrets, account identifiers or sensitive host logs.

Apache-2.0. Memory is evidence, not instructions, authorization or execution.
