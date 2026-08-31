# Optional network dependency locks

The native network client and its optional server have separate, wheel-only
dependency locks. The single-file memory core remains standard-library-only.
Nothing installs dependencies on import, and these files do not change the
existing compatibility range in `requirements-integrations.txt`.

| File | Scope |
| --- | --- |
| `requirements-network-lock.txt` | Client: `cryptography`, `joserfc`, `httpx`, and every required transitive dependency |
| `requirements-network-server-lock.txt` | Includes the client lock, then adds base `starlette`, `uvicorn`, and `click` |
| `examples/network-interop/package-lock.json` | Independent TypeScript fixture: `jose@6.2.10`, with npm artifact integrity |
| `clients/typescript/network/package-lock.json` | Independent TypeScript endpoint: the same `jose@6.2.10` artifact; built-in Node crypto and SQLite add no npm runtime dependency |

The unlocked requirements files remain useful declarations of optional
dependencies. The lock files are the reproducible installation inputs; do not
combine them with the unlocked files in hash-checking mode.

## Exact versions and markers

This snapshot was generated on **2026-08-31**, retaining the versions in the
existing synthetic-test environment. The Python 3.10-only `exceptiongroup`
branch was resolved separately from official PyPI metadata.

| Scope | Exact versions |
| --- | --- |
| Client direct | `cryptography==50.0.1`, `joserfc==1.7.5`, `httpx==0.28.1` |
| Client transitive | `anyio==4.14.2`, `certifi==2026.7.22`, `cffi==2.1.1`, `exceptiongroup==1.3.1`, `h11==0.16.0`, `httpcore==1.0.9`, `idna==3.19`, `pycparser==3.0`, `typing_extensions==4.16.0` |
| Server additional | `starlette==1.6.0`, `uvicorn==0.52.4`, `click==8.5.0` |

The client has 12 conditional pins, and the server has 15 including that client
closure. `exceptiongroup` is needed below Python 3.11; `typing_extensions` is
needed below Python 3.13. `cffi` and its `pycparser` dependency are selected for
non-PyPy interpreters according to the cryptography dependency branch. These
markers must not be removed based on a freeze from a single Python version.
Keeping the PyPy condition does not establish PyPy runtime support.

No optional extras are enabled: this does not install `uvicorn[standard]`,
`starlette[full]`, HTTP/2, SOCKS, alternative event loops, or build toolchains.
The test environment's unrelated `PyYAML` installation is not a dependency of
these base profiles and is not included.

Each pin records SHA256 hashes for **all non-yanked official wheels** listed by
its exact PyPI release at generation time: 154 client hashes and three further
server hashes. Source distributions are excluded. Every package block links
to its version-specific official PyPI JSON metadata, which supplies dependency
metadata, filenames and artifact digests. For example:
[cryptography 50.0.1 metadata](https://pypi.org/pypi/cryptography/50.0.1/json),
[anyio 4.14.2 metadata](https://pypi.org/pypi/anyio/4.14.2/json), and
[exceptiongroup 1.3.1 metadata](https://pypi.org/pypi/exceptiongroup/1.3.1/json).

## Python and platform coverage

The intended optional-network lock range is **CPython 3.10 through 3.14** on
ordinary, non-free-threaded builds. Its reviewed wheel targets are:

- macOS 11 or newer on ARM64;
- Linux x86_64 and ARM64 with a compatible manylinux/glibc or musllinux wheel;
- Windows x64 (`win_amd64`).

For the selected releases, the Linux checks used glibc 2.17-compatible and
musl 1.2-compatible tags. These describe wheel selection, not proof that every
distribution or operating system release works.

The official `cryptography==50.0.1` release currently has no macOS Intel,
Windows ARM64, or Windows 32-bit wheel. The wheel-only locks therefore cannot
install on those targets; they fail rather than compile source silently.
Other architectures, PyPy, free-threaded Python, and Python outside the stated
range have no support claim here, even when an allowed hash happens to cover
an artifact for them. Requirements files do not enforce an upper Python
version bound. See the release's
[official artifact list](https://pypi.org/project/cryptography/50.0.1/#files).

**No cross-platform execution certification is implied.** The runtime already
used for synthetic checks was CPython **3.12.0b4** on macOS ARM64, with pip
23.1.2. It is a prerelease interpreter, not evidence for a stable Python 3.12
deployment. Both locks also passed resolution-only dry-runs under the existing
stable CPython **3.11.4** interpreter with pip 23.1.2 on macOS ARM64. This did
not install packages or run the network suite under that interpreter;
stable-interpreter execution and real-host acceptance remain separate gates.

During later package preparation, both locks were installed into separate new
CPython 3.11.4 virtual environments on macOS ARM64 using the full unmodified
locks, required hashes and wheel-only mode. The server environment then passed
23 targeted network, native-entry and selected memory regression tests with
no failures/errors/skips. The client environment contains no server packages.
This is local execution evidence, not cross-platform or real-host certification.

## Reproduce resolution without installing

From the source root, use the interpreter in the explicitly chosen environment:

```sh
python -m pip --isolated --disable-pip-version-check --no-cache-dir install --dry-run --ignore-installed --only-binary=:all: --require-hashes --index-url https://pypi.org/simple -r requirements-network-lock.txt
python -m pip --isolated --disable-pip-version-check --no-cache-dir install --dry-run --ignore-installed --only-binary=:all: --require-hashes --index-url https://pypi.org/simple -r requirements-network-server-lock.txt
```

`--ignore-installed` ensures that already installed packages do not hide a
missing pin or hash. `--dry-run` does not install them. Downloads and metadata
checks still require network access unless an approved wheelhouse is used.
TLS certificate validation must stay enabled.

For a wheelhouse, choose a new private destination and use the appropriate
lock on the actual target interpreter and OS:

```sh
python -m pip --isolated --disable-pip-version-check download --only-binary=:all: --require-hashes --index-url https://pypi.org/simple --dest /absolute/private/network-wheelhouse -r requirements-network-server-lock.txt
```

After explicit deployment authorization, use the selected virtual environment
and that same lock. An offline installation can use `--no-index --find-links`
with the reviewed wheelhouse. No installation, runtime upgrade or source build
was performed while preparing these locks.

Hash-checking requires pinned hashes for the full dependency closure, and
wheel-only mode excludes source build execution. Both controls follow
[pip's secure installation guidance](https://pip.pypa.io/en/stable/topics/secure-installs/).
They do not audit the downloaded package's behavior.

## Validation performed for this snapshot

1. Fetched metadata for all 15 exact Python releases from official PyPI over
   verified HTTPS. Every allowed digest came from a non-yanked wheel; no
   source archive hash or private index was added.
2. Ran both complete pip dry-runs on macOS ARM64 under CPython 3.12.0b4 and
   stable CPython 3.11.4, ignoring installed packages. All four dry-runs passed:
   the client selected 11 distributions and the server selected 14 on each
   interpreter, with required hashes and wheel-only mode. Download URLs in the
   reports pointed to the official `files.pythonhosted.org` artifact host.
3. Evaluated dependency constraints and environment markers for CPython
   3.10, 3.11, 3.12, 3.13 and 3.14 across six platform profiles: macOS ARM64,
   manylinux x86_64/ARM64, musllinux x86_64/ARM64, and Windows x64. All **30
   metadata cases** had a complete, version-compatible dependency closure.
4. Materialized the marker-selected server closure for the six cases below,
   downloaded its wheels, checked each file's SHA256 against official metadata,
   and inspected each wheel's `METADATA` for version and recursive dependency
   constraints. No wheel was imported or executed by these download checks.
5. Used a temporary requirement with an intentionally incorrect SHA256 against
   a downloaded wheel. Pip rejected it with a hash mismatch and nonzero exit
   status; no installation occurred.

| Target used for artifact download | Wheel count | Result |
| --- | ---: | --- |
| CPython 3.10, Windows x64 | 15 | Download, SHA256 and wheel metadata passed |
| CPython 3.10, manylinux 2.17 x86_64 | 15 | Download, SHA256 and wheel metadata passed |
| CPython 3.12, macOS 11 ARM64 | 14 | Download, SHA256 and wheel metadata passed |
| CPython 3.14, manylinux 2.17 ARM64 | 13 | Download, SHA256 and wheel metadata passed |
| CPython 3.14, musllinux 1.2 x86_64 | 13 | Download, SHA256 and wheel metadata passed |
| CPython 3.14, Windows x64 | 13 | Download, SHA256 and wheel metadata passed |

Cross-target download used explicit `--implementation cp`, `--python-version`,
`--abi`, `--platform`, `--only-binary=:all:` and `--require-hashes`. Requirements
were first selected using the target's marker environment, then downloaded
with `--no-deps`; wheel metadata was independently checked for closure.
Simply giving pip a target wheel tag does not substitute for validating
Python-version-dependent requirement markers. To reproduce installation
acceptance, run the full unmodified lock with the actual target interpreter;
the table above records artifact checks only.

## TypeScript fixture lock

The fixture's `package-lock.json` was generated with npm 10.9.3 using
`--package-lock-only --ignore-scripts --no-audit --no-fund` in a private temporary
directory. It resolves only `jose@6.2.10` from `registry.npmjs.org`; that release
has no recursive runtime dependencies. No `node_modules` directory was created.

The official tarball was downloaded and inspected in memory without unpacking
files or executing package code. Its SHA512 matched npm's recorded integrity
and its package metadata confirmed the version. Its additional SHA256 is:

```text
6a081a81561122e7184ed7ec956d02441c0a568e2fb33209247c070dad12a136
```

Sources: [official npm release metadata](https://registry.npmjs.org/jose/6.2.10)
and [official tarball](https://registry.npmjs.org/jose/-/jose-6.2.10.tgz).
The available Node executable was 22.19.0. Generating this lock does not prove
the interoperability fixture ran, nor that every Node release supports it.

For an explicitly approved fixture environment, `npm ci --ignore-scripts
--no-audit --no-fund --registry=https://registry.npmjs.org` consumes the lock.
The package is separate from the Python client and server profiles.

The independent endpoint's lock pins the same artifact and integrity. Its
development-only static check used an isolated TypeScript 5.9.3 compiler,
`@types/node` 22.18.6 and `undici-types` 6.21.0, each checked against official
npm integrity metadata. That private compiler installation is not distributed
or added to ordinary endpoint runtime dependencies. Runtime and storage
platform limits are recorded in [the endpoint guide](NETWORK_TYPESCRIPT.md).

## Updates and remaining risks

- A digest pins downloaded bytes; it is not an independent audit, author
  identity attestation, vulnerability scan, or guarantee of continued security.
  This preparation did not verify PyPI/npm provenance attestations.
- Locks do not update themselves. A dependency security update requires an
  explicit version change, fresh official artifact hashes, full recursive
  marker resolution, and the relevant crypto/network regression tests.
- New artifacts later published under the same release are not automatically
  trusted; update the reviewed hash set before allowing a newly supported tag.
- Preserve compatibility declarations separately. Do not replace the old
  integration version range merely to match this optional lock snapshot.
- Pip, Python, Node, TLS trust roots, and operating-system libraries are not
  provisioned or locked by these files. Record and validate the deployment
  runtime independently, including a stable Python build.
- Cross-platform downloads and metadata checks do not replace actual tests on
  macOS, Linux and Windows, real-model interoperability, or security review.
