"""One bounded source-gate smoke test, using a new synthetic local Git repo.

No application imports, credentials, user Git configuration, network, private
memory, installation or release publishing. This is not the full test suite.
"""

from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts.release_source import ReleaseSource, SourceError, git_environment


class ReleaseSourceGateTests(unittest.TestCase):
    def test_only_current_committed_public_sources_are_accepted(self) -> None:
        with tempfile.TemporaryDirectory(prefix="synthetic-release-source-") as temporary:
            root = Path(temporary).resolve()

            def git(*arguments: str) -> str:
                result = subprocess.run(
                    ["git", "-C", str(root), "-c", "user.name=Synthetic Fixture",
                     "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false",
                     "-c", "core.hooksPath=" + str(root / "unused-hooks"), *arguments],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    env=git_environment(), timeout=15, check=True,
                )
                return result.stdout.decode("utf-8").strip()

            git("init", "--quiet")
            fixtures = {
                ".gitignore": b"*.private.ndjson\n",
                "README.md": b"Synthetic repository only.\n",
                "schemas/public.json": b'{"synthetic":1}\n',
                "examples/protocol/public.ndjson": b'{"synthetic":true}\n',
                "adapters/public.md": b"Synthetic adapter.\n",
                "tests/test_v025_public.py": b"SYNTHETIC = True\n",
            }
            for name, data in fixtures.items():
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            git("add", "--", *fixtures)
            git("commit", "--quiet", "-m", "Synthetic source fixture")
            prior = git("rev-parse", "HEAD")
            git("commit", "--quiet", "--allow-empty", "-m", "Synthetic current head")
            head = git("rev-parse", "HEAD")

            with self.subTest(case="wrong_existing_commit"):
                with self.assertRaisesRegex(SourceError, "release_source_commit_not_current_head"):
                    ReleaseSource(root, prior)

            selected = [root / name for name in fixtures if name not in {"README.md", ".gitignore"}]
            source = ReleaseSource(root, head)
            with self.subTest(case="clean_declared_sources"):
                self.assertEqual(source.commit, head)
                for path in selected:
                    self.assertEqual(source.read(path), fixtures[path.relative_to(root).as_posix()])
                source.assert_current()

            with self.subTest(case="unrelated_dirty_file_allowed"):
                (root / "README.md").write_bytes(b"Unrelated synthetic local edit.\n")
                source.assert_current()

            with self.subTest(case="modified_included_file_refused"):
                target = root / "schemas/public.json"
                target.write_bytes(b'{"synthetic":2}\n')  # Same size: byte comparison is required.
                with self.assertRaisesRegex(SourceError, "release_source_changed_input"):
                    source.read(target)
                target.write_bytes(fixtures["schemas/public.json"])

            candidates = (
                ("schemas/untracked.json", "*.json", False),
                ("examples/protocol/ignored.private.ndjson", "*.ndjson", True),
                ("tests/test_v025_untracked.py", "test_v025_*.py", False),
            )
            for relative, pattern, ignored in candidates:
                with self.subTest(case="untracked_matching_glob", ignored=ignored):
                    candidate = root / relative
                    candidate.write_bytes(b"Synthetic unreviewed candidate only.\n")
                    if ignored:
                        self.assertEqual(git("check-ignore", "--", relative), relative)
                    with self.assertRaisesRegex(SourceError, "release_source_untracked_input"):
                        for path in sorted(candidate.parent.glob(pattern)):
                            source.read(path)
                    candidate.unlink()
            source.assert_current()


if __name__ == "__main__":
    unittest.main()
