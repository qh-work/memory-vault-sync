from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = (
    PLUGIN_ROOT / "scripts" / "memory_vault_runtime" / "core.py"
)
SPEC = importlib.util.spec_from_file_location("memory_vault_sync_redirects", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
vault_sync = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = vault_sync
SPEC.loader.exec_module(vault_sync)


class RedirectPolicyTests(unittest.TestCase):
    def test_git_transport_disables_implicit_redirects(self) -> None:
        config = vault_sync.default_config()
        with tempfile.TemporaryDirectory() as temporary:
            prefix = vault_sync.GitVault(config, Path(temporary))._git_prefix()
        self.assertIn("http.followRedirects=false", prefix)

    def test_same_origin_redirect_keeps_authorization(self) -> None:
        request = vault_sync.urllib.request.Request(
            "https://www.googleapis.com/drive/v3/files",
            headers={"Authorization": "Bearer test-token"},
        )
        redirected = vault_sync._PolicyRedirectHandler(
            vault_sync.GOOGLE_DRIVE_API_POLICY
        ).redirect_request(request, None, 302, "Found", "/drive/v3/files?next=1")
        self.assertEqual(
            redirected.full_url,
            "https://www.googleapis.com/drive/v3/files?next=1",
        )
        self.assertEqual(
            redirected.get_header("Authorization"),
            "Bearer test-token",
        )

    def test_approved_google_media_redirect_is_allowed_without_auth_leak(self) -> None:
        request = vault_sync.urllib.request.Request(
            "https://www.googleapis.com/drive/v3/files/file-1?alt=media",
            headers={"Authorization": "Bearer test-token"},
        )
        redirected = vault_sync._PolicyRedirectHandler(
            vault_sync.GOOGLE_DRIVE_MEDIA_POLICY
        ).redirect_request(
            request,
            None,
            302,
            "Found",
            "https://drive.usercontent.google.com/download?id=file-1",
        )
        self.assertEqual(
            redirected.host,
            "drive.usercontent.google.com",
        )
        self.assertIsNone(redirected.get_header("Authorization"))

    def test_foreign_host_redirect_is_rejected(self) -> None:
        request = vault_sync.urllib.request.Request(
            "https://api.github.com/repos/qh-work/memory-vault-sync",
            headers={"Authorization": "Bearer test-token"},
        )
        with self.assertRaises(vault_sync.PrivacyError):
            vault_sync._PolicyRedirectHandler(
                vault_sync.GITHUB_API_POLICY
            ).redirect_request(
                request,
                None,
                302,
                "Found",
                "https://evil.example.invalid/steal",
            )

    def test_https_downgrade_is_rejected(self) -> None:
        request = vault_sync.urllib.request.Request(
            "https://oauth2.googleapis.com/token",
        )
        with self.assertRaises(vault_sync.PrivacyError):
            vault_sync._PolicyRedirectHandler(
                vault_sync.GOOGLE_OAUTH_POLICY
            ).redirect_request(
                request,
                None,
                302,
                "Found",
                "http://oauth2.googleapis.com/token",
            )

    def test_redirect_loop_is_rejected(self) -> None:
        target = "https://www.googleapis.com/drive/v3/files?loop=1"
        request = vault_sync.urllib.request.Request(
            "https://www.googleapis.com/drive/v3/files",
        )
        request.redirect_dict = {target: 1}
        with self.assertRaises(vault_sync.VerificationError):
            vault_sync._PolicyRedirectHandler(
                vault_sync.GOOGLE_DRIVE_API_POLICY
            ).redirect_request(request, None, 302, "Found", target)

    def test_unapproved_resumable_location_is_rejected_before_upload_bytes(self) -> None:
        config = vault_sync.default_config()
        profile = vault_sync._provider_profile(config)
        store = profile["object_stores"][0]
        config["adapter_configs"][store["adapter_config_ref"]].update(
            {
                "root_folder_id": "root-private",
                "oauth_client_id": "client-id",
            }
        )
        vault_sync._refresh_provider_scope_fingerprints(config)
        adapter = vault_sync.GoogleDriveAdapter(config)
        adapter.assert_private = mock.Mock()
        adapter.find_verified = mock.Mock(return_value=None)
        adapter._request = mock.Mock(
            return_value=(
                200,
                {"Location": "https://evil.example.invalid/upload"},
                b"",
            )
        )
        adapter._access_token = mock.Mock(
            side_effect=AssertionError("token must not be used")
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "artifact.bin"
            path.write_bytes(b"artifact")
            with self.assertRaises(vault_sync.VerificationError):
                adapter.upload_and_verify(
                    path,
                    vault_sync.sha256_bytes(b"artifact"),
                    len(b"artifact"),
                    "application/octet-stream",
                )
        adapter._access_token.assert_not_called()

    def test_drive_root_privacy_check_is_cached_per_adapter(self) -> None:
        config = vault_sync.default_config()
        profile = vault_sync._provider_profile(config)
        store = profile["object_stores"][0]
        config["adapter_configs"][store["adapter_config_ref"]].update(
            {
                "root_folder_id": "root-private",
                "oauth_client_id": "client-id",
            }
        )
        vault_sync._refresh_provider_scope_fingerprints(config)
        adapter = vault_sync.GoogleDriveAdapter(config)
        calls: list[str] = []

        def json_request(url: str, **_: object) -> dict[str, object]:
            calls.append(url)
            if "/permissions?" in url:
                return {
                    "permissions": [
                        {
                            "type": "user",
                            "role": "owner",
                            "deleted": False,
                        }
                    ]
                }
            return {
                "id": "root-private",
                "trashed": False,
                "mimeType": "application/vnd.google-apps.folder",
            }

        adapter._json_request = mock.Mock(side_effect=json_request)
        adapter.assert_private()
        adapter.assert_private()
        self.assertEqual(len(calls), 2)

    def test_drive_verified_lookup_is_cached_per_adapter(self) -> None:
        config = vault_sync.default_config()
        profile = vault_sync._provider_profile(config)
        store = profile["object_stores"][0]
        config["adapter_configs"][store["adapter_config_ref"]].update(
            {
                "root_folder_id": "root-private",
                "oauth_client_id": "client-id",
            }
        )
        vault_sync._refresh_provider_scope_fingerprints(config)
        adapter = vault_sync.GoogleDriveAdapter(config)
        verified = vault_sync.VerifiedDriveObject(
            store_id=vault_sync.DEFAULT_OBJECT_STORE_ID,
            driver="google-drive-v3",
            file_id="file-1",
            parent_id="root-private",
            sha256="a" * 64,
            size=1,
            mime_type="application/octet-stream",
            verification_level="drive-native-sha256",
        )
        adapter.assert_private = mock.Mock()
        adapter._lookup = mock.Mock(return_value=[{"id": "file-1"}])
        adapter._verify_metadata = mock.Mock(return_value=verified)
        first = adapter.find_verified(
            verified.sha256,
            verified.size,
            verified.mime_type,
        )
        second = adapter.find_verified(
            verified.sha256,
            verified.size,
            verified.mime_type,
        )
        self.assertEqual(first, verified)
        self.assertEqual(second, verified)
        adapter._lookup.assert_called_once_with(verified.sha256)


if __name__ == "__main__":
    unittest.main()
