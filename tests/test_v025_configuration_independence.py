"""Synthetic lazy-configuration regression cases; written, NOT executed here.

Fixtures contain no real memories or credentials. Operator storage/network
effects are replaced with mocks. These cases check routing/contract boundaries,
not live hosts, production encryption or successful restoration of real data.
"""

from __future__ import annotations

import argparse
from collections import UserDict
import io
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import memory_vault as core
import memory_vault_client as client


REQUEST_ID = "req_synthetic_capability_01"
CAPABILITIES = {"op": "capabilities", "schema_version": core.REQUEST_SCHEMA, "request_id": REQUEST_ID}


class StatelessCoreTests(unittest.TestCase):
    def test_capability_response_never_selects_a_vault_and_echoes_request_id(self) -> None:
        with mock.patch.object(core, "default_vault_path", side_effect=AssertionError("No default Vault")), \
                mock.patch.object(core, "Vault", side_effect=AssertionError("No Vault construction")):
            response = core.capability_response(CAPABILITIES)
        self.assertTrue(response["ok"])
        self.assertEqual(response["request_id"], REQUEST_ID)
        self.assertEqual(response["result"], core.capability_result())

    def test_capability_response_rejects_unknown_fields_and_versions(self) -> None:
        for request, code in (({**CAPABILITIES, "ignored": True}, "invalid_shape"),
                              ({**CAPABILITIES, "schema_version": "future/v999"}, "unsupported_request_schema"),
                              ({**CAPABILITIES, "op": "status"}, "invalid_operation")):
            with self.subTest(code=code):
                response = core.capability_response(request)
                self.assertFalse(response["ok"])
                self.assertEqual(response["error"]["code"], code)
                self.assertEqual(response["request_id"], REQUEST_ID)

    def test_discovery_keeps_tree_depth_node_number_and_text_checks(self) -> None:
        deep = "synthetic"
        for _ in range(core.MAX_TREE_DEPTH + 1):
            deep = [deep]
        cases = ((deep, "structure_too_large"), ([0] * core.MAX_TREE_NODES, "structure_too_large"),
                 (1.5, "floating_point_forbidden"), (2**63, "integer_out_of_range"),
                 ("\x00", "invalid_text"), ("x" * (core.MAX_TEXT_BYTES + 1), "invalid_text"))
        for value, code in cases:
            with self.subTest(code=code):
                response = core.capability_response({**CAPABILITIES, "unknown": value})
                self.assertEqual(response["error"]["code"], code)
                self.assertEqual(response["request_id"], REQUEST_ID)

    def test_invalid_request_ids_are_never_echoed(self) -> None:
        for request_id in (True, 42, "invalid-id", "req_short", "req_" + "a" * 97):
            with self.subTest(identifier=request_id):
                response = core.capability_response({**CAPABILITIES, "request_id": request_id})
                self.assertEqual(response["error"]["code"], "invalid_request_id")
                self.assertNotIn("request_id", response)

    def test_vault_handle_and_stateless_discovery_share_validation(self) -> None:
        # No constructor/path/state is needed for this stateless branch.
        vault = object.__new__(core.Vault)
        with mock.patch.object(core.Vault, "_connect", side_effect=AssertionError("No database")):
            for request in (CAPABILITIES, {**CAPABILITIES, "unknown": True},
                            {**CAPABILITIES, "schema_version": "wrong/v1"}):
                self.assertEqual(vault.handle(request), core.capability_response(request))

    def test_core_single_request_cli_is_stateless_for_capabilities(self) -> None:
        with mock.patch.object(core, "read_request", return_value=CAPABILITIES), \
                mock.patch.object(core, "Vault", side_effect=AssertionError("No Vault")), \
                mock.patch.object(core, "write_response") as output:
            self.assertEqual(core.main(["--vault", "invalid-relative-path"]), 0)
        self.assertTrue(output.call_args.args[0]["ok"])
        self.assertEqual(output.call_args.args[0]["request_id"], REQUEST_ID)

    def test_core_stream_can_self_describe_without_any_vault(self) -> None:
        source = types.SimpleNamespace(buffer=io.BytesIO(core.canonical_bytes(CAPABILITIES) + b"\n"))
        with mock.patch.object(core.sys, "stdin", source), \
                mock.patch.object(core, "Vault", side_effect=AssertionError("No Vault")), \
                mock.patch.object(core, "write_response") as output:
            self.assertEqual(core.main(["--serve", "--vault", "invalid-relative-path"]), 0)
        self.assertTrue(output.call_args.args[0]["ok"])

    def test_core_stream_selects_one_vault_only_on_first_data_operation(self) -> None:
        requests = [CAPABILITIES, {"op": "status"}, {"op": "status"}]
        source = types.SimpleNamespace(buffer=io.BytesIO(b"".join(core.canonical_bytes(item) + b"\n" for item in requests)))
        selected = mock.Mock()
        selected.handle.return_value = core.success({"state": "synthetic"})
        with mock.patch.object(core.sys, "stdin", source), \
                mock.patch.object(core, "Vault", return_value=selected) as constructor, \
                mock.patch.object(core, "write_response"):
            self.assertEqual(core.serve(), 0)
        constructor.assert_called_once_with(None)
        self.assertEqual(selected.handle.call_args_list, [mock.call({"op": "status"}), mock.call({"op": "status"})])


class ClientConfigurationTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.path = self.root / "synthetic-client.json"

    def test_configured_protocol_capabilities_do_not_load_config_or_default_vault(self) -> None:
        with mock.patch.object(client, "default_config_path", side_effect=AssertionError("No default config")), \
                mock.patch.object(client.ClientConfig, "load", side_effect=AssertionError("No config read")), \
                mock.patch.object(core, "Vault", side_effect=AssertionError("No Vault")):
            response = client.protocol_request(None, CAPABILITIES)
        self.assertEqual(response, core.capability_response(CAPABILITIES))
        self.assertEqual(list(self.root.iterdir()), [])

    def test_configured_protocol_still_validates_unknown_capability_fields(self) -> None:
        with mock.patch.object(client.ClientConfig, "load", side_effect=AssertionError("No config")):
            response = client.protocol_request(Path("invalid-relative"), {**CAPABILITIES, "authority": "execute"})
        self.assertEqual(response["error"]["code"], "invalid_shape")
        self.assertEqual(response["request_id"], REQUEST_ID)

    def test_client_protocol_cli_does_not_eagerly_resolve_config(self) -> None:
        with mock.patch.object(client, "default_config_path", side_effect=AssertionError("No default config")), \
                mock.patch.object(client, "read_request", return_value=CAPABILITIES), \
                mock.patch.object(client, "write_response") as output:
            self.assertEqual(client.main(["protocol"]), 0)
        self.assertEqual(output.call_args.args[0], core.capability_response(CAPABILITIES))

    def test_mcp_cli_can_self_describe_before_selecting_configuration(self) -> None:
        captured = []
        def describe(server):
            captured.append(server.call("memory_capabilities", {}))
            return 0
        with mock.patch.object(client, "default_config_path", side_effect=AssertionError("No default config")), \
                mock.patch.object(client.ClientConfig, "load", side_effect=AssertionError("No config")), \
                mock.patch.object(client.MCPServer, "serve", autospec=True, side_effect=describe):
            self.assertEqual(client.main(["mcp"]), 0)
        self.assertTrue(captured[0]["ok"])

    def test_mcp_pins_default_path_on_first_data_tool_but_reloads_current_config(self) -> None:
        server = client.MCPServer()
        config = mock.Mock()
        with mock.patch.object(client, "default_config_path", return_value=self.path) as default, \
                mock.patch.object(client.ClientConfig, "load", return_value=config) as load, \
                mock.patch.object(client, "_read_operation", return_value=core.success({})), \
                mock.patch.object(client, "client_health", return_value={}):
            server.call("memory_capabilities", {})
            default.assert_not_called()
            load.assert_not_called()
            server.call("memory_status", {})
            server.call("memory_status", {})
        default.assert_called_once_with()
        self.assertEqual(load.call_args_list, [mock.call(self.path), mock.call(self.path)])

    def test_mcp_data_operation_fails_closed_when_default_configuration_is_invalid(self) -> None:
        server = client.MCPServer()
        with mock.patch.object(client, "default_config_path", side_effect=core.MemoryError("invalid_client_config")), \
                mock.patch.object(client.ClientConfig, "load") as load, \
                mock.patch.object(core, "Vault", side_effect=AssertionError("No alternate Vault")):
            with self.assertRaises(core.MemoryError) as raised:
                server.call("memory_status", {})
        self.assertEqual(raised.exception.code, "invalid_client_config")
        load.assert_not_called()

    def test_protocol_stream_pins_default_only_when_a_data_request_arrives(self) -> None:
        requests = [CAPABILITIES, {"op": "status"}, {"op": "status"}]
        source = types.SimpleNamespace(buffer=io.BytesIO(b"".join(core.canonical_bytes(item) + b"\n" for item in requests)))
        config = mock.Mock()
        config.vault.return_value.handle.return_value = core.success({})
        args = argparse.Namespace(accept_unsigned=False, import_path=None, export_path=None, serve=True)
        with mock.patch.object(client.sys, "stdin", source), \
                mock.patch.object(client, "default_config_path", return_value=self.path) as default, \
                mock.patch.object(client.ClientConfig, "load", return_value=config) as load, \
                mock.patch.object(client, "write_response") as output:
            self.assertEqual(client.run_protocol(args, None), 0)
        default.assert_called_once_with()
        self.assertEqual(load.call_args_list, [mock.call(self.path), mock.call(self.path)])
        self.assertEqual(output.call_args_list[0].args[0], core.capability_response(CAPABILITIES))

    def test_explicit_mapping_write_keeps_selected_signer_boundary(self) -> None:
        config = mock.Mock()
        config.vault.return_value.handle.return_value = core.success({"memory_id": "mem_" + "a" * 40})
        request = UserDict({"op": "remember", "request_id": "req_synthetic_write_01", "kind": "fact", "text": "Synthetic"})
        with mock.patch.object(client, "default_config_path", side_effect=AssertionError("No alternative config")), \
                mock.patch.object(client.ClientConfig, "load", return_value=config) as load, \
                mock.patch.object(client, "notify_sync", return_value={}) as notify:
            response = client.protocol_request(self.path, request)
        self.assertTrue(response["ok"])
        load.assert_called_once_with(self.path)
        config.vault.assert_called_once_with(writing=True)
        config.vault.return_value.handle.assert_called_once_with(request)
        notify.assert_called_once_with(config, "memory-write")

    def test_independent_operator_routes_never_select_client_configuration(self) -> None:
        routes = {"update": "memory_vault_update", "install": "memory_vault_install", "pack": "memory_vault_pack",
                  "device-trust": "memory_vault_device_trust", "envelope": "memory_vault_crypto"}
        for command, module_name in routes.items():
            with self.subTest(command=command):
                module = types.ModuleType(module_name)
                module.main = mock.Mock(return_value=23)
                with mock.patch.dict(sys.modules, {module_name: module}), \
                        mock.patch.object(client, "default_config_path", side_effect=AssertionError("No config")):
                    self.assertEqual(client.main([command, "--help"]), 23)
                module.main.assert_called_once_with(["--help"])

    def test_operator_routes_receive_only_explicit_client_selection(self) -> None:
        routes = {"manage": "memory_vault_manage", "share": "memory_vault_sharing", "legacy-pack": "memory_vault_legacy_pack",
                  "host": "memory_vault_hosts", "compat": "memory_vault_compat"}
        for command, module_name in routes.items():
            with self.subTest(command=command):
                module = types.ModuleType(module_name)
                module.main = mock.Mock(return_value=0)
                with mock.patch.dict(sys.modules, {module_name: module}), \
                        mock.patch.object(client, "default_config_path", side_effect=AssertionError("No default config")):
                    self.assertEqual(client.main([command, "--help"]), 0)
                    self.assertEqual(client.main(["--config", str(self.path), command, "--help"]), 0)
                self.assertEqual(module.main.call_args_list,
                                 [mock.call(["--help"], config_path=None), mock.call(["--help"], config_path=self.path)])

    def test_manage_restore_through_client_does_not_need_original_configuration(self) -> None:
        import memory_vault_backup as backup
        import memory_vault_manage as manage
        source, destination = self.root / "synthetic-backup", self.root / "synthetic-new.sqlite3"
        with mock.patch.object(client, "default_config_path", side_effect=AssertionError("No original config")), \
                mock.patch.object(backup, "restore_database", return_value={"state": "synthetic_restore"}) as restore, \
                mock.patch.object(manage, "write_response"):
            self.assertEqual(client.main(["manage", "restore", "--backup", str(source), "--output", str(destination)]), 0)
        restore.assert_called_once_with(source, destination, trust_store=None, accept_unsigned=False, timeout=60)

    def test_capture_route_still_requires_its_selected_configuration(self) -> None:
        with mock.patch.object(client, "default_config_path", return_value=self.path), \
                mock.patch.object(client.ClientConfig, "load", side_effect=core.MemoryError("client_not_configured")) as load, \
                mock.patch.object(client, "handle_hook", side_effect=AssertionError("No unconfigured capture")), \
                mock.patch.object(client, "_emit") as output:
            self.assertEqual(client.main(["hook", "stop"]), 0)
        load.assert_called_once_with(self.path)
        self.assertIn("client_not_configured", str(output.call_args.args[0]))


class LazyStoreOperatorTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.config = self.root / "synthetic-client.json"
        self.source = self.root / "synthetic-source"

    def test_share_verify_does_not_resolve_default_configuration(self) -> None:
        import memory_vault_sharing as sharing
        metadata = mock.Mock()
        metadata.as_dict.return_value = {"state": "synthetic_verified"}
        with mock.patch.object(client, "default_config_path", side_effect=AssertionError("No store needed")), \
                mock.patch.object(sharing, "verify_share_bundle", return_value=metadata), \
                mock.patch.object(sharing, "write_response"):
            self.assertEqual(sharing.main(["verify", "--source", str(self.source)]), 0)

    def test_share_read_write_operations_still_select_default_when_needed(self) -> None:
        import memory_vault_sharing as sharing
        import memory_vault_update as update
        for action in ("review", "export", "import"):
            with self.subTest(action=action):
                arguments = [action, "--source" if action == "import" else "--selector", str(self.source)]
                if action == "export":
                    arguments += ["--out", str(self.root / "synthetic-output")]
                with mock.patch.object(client, "default_config_path", return_value=self.config) as default, \
                        mock.patch.object(update, "read_file", return_value=b"{}"), \
                        mock.patch.object(sharing, "parse_selector", return_value={}), \
                        mock.patch.object(sharing, "export_share", return_value={}) as export, \
                        mock.patch.object(sharing, "import_share", return_value={}) as receive, \
                        mock.patch.object(sharing, "write_response"):
                    self.assertEqual(sharing.main(arguments), 0)
                default.assert_called_once_with()
                self.assertEqual((receive if action == "import" else export).call_args.args[0], self.config)

    def test_legacy_verification_does_not_resolve_default_configuration(self) -> None:
        import memory_vault_legacy_pack as legacy_pack
        with mock.patch.object(client, "default_config_path", side_effect=AssertionError("No store needed")), \
                mock.patch.object(legacy_pack, "verify", return_value={}), mock.patch("builtins.print"):
            self.assertEqual(legacy_pack.main(["verify", "--source", str(self.source)]), 0)

    def test_legacy_alias_registration_retains_default_and_explicit_selection(self) -> None:
        import memory_vault_legacy_pack as legacy_pack
        explicit = self.root / "explicit-client.json"
        arguments = ["register-aliases", "--source", str(self.source)]
        with mock.patch.object(client, "default_config_path", return_value=self.config) as default, \
                mock.patch.object(legacy_pack, "register_aliases", return_value={}) as register, mock.patch("builtins.print"):
            self.assertEqual(legacy_pack.main(arguments), 0)
            self.assertEqual(legacy_pack.main(arguments, config_path=explicit), 0)
        default.assert_called_once_with()
        self.assertEqual(register.call_args_list, [mock.call(self.source, self.config, part=1), mock.call(self.source, explicit, part=1)])


if __name__ == "__main__":
    unittest.main()
