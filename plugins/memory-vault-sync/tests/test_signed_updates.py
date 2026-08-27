from __future__ import annotations

import argparse
import base64
import copy
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Mapping
from unittest import mock


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_ROOT = PLUGIN_ROOT / "scripts"
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

from memory_vault_runtime import core as vault_sync  # noqa: E402
from memory_vault_runtime import signed_updates  # noqa: E402
from memory_vault_runtime.protocol import (  # noqa: E402
    jcs_json_bytes,
    sha256_bytes,
)


NOW = int(
    dt.datetime(
        2030,
        1,
        1,
        12,
        tzinfo=dt.timezone.utc,
    ).timestamp()
)
ISSUED = "2030-01-01T00:00:00Z"
EXPIRY = {
    "root": "2030-12-31T00:00:00Z",
    "targets": "2030-12-31T00:00:00Z",
    "snapshot": "2030-01-07T00:00:00Z",
    "timestamp": "2030-01-02T00:00:00Z",
}


# Test-only RSA parameters. They have no production authority, are never read
# by the runtime, and intentionally avoid a reusable private-key file format.
TEST_RSA_PARAMETERS = (
    (
        24483793540471599978275845704243003784605213306466773556887885774080865686149510416029522732660546199048325105617414076313518813577844298671255380878740530867437018576797604257169174630899925710322598121388117143765738533772096576112141348658576870021360830351793388856087948509383935198461591708000728289259923149206002099975178078417005124004257236027465659919934378615865151320324614746452127669287976861803230359447108343702285491807733655082520160688910803353869161560063485394631498295346730327545340773139936159510726778581241399556729808381904201473262357519644921633917743116744664057055760861395566642157251,
        7539366120516004076500066255051773187315833952390343731808816741790529783361815000776535365790659975937169064138807596839695487691143564573975080359397937858549315224962272479880542490901191704838798734878520409514264756550569617201262257309286964827518545513672313052240885131572656609856316008654083916040529439414676658592173629658251767402009904672900338066588600180570616263051726316837439451592882606700746387615784602751859935547346104933329251274469431240732438218487389993235324734916182026065640036375946359661168094752948558173198566372115447896540108221366798529491257155871186026216130555519350170940969,
    ),
    (
        28750927128259241962666203877436436682193381552618573705546389090917689023456168127235562084930417245037136788313144086791127290622796801119670651416985465892506733517677827574422886517867877462295103320685464458434053634379511798956928298966242335583721154169214698621824737351958782361806793848077444579308911883644474982474188561741481411885375734010004828317409681474361470826133017628995467683280252350919212597046046804642531704715664995577821525661380642567673811914231358579345546636031832025912006370687372480013843290792461974717706609917857725430528022412363529330424387841543864091755863723583148105403227,
        7749593782454178697079489318933040175640418162671576430237529384791201559414578176718742149172159553131529080756697595147249089657013679170224179582236725132232654036495091690223542278989518216754550866837187079943200901037796602355526472088113140029089433272795179076773944265412696498486610820243344347368447408697112357699112698042784913052046825922688603137753050119876929403642472130367871748923865520633393564259401120834442322882827424661333917138401048058294496159698783366312101822219716966300661847904146731328577452258452971674875957351996476656443435034428741696809225962665364534041670601949729893252993,
    ),
    (
        25716232020026774184436716188278103605059890082195023691070982569740306262189977447295689260445309140169022589609987667275562447918402962051785694936271527792756082246217297987133149386582673778956386708282242383806652091002592580619184930487356011197125399011972600831139464946033280585130308289236016423292276460817096746897381389209287664386061221017876229109631607997167994962201073970017221975902964987279946029036440743674855947406670873036006143773968784660120687549484117755468163892489036630771975474948117731583348952867651349001979838897134286016549963146465122763820483523450273381833515734000806133443117,
        22347149393053463182291765317891058156640764759923231063829341110048982741626583542135538689162164896802813761705271947739605977865953081340483194414080592326857372781853324651192761199250344910284956275438027160232733314535127486135209133408386288565047051270745557317762846455308319920102479322829552334145599752069927301568617847708591512385530902241531616029567764562414777117567824295913027637950158010261640501972846096323719062290144716366790458488316104203529888060608136004800546617471972933142869203856744937307555237637011191938066183755144908100813276140165510884136921978947373908380308686173162479494021,
    ),
    (
        22847100655419421832883618534743367998373043871595436716508907760782936945716854697672625910520546524303914727988016211755184513889652863528152556225485086704290677829701283459982733177300447442917648894906986013032258802667493630365060213849815142222490914237740102311757676098878477775708018515411199465792423695368022066773118605551154361658807137323723601624000354291007553725560883648639474344576669474420835957614620765082062646837825240012230366587605003441953903102918099993269084186395056120829775178147163487688597442856136034707251155968875279360917776165625707545941626263141175371054388751146437933590399,
        11766760584438893222535678721992048767094699937408803812996096306661984386358560761257673411321848830963120585528472636760497778313280331761687798194589287448768226326897896159799764910408196935178592293663052915114787545454261142647845909914594969184365104113194709451588520093465450972175606893063066902190845343337883281543844744015237718812891906309976319634358386339920594652440141057802188110332023286634238219758867452188379496753880472531892293692759965833657277895170424000591196961579824070685930454969629867798110283643969092150802606535768359391377427023573682973357357239506031800227662255749483127935689,
    ),
    (
        26002711171394753763384766847024947814719806677441843227221898491093448510212604333606932602532816889914434858449254969137142555156622459744163396168076908865918291279956051978799134878460146925580604332334265596140683698106293954948638800852680729342761371216299540024788208524714561357193798458843786324960146022520363052674919028452125614317462212306349195317215565779949924694377265198606990906112899342818690344871476616964008841889174739994094288479365176969935045255901849992149843845112746718905624548168865406740041570450411156281114592007806485127429588275624598683031853985093457428680850168616085594908047,
        8378065048677413071511249168283241498018271172022856731098732144253311240088031998847124354716922676464183689686962600184627038080584095395848974983369882777861828259876893870398744710523283984322749608336822746358647435329851887524535101069704232430562111701838367443786377332008982370546473721057500221826626573949871753029573481537599364493417269997474579371706769548108235374885993088641905258384154633499368958754130568833138177081202333909720328833087453485328905534074514139247280509075881791801511892370306821061659225941255082471309998834019897479562255256477223579057881764681282749864103063701013258846081,
    ),
)


def _der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _der_value(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _der_length(len(value)) + value


def _der_integer(value: int) -> bytes:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if raw[0] & 0x80:
        raw = b"\0" + raw
    return _der_value(0x02, raw)


def _public_pem(modulus: int) -> str:
    rsa = _der_value(
        0x30,
        _der_integer(modulus) + _der_integer(65537),
    )
    algorithm = bytes.fromhex("300d06092a864886f70d0101010500")
    spki = _der_value(0x30, algorithm + _der_value(0x03, b"\0" + rsa))
    body = base64.b64encode(spki).decode("ascii")
    lines = [body[offset : offset + 64] for offset in range(0, len(body), 64)]
    return (
        "-----BEGIN PUBLIC KEY-----\n"
        + "\n".join(lines)
        + "\n-----END PUBLIC KEY-----\n"
    )


def _test_key(index: int) -> dict[str, Any]:
    modulus, private_exponent = TEST_RSA_PARAMETERS[index]
    value = {
        "keytype": "rsa",
        "scheme": "rsassa-pss-sha256",
        "keyval": {"public": _public_pem(modulus)},
    }
    return {
        "modulus": modulus,
        "private_exponent": private_exponent,
        "value": value,
        "keyid": signed_updates.key_id(value),
    }


TEST_KEYS = tuple(_test_key(index) for index in range(5))
KEY_INDEX = {item["keyid"]: index for index, item in enumerate(TEST_KEYS)}


def _mgf1(seed: bytes, length: int) -> bytes:
    output = bytearray()
    for counter in range((length + 31) // 32):
        output.extend(
            hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        )
    return bytes(output[:length])


def _sign(index: int, message: bytes) -> str:
    key = TEST_KEYS[index]
    modulus = int(key["modulus"])
    private_exponent = int(key["private_exponent"])
    digest = hashlib.sha256(message).digest()
    salt = hashlib.sha256(
        b"memory-vault-test-only-pss"
        + index.to_bytes(2, "big")
        + message
    ).digest()
    encoded_bits = modulus.bit_length() - 1
    encoded_length = (encoded_bits + 7) // 8
    padding = b"\0" * (encoded_length - 32 - 32 - 2)
    database = padding + b"\x01" + salt
    hashed = hashlib.sha256(b"\0" * 8 + digest + salt).digest()
    masked = bytearray(
        left ^ right
        for left, right in zip(database, _mgf1(hashed, len(database)))
    )
    unused_bits = 8 * encoded_length - encoded_bits
    if unused_bits:
        masked[0] &= 0xFF >> unused_bits
    encoded = bytes(masked) + hashed + b"\xbc"
    signature = pow(
        int.from_bytes(encoded, "big"),
        private_exponent,
        modulus,
    ).to_bytes((modulus.bit_length() + 7) // 8, "big")
    return signature.hex()


def _envelope(
    signed: Mapping[str, Any],
    signers: tuple[int, ...],
) -> dict[str, Any]:
    message = jcs_json_bytes(signed)
    return {
        "signatures": [
            {
                "keyid": TEST_KEYS[index]["keyid"],
                "sig": _sign(index, message),
            }
            for index in signers
        ],
        "signed": dict(signed),
    }


def _default_roles() -> dict[str, tuple[tuple[int, ...], int]]:
    return {
        "root": ((0,), 1),
        "targets": ((1,), 1),
        "snapshot": ((2,), 1),
        "timestamp": ((3,), 1),
    }


def _root(
    *,
    version: int = 1,
    roles: Mapping[str, tuple[tuple[int, ...], int]] | None = None,
    signers: tuple[int, ...] | None = None,
    issued: str = ISSUED,
    expires: str = EXPIRY["root"],
) -> dict[str, Any]:
    selected = dict(roles or _default_roles())
    indices = sorted(
        {
            index
            for key_indices, _threshold in selected.values()
            for index in key_indices
        }
    )
    signed = {
        "_type": "root",
        "spec_version": signed_updates.SPEC_VERSION,
        "version": version,
        "expires": expires,
        "issued_at": issued,
        "consistent_snapshot": False,
        "keys": {
            TEST_KEYS[index]["keyid"]: TEST_KEYS[index]["value"]
            for index in indices
        },
        "roles": {
            role: {
                "keyids": [
                    TEST_KEYS[index]["keyid"] for index in key_indices
                ],
                "threshold": threshold,
            }
            for role, (key_indices, threshold) in selected.items()
        },
    }
    root_signers = signers if signers is not None else selected["root"][0]
    return _envelope(signed, tuple(root_signers))


def _role_signers(
    root: Mapping[str, Any],
    role: str,
) -> tuple[int, ...]:
    return tuple(
        KEY_INDEX[keyid]
        for keyid in root["signed"]["roles"][role]["keyids"]
    )


def _write_chain(
    directory: Path,
    root: Mapping[str, Any],
    *,
    candidate: Mapping[str, Any] | None = None,
    versions: Mapping[str, int] | None = None,
    release_notes: str = "Test-only signed release",
    protocol: tuple[int, int] = (1, 1),
    issued: Mapping[str, str] | None = None,
    expires: Mapping[str, str] | None = None,
    signature_overrides: Mapping[str, tuple[int, ...]] | None = None,
    signed_commit: str | None = None,
) -> dict[str, Any]:
    directory.mkdir(parents=True, exist_ok=True)
    observed = dict(
        candidate
        or {
            "version": "1.0.0",
            "bundle_sha256": "b" * 64,
            "bundle_length": 321,
            "commit_sha": "c" * 40,
        }
    )
    role_versions = {
        "timestamp": 1,
        "snapshot": 1,
        "targets": 1,
        **dict(versions or {}),
    }
    role_issued = {role: ISSUED for role in ("targets", "snapshot", "timestamp")}
    role_issued.update(dict(issued or {}))
    role_expires = {
        role: EXPIRY[role] for role in ("targets", "snapshot", "timestamp")
    }
    role_expires.update(dict(expires or {}))
    overrides = dict(signature_overrides or {})

    targets_signed = {
        "_type": "targets",
        "spec_version": signed_updates.SPEC_VERSION,
        "version": role_versions["targets"],
        "expires": role_expires["targets"],
        "issued_at": role_issued["targets"],
        "targets": {
            signed_updates.TARGET_PATH: {
                "length": observed["bundle_length"],
                "hashes": {"sha256": observed["bundle_sha256"]},
                "custom": {
                    "schema_version": signed_updates.TARGET_CUSTOM_SCHEMA,
                    "plugin_name": vault_sync.PLUGIN_NAME,
                    "plugin_version": observed["version"],
                    "marketplace_commit_sha": (
                        signed_commit or "a" * 40
                    ),
                    "protocol": {
                        "minimum": protocol[0],
                        "maximum": protocol[1],
                    },
                    "release_notes": release_notes,
                },
            }
        },
    }
    targets = _envelope(
        targets_signed,
        overrides.get("targets", _role_signers(root, "targets")),
    )
    targets_raw = signed_updates.metadata_bytes(targets)
    (directory / "targets.json").write_bytes(targets_raw)

    snapshot_signed = {
        "_type": "snapshot",
        "spec_version": signed_updates.SPEC_VERSION,
        "version": role_versions["snapshot"],
        "expires": role_expires["snapshot"],
        "issued_at": role_issued["snapshot"],
        "meta": {
            "targets.json": {
                "version": role_versions["targets"],
                "length": len(targets_raw),
                "hashes": {"sha256": sha256_bytes(targets_raw)},
            }
        },
    }
    snapshot = _envelope(
        snapshot_signed,
        overrides.get("snapshot", _role_signers(root, "snapshot")),
    )
    snapshot_raw = signed_updates.metadata_bytes(snapshot)
    (directory / "snapshot.json").write_bytes(snapshot_raw)

    timestamp_signed = {
        "_type": "timestamp",
        "spec_version": signed_updates.SPEC_VERSION,
        "version": role_versions["timestamp"],
        "expires": role_expires["timestamp"],
        "issued_at": role_issued["timestamp"],
        "meta": {
            "snapshot.json": {
                "version": role_versions["snapshot"],
                "length": len(snapshot_raw),
                "hashes": {"sha256": sha256_bytes(snapshot_raw)},
            }
        },
    }
    timestamp = _envelope(
        timestamp_signed,
        overrides.get("timestamp", _role_signers(root, "timestamp")),
    )
    (directory / "timestamp.json").write_bytes(
        signed_updates.metadata_bytes(timestamp)
    )
    return observed


class SignedUpdateVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="memory-vault-signed-updates-"
        )
        self.root = Path(self.temporary.name)
        self.metadata = self.root / "metadata"
        self.initial_root = _root()
        self.trust = signed_updates.import_trusted_root(
            signed_updates.metadata_bytes(self.initial_root),
            now_epoch=NOW,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_rsa_pss_profile_accepts_valid_and_rejects_tampering(self) -> None:
        message = b"signed update test message"
        public = TEST_KEYS[0]["value"]["keyval"]["public"]
        signature = _sign(0, message)
        modulus, exponent = signed_updates._parse_rsa_public_key(public)
        self.assertEqual(modulus, TEST_KEYS[0]["modulus"])
        self.assertEqual(exponent, 65537)
        self.assertTrue(
            signed_updates._verify_rsa_pss(public, message, signature)
        )
        self.assertFalse(
            signed_updates._verify_rsa_pss(public, message + b"!", signature)
        )
        with self.assertRaises(signed_updates.SignedUpdateError):
            signed_updates._parse_rsa_public_key(public.replace("PUBLIC", "PRIVATE"))
        with self.assertRaises(signed_updates.SignedUpdateError):
            signed_updates._parse_rsa_public_key(public[:-1] + "记\n")

    def test_rsa_pss_verification_cross_checks_openssl(self) -> None:
        openssl = shutil.which("openssl")
        if openssl is None:
            self.skipTest("OpenSSL is unavailable for an independent signature check")
        private_key = self.root / "test-only-key.pem"
        public_key = self.root / "test-only-public.pem"
        message = self.root / "message.bin"
        signature = self.root / "signature.bin"
        message.write_bytes(b"independent RSA-PSS verifier cross-check")
        commands = (
            [
                openssl,
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                str(private_key),
            ],
            [
                openssl,
                "pkey",
                "-in",
                str(private_key),
                "-pubout",
                "-out",
                str(public_key),
            ],
            [
                openssl,
                "dgst",
                "-sha256",
                "-sigopt",
                "rsa_padding_mode:pss",
                "-sigopt",
                "rsa_pss_saltlen:32",
                "-sigopt",
                "rsa_mgf1_md:sha256",
                "-sign",
                str(private_key),
                "-out",
                str(signature),
                str(message),
            ],
        )
        try:
            for command in commands:
                subprocess.run(
                    command,
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=15,
                )
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            self.skipTest("installed OpenSSL lacks the required RSA-PSS interface")
        public = public_key.read_text(encoding="ascii")
        observed_signature = signature.read_bytes().hex()
        self.assertTrue(
            signed_updates._verify_rsa_pss(
                public,
                message.read_bytes(),
                observed_signature,
            )
        )
        self.assertFalse(
            signed_updates._verify_rsa_pss(
                public,
                message.read_bytes() + b"!",
                observed_signature,
            )
        )

    def test_initial_root_requires_self_threshold_and_freshness(self) -> None:
        roles = _default_roles()
        roles["root"] = ((0, 4), 2)
        missing_signature = _root(roles=roles, signers=(0,))
        with self.assertRaises(signed_updates.SignedUpdateError):
            signed_updates.import_trusted_root(
                signed_updates.metadata_bytes(missing_signature),
                now_epoch=NOW,
            )
        valid = _root(roles=roles, signers=(0, 4))
        imported = signed_updates.import_trusted_root(
            signed_updates.metadata_bytes(valid),
            now_epoch=NOW,
        )
        self.assertEqual(imported["trusted_root"]["signed"]["version"], 1)
        expired = _root(expires="2030-01-01T12:00:00Z")
        with self.assertRaises(signed_updates.SignedUpdateError):
            signed_updates.import_trusted_root(
                signed_updates.metadata_bytes(expired),
                now_epoch=NOW,
            )

    def test_complete_chain_binds_bundle_and_persists_floors(self) -> None:
        candidate = _write_chain(self.metadata, self.initial_root)
        verified = signed_updates.verify_update_chain(
            self.metadata,
            self.trust,
            candidate,
            plugin_name=vault_sync.PLUGIN_NAME,
            now_epoch=NOW,
        )
        self.assertEqual(verified["root_rotations"], 0)
        self.assertEqual(
            verified["target"]["bundle_sha256"],
            candidate["bundle_sha256"],
        )
        summary = signed_updates.trust_summary(
            verified["trust_store"],
            now_epoch=NOW,
        )
        self.assertTrue(summary["required"])
        self.assertTrue(summary["valid"])
        self.assertFalse(summary["root_expired"])
        self.assertEqual(summary["metadata_versions"]["targets"], 1)
        self.assertFalse(summary["private_keys_imported"])

    def test_threshold_target_and_protocol_mismatches_fail_closed(self) -> None:
        candidate = _write_chain(
            self.metadata,
            self.initial_root,
            signature_overrides={"timestamp": (0,)},
        )
        with self.assertRaises(signed_updates.SignedUpdateError):
            signed_updates.verify_update_chain(
                self.metadata,
                self.trust,
                candidate,
                plugin_name=vault_sync.PLUGIN_NAME,
                now_epoch=NOW,
            )
        candidate = _write_chain(self.metadata, self.initial_root)
        for changed in (
            {**candidate, "version": "1.0.1"},
            {**candidate, "bundle_sha256": "d" * 64},
            {**candidate, "bundle_length": candidate["bundle_length"] + 1},
        ):
            with self.subTest(changed=changed):
                with self.assertRaises(signed_updates.SignedUpdateError):
                    signed_updates.verify_update_chain(
                        self.metadata,
                        self.trust,
                        changed,
                        plugin_name=vault_sync.PLUGIN_NAME,
                        now_epoch=NOW,
                    )
        incompatible = _write_chain(
            self.metadata,
            self.initial_root,
            protocol=(2, 2),
        )
        with self.assertRaises(signed_updates.SignedUpdateError):
            signed_updates.verify_update_chain(
                self.metadata,
                self.trust,
                incompatible,
                plugin_name=vault_sync.PLUGIN_NAME,
                now_epoch=NOW,
            )

    def test_expiry_future_metadata_and_clock_rollback_are_refused(self) -> None:
        candidate = _write_chain(
            self.metadata,
            self.initial_root,
            expires={"timestamp": "2030-01-01T12:00:00Z"},
        )
        with self.assertRaises(signed_updates.SignedUpdateError):
            signed_updates.verify_update_chain(
                self.metadata,
                self.trust,
                candidate,
                plugin_name=vault_sync.PLUGIN_NAME,
                now_epoch=NOW,
            )
        future = "2030-01-01T12:05:01Z"
        future_expiry = "2030-01-02T12:05:01Z"
        candidate = _write_chain(
            self.metadata,
            self.initial_root,
            issued={"timestamp": future},
            expires={"timestamp": future_expiry},
        )
        with self.assertRaises(signed_updates.SignedUpdateError):
            signed_updates.verify_update_chain(
                self.metadata,
                self.trust,
                candidate,
                plugin_name=vault_sync.PLUGIN_NAME,
                now_epoch=NOW,
            )
        candidate = _write_chain(self.metadata, self.initial_root)
        verified = signed_updates.verify_update_chain(
            self.metadata,
            self.trust,
            candidate,
            plugin_name=vault_sync.PLUGIN_NAME,
            now_epoch=NOW,
        )
        with self.assertRaises(signed_updates.SignedUpdateError):
            signed_updates.verify_update_chain(
                self.metadata,
                verified["trust_store"],
                candidate,
                plugin_name=vault_sync.PLUGIN_NAME,
                now_epoch=NOW - signed_updates.MAX_CLOCK_SKEW_SECONDS - 1,
            )

    def test_metadata_rollback_and_same_version_change_are_refused(self) -> None:
        candidate = _write_chain(
            self.metadata,
            self.initial_root,
            versions={"timestamp": 2, "snapshot": 2, "targets": 2},
        )
        verified = signed_updates.verify_update_chain(
            self.metadata,
            self.trust,
            candidate,
            plugin_name=vault_sync.PLUGIN_NAME,
            now_epoch=NOW,
        )
        rolled_back = _write_chain(self.metadata, self.initial_root)
        with self.assertRaises(signed_updates.SignedUpdateError):
            signed_updates.verify_update_chain(
                self.metadata,
                verified["trust_store"],
                rolled_back,
                plugin_name=vault_sync.PLUGIN_NAME,
                now_epoch=NOW,
            )
        changed = _write_chain(
            self.metadata,
            self.initial_root,
            versions={"timestamp": 3, "snapshot": 3, "targets": 2},
            release_notes="Changed same-version target metadata",
        )
        with self.assertRaises(signed_updates.SignedUpdateError):
            signed_updates.verify_update_chain(
                self.metadata,
                verified["trust_store"],
                changed,
                plugin_name=vault_sync.PLUGIN_NAME,
                now_epoch=NOW,
            )

    def test_root_rotation_needs_old_and_new_signatures_and_keeps_floors(self) -> None:
        candidate = _write_chain(
            self.metadata,
            self.initial_root,
            versions={"timestamp": 5, "snapshot": 5, "targets": 5},
        )
        first = signed_updates.verify_update_chain(
            self.metadata,
            self.trust,
            candidate,
            plugin_name=vault_sync.PLUGIN_NAME,
            now_epoch=NOW,
        )
        rotated_roles = {
            "root": ((4,), 1),
            "targets": ((0,), 1),
            "snapshot": ((2,), 1),
            "timestamp": ((3,), 1),
        }
        rotated = _root(
            version=2,
            roles=rotated_roles,
            signers=(0, 4),
        )
        (self.metadata / "2.root.json").write_bytes(
            signed_updates.metadata_bytes(rotated)
        )
        lower_target = _write_chain(
            self.metadata,
            rotated,
            versions={"timestamp": 6, "snapshot": 6, "targets": 4},
        )
        with self.assertRaises(signed_updates.SignedUpdateError):
            signed_updates.verify_update_chain(
                self.metadata,
                first["trust_store"],
                lower_target,
                plugin_name=vault_sync.PLUGIN_NAME,
                now_epoch=NOW,
            )
        current = _write_chain(
            self.metadata,
            rotated,
            versions={"timestamp": 6, "snapshot": 6, "targets": 6},
        )
        second = signed_updates.verify_update_chain(
            self.metadata,
            first["trust_store"],
            current,
            plugin_name=vault_sync.PLUGIN_NAME,
            now_epoch=NOW,
        )
        self.assertEqual(second["root_rotations"], 1)
        self.assertEqual(second["trust_store"]["trusted_root"]["signed"]["version"], 2)

        for signers in ((0,), (4,)):
            with self.subTest(rotation_signers=signers):
                alternate = self.root / f"rotation-{'-'.join(map(str, signers))}"
                alternate.mkdir()
                invalid = _root(
                    version=2,
                    roles=rotated_roles,
                    signers=signers,
                )
                (alternate / "2.root.json").write_bytes(
                    signed_updates.metadata_bytes(invalid)
                )
                invalid_candidate = _write_chain(alternate, rotated)
                with self.assertRaises(signed_updates.SignedUpdateError):
                    signed_updates.verify_update_chain(
                        alternate,
                        self.trust,
                        invalid_candidate,
                        plugin_name=vault_sync.PLUGIN_NAME,
                        now_epoch=NOW,
                    )

    def test_root_rotation_version_must_be_sequential(self) -> None:
        nonsequential = _root(version=3, signers=(0,))
        self.metadata.mkdir()
        (self.metadata / "2.root.json").write_bytes(
            signed_updates.metadata_bytes(nonsequential)
        )
        candidate = _write_chain(self.metadata, self.initial_root)
        with self.assertRaises(signed_updates.SignedUpdateError):
            signed_updates.verify_update_chain(
                self.metadata,
                self.trust,
                candidate,
                plugin_name=vault_sync.PLUGIN_NAME,
                now_epoch=NOW,
            )

    def test_rotation_allows_expired_intermediate_but_not_future_authority(
        self,
    ) -> None:
        roles_v2 = {
            "root": ((4,), 1),
            "targets": ((0,), 1),
            "snapshot": ((2,), 1),
            "timestamp": ((3,), 1),
        }
        roles_v3 = {
            "root": ((1,), 1),
            "targets": ((0,), 1),
            "snapshot": ((2,), 1),
            "timestamp": ((3,), 1),
        }
        expired_directory = self.root / "expired-intermediate"
        expired_directory.mkdir()
        expired_v2 = _root(
            version=2,
            roles=roles_v2,
            signers=(0, 4),
            issued="2029-01-01T00:00:00Z",
            expires="2029-12-31T00:00:00Z",
        )
        current_v3 = _root(
            version=3,
            roles=roles_v3,
            signers=(4, 1),
        )
        (expired_directory / "2.root.json").write_bytes(
            signed_updates.metadata_bytes(expired_v2)
        )
        (expired_directory / "3.root.json").write_bytes(
            signed_updates.metadata_bytes(current_v3)
        )
        candidate = _write_chain(expired_directory, current_v3)
        verified = signed_updates.verify_update_chain(
            expired_directory,
            self.trust,
            candidate,
            plugin_name=vault_sync.PLUGIN_NAME,
            now_epoch=NOW,
        )
        self.assertEqual(verified["root_rotations"], 2)

        future_directory = self.root / "future-intermediate"
        future_directory.mkdir()
        future_v2 = _root(
            version=2,
            roles=roles_v2,
            signers=(0, 4),
            issued="2030-01-01T12:05:01Z",
            expires="2030-12-31T12:05:01Z",
        )
        (future_directory / "2.root.json").write_bytes(
            signed_updates.metadata_bytes(future_v2)
        )
        (future_directory / "3.root.json").write_bytes(
            signed_updates.metadata_bytes(current_v3)
        )
        future_candidate = _write_chain(future_directory, current_v3)
        with self.assertRaises(signed_updates.SignedUpdateError):
            signed_updates.verify_update_chain(
                future_directory,
                self.trust,
                future_candidate,
                plugin_name=vault_sync.PLUGIN_NAME,
                now_epoch=NOW,
            )

    def test_mix_and_match_noncanonical_and_unsafe_files_are_refused(self) -> None:
        candidate = _write_chain(self.metadata, self.initial_root)
        snapshot = self.metadata / "snapshot.json"
        snapshot.write_bytes(snapshot.read_bytes() + b"\n")
        with self.assertRaises(signed_updates.SignedUpdateError):
            signed_updates.verify_update_chain(
                self.metadata,
                self.trust,
                candidate,
                plugin_name=vault_sync.PLUGIN_NAME,
                now_epoch=NOW,
            )
        pretty_root = (
            json.dumps(self.initial_root, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        with self.assertRaises(signed_updates.SignedUpdateError):
            signed_updates.import_trusted_root(pretty_root, now_epoch=NOW)

        bounded = self.root / "bounded.json"
        bounded.write_bytes(signed_updates.metadata_bytes(self.initial_root))
        hardlink = self.root / "hardlink.json"
        os.link(bounded, hardlink)
        with self.assertRaises(signed_updates.SignedUpdateError):
            signed_updates.read_metadata_file(hardlink)
        symlink = self.root / "symlink.json"
        try:
            symlink.symlink_to(bounded)
        except OSError:
            pass
        else:
            with self.assertRaises(signed_updates.SignedUpdateError):
                signed_updates.read_metadata_file(symlink)
        oversized = self.root / "oversized.json"
        oversized.write_bytes(b"x" * (signed_updates.MAX_METADATA_BYTES + 1))
        with self.assertRaises(signed_updates.SignedUpdateError):
            signed_updates.read_metadata_file(oversized)

    def test_malformed_parent_bound_child_and_display_controls_fail_closed(self) -> None:
        candidate = _write_chain(self.metadata, self.initial_root)
        snapshot_path = self.metadata / "snapshot.json"
        snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
        snapshot_signed = dict(snapshot["signed"])
        del snapshot_signed["version"]
        malformed_snapshot = _envelope(
            snapshot_signed,
            _role_signers(self.initial_root, "snapshot"),
        )
        malformed_raw = signed_updates.metadata_bytes(malformed_snapshot)
        snapshot_path.write_bytes(malformed_raw)
        timestamp_path = self.metadata / "timestamp.json"
        timestamp = json.loads(timestamp_path.read_text(encoding="utf-8"))
        timestamp_signed = copy.deepcopy(timestamp["signed"])
        timestamp_signed["meta"]["snapshot.json"].update(
            {
                "length": len(malformed_raw),
                "hashes": {"sha256": sha256_bytes(malformed_raw)},
            }
        )
        timestamp_path.write_bytes(
            signed_updates.metadata_bytes(
                _envelope(
                    timestamp_signed,
                    _role_signers(self.initial_root, "timestamp"),
                )
            )
        )
        with self.assertRaises(signed_updates.SignedUpdateError):
            signed_updates.verify_update_chain(
                self.metadata,
                self.trust,
                candidate,
                plugin_name=vault_sync.PLUGIN_NAME,
                now_epoch=NOW,
            )
        with self.assertRaises(signed_updates.SignedUpdateError):
            signed_updates._validate_release_notes("safe\u202ereversed")

    def test_trust_store_rejects_partial_or_type_confused_state(self) -> None:
        candidate = _write_chain(self.metadata, self.initial_root)
        verified = signed_updates.verify_update_chain(
            self.metadata,
            self.trust,
            candidate,
            plugin_name=vault_sync.PLUGIN_NAME,
            now_epoch=NOW,
        )
        tampered = copy.deepcopy(verified["trust_store"])
        tampered["last_target"]["bundle_length"] = True
        with self.assertRaises(signed_updates.SignedUpdateError):
            signed_updates.validate_trust_store(tampered)
        incomplete = copy.deepcopy(verified["trust_store"])
        incomplete["last_target"] = None
        with self.assertRaises(signed_updates.SignedUpdateError):
            signed_updates.validate_trust_store(incomplete)
        confused_root = copy.deepcopy(self.initial_root)
        confused_root["signed"]["roles"]["root"]["keyids"] = [[]]
        with self.assertRaises(signed_updates.SignedUpdateError):
            signed_updates.import_trusted_root(
                signed_updates.metadata_bytes(confused_root),
                now_epoch=NOW,
            )


class SignedUpdateCoreIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="memory-vault-signed-core-"
        )
        self.root = Path(self.temporary.name)
        self.data = self.root / "data"
        vault_sync.ensure_private_dir(self.data)
        self.initial_root = _root()
        self.root_file = self.root / "1.root.json"
        self.root_file.write_bytes(
            signed_updates.metadata_bytes(self.initial_root)
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_trust_import_is_explicit_one_way_and_works_before_config(self) -> None:
        with mock.patch.object(vault_sync.time, "time", return_value=NOW):
            result = vault_sync.configure_update_trust_command(
                argparse.Namespace(root_file=self.root_file),
                self.data,
            )
            status = vault_sync.update_trust_status_command(self.data)
        self.assertEqual(result["status"], "trusted_root_imported")
        self.assertTrue(status["required"])
        self.assertTrue(status["valid"])
        self.assertFalse(status["private_keys_imported"])
        self.assertFalse((self.data / "config.json").exists())
        persisted = (
            self.data / "updates" / vault_sync.SIGNED_UPDATE_TRUST_FILENAME
        ).read_text(encoding="utf-8")
        self.assertNotIn("BEGIN PRIVATE KEY", persisted)
        with (
            mock.patch.object(vault_sync.time, "time", return_value=NOW),
            self.assertRaises(vault_sync.ConflictError),
        ):
            vault_sync.configure_update_trust_command(
                argparse.Namespace(root_file=self.root_file),
                self.data,
            )

    def test_trust_import_rejects_symlink_and_trust_store_requires_private_mode(
        self,
    ) -> None:
        symlink = self.root / "root-link.json"
        try:
            symlink.symlink_to(self.root_file)
        except OSError:
            self.skipTest("symbolic links are unavailable")
        with (
            mock.patch.object(vault_sync.time, "time", return_value=NOW),
            self.assertRaises(vault_sync.VerificationError),
        ):
            vault_sync.configure_update_trust_command(
                argparse.Namespace(root_file=symlink),
                self.data,
            )
        with mock.patch.object(vault_sync.time, "time", return_value=NOW):
            vault_sync.configure_update_trust_command(
                argparse.Namespace(root_file=self.root_file),
                self.data,
            )
        trust_path = (
            self.data / "updates" / vault_sync.SIGNED_UPDATE_TRUST_FILENAME
        )
        if os.name != "nt":
            trust_path.chmod(0o644)
            with self.assertRaises(vault_sync.VerificationError):
                vault_sync.update_trust_status_command(self.data)
            trust_path.chmod(0o600)

    def test_signed_same_version_reanchors_verified_legacy_identity(self) -> None:
        legacy_commit = "c" * 40
        signed_commit = "a" * 40
        bundle_sha256 = "b" * 64
        vault_sync._refresh_stable_runtime_from_plugin(
            self.data,
            PLUGIN_ROOT,
            vault_sync.VERSION,
            bundle_sha256=bundle_sha256,
            marketplace_commit_sha=legacy_commit,
        )
        updater = vault_sync.PluginUpdater(vault_sync.default_config(), self.data)
        candidate = {
            "version": vault_sync.VERSION,
            "bundle_sha256": bundle_sha256,
            "bundle_length": 321,
            "commit_sha": legacy_commit,
            "plugin_root": str(PLUGIN_ROOT),
        }
        installed = {
            "version": vault_sync.VERSION,
            "enabled": True,
        }
        with (
            mock.patch.object(
                vault_sync,
                "_trusted_codex_executable",
                return_value=self.root / "codex",
            ),
            mock.patch.object(
                updater,
                "_marketplace",
                return_value=(self.root, "local"),
            ),
            mock.patch.object(updater, "_candidate", return_value=candidate),
            mock.patch.object(
                updater,
                "_verify_signed_candidate",
                return_value={
                    "required": True,
                    "identity_commit_sha": signed_commit,
                    "target": {},
                },
            ),
            mock.patch.object(updater, "_installed", return_value=installed),
            mock.patch.object(updater, "_assert_candidate_unchanged") as unchanged,
        ):
            result = updater.check(force=True, check_only=True)
        self.assertEqual(result["status"], "up_to_date")
        unchanged.assert_called_once_with(self.root, candidate)
        identity = vault_sync._load_verified_stable_runtime_identity(self.data)
        self.assertIsNotNone(identity)
        self.assertEqual(identity["bundle_sha256"], bundle_sha256)
        self.assertEqual(identity["marketplace_commit_sha"], signed_commit)

    def test_configured_trust_makes_missing_metadata_fail_closed(self) -> None:
        trust = signed_updates.import_trusted_root(
            self.root_file.read_bytes(),
            now_epoch=NOW,
        )
        vault_sync._persist_signed_update_trust_store(self.data, trust)
        config = vault_sync.default_config()
        updater = vault_sync.PluginUpdater(config, self.data)
        marketplace = self.root / "marketplace"
        marketplace.mkdir()
        candidate = {
            "version": "9.0.0",
            "bundle_sha256": "b" * 64,
            "bundle_length": 321,
            "commit_sha": "c" * 40,
            "plugin_root": str(marketplace / "plugins" / vault_sync.PLUGIN_NAME),
        }
        with (
            mock.patch.object(
                vault_sync,
                "_trusted_codex_executable",
                return_value=self.root / "codex",
            ),
            mock.patch.object(
                updater,
                "_marketplace",
                return_value=(marketplace, "local"),
            ),
            mock.patch.object(updater, "_candidate", return_value=candidate),
        ):
            result = updater.check(force=True)
        self.assertEqual(result["status"], "check_failed")
        self.assertEqual(result["last_error_code"], "verification")

    def test_signed_commit_may_precede_metadata_only_head_but_not_plugin_change(
        self,
    ) -> None:
        marketplace = self.root / "git-marketplace"
        marketplace.mkdir()
        subprocess.run(["git", "init", "-q", str(marketplace)], check=True)
        subprocess.run(
            ["git", "-C", str(marketplace), "config", "user.name", "Test"],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(marketplace),
                "config",
                "user.email",
                "test@example.invalid",
            ],
            check=True,
        )
        manifest = marketplace / ".agents" / "plugins" / "marketplace.json"
        plugin_file = marketplace / "plugins" / vault_sync.PLUGIN_NAME / "payload"
        manifest.parent.mkdir(parents=True)
        plugin_file.parent.mkdir(parents=True)
        manifest.write_text("{}\n", encoding="utf-8")
        plugin_file.write_text("release payload\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(marketplace), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(marketplace), "commit", "-qm", "release"],
            check=True,
        )
        release_commit = subprocess.check_output(
            ["git", "-C", str(marketplace), "rev-parse", "HEAD"],
            text=True,
        ).strip()
        candidate = {
            "version": "1.0.0",
            "bundle_sha256": "b" * 64,
            "bundle_length": 321,
            "commit_sha": "0" * 40,
            "plugin_root": str(plugin_file.parent),
        }
        _write_chain(
            marketplace / vault_sync.SIGNED_UPDATE_METADATA_DIRECTORY,
            self.initial_root,
            candidate=candidate,
            signed_commit=release_commit,
        )
        subprocess.run(["git", "-C", str(marketplace), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(marketplace), "commit", "-qm", "metadata"],
            check=True,
        )
        metadata_commit = subprocess.check_output(
            ["git", "-C", str(marketplace), "rev-parse", "HEAD"],
            text=True,
        ).strip()
        candidate["commit_sha"] = metadata_commit
        trust = signed_updates.import_trusted_root(
            self.root_file.read_bytes(),
            now_epoch=NOW,
        )
        vault_sync._persist_signed_update_trust_store(self.data, trust)
        updater = vault_sync.PluginUpdater(vault_sync.default_config(), self.data)
        verified = updater._verify_signed_candidate(
            marketplace,
            candidate,
            now=NOW,
        )
        self.assertTrue(verified["required"])
        self.assertEqual(verified["identity_commit_sha"], release_commit)

        plugin_file.write_text("changed after signed release\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(marketplace), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(marketplace), "commit", "-qm", "tamper"],
            check=True,
        )
        candidate["commit_sha"] = subprocess.check_output(
            ["git", "-C", str(marketplace), "rev-parse", "HEAD"],
            text=True,
        ).strip()
        with self.assertRaises(vault_sync.VerificationError):
            updater._verify_signed_candidate(
                marketplace,
                candidate,
                now=NOW,
            )


if __name__ == "__main__":
    unittest.main()
