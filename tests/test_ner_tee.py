"""NER TEE (2026-11-22): attestation, the RA-TLS channel, and the fallback.

The k-anon TEE sends free text to the NER TEE only after verifying its MAA
attestation and pinning its TLS key. These tests stand up the real RA-TLS
server (enclave/ratls_server.py) on localhost with a throwaway certificate, and
sign attestation tokens with a throwaway "MAA" key, so the real client
(lib/ner_client.py) and verifier (lib/attest_verify.py) run end to end.

The property that matters most is the fallback: every failure must raise
NerUnavailable having written nothing, so the stage runs locally as before.

Run:  python3 -m unittest discover -s tests
"""

from __future__ import annotations

import base64
import csv
import datetime
import hashlib
import io
import json
import os
import socket
import subprocess
import tarfile
import tempfile
import time
import unittest
from unittest import mock

from tests.test_folder_upload import TempDirCase  # sys.path + stubs

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from lib import attest_verify, ner_client
from lib.config import config

ISSUER = attest_verify.MAA_ISSUER


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _self_signed(key) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))


def _spki_b64(key) -> str:
    return base64.b64encode(key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()


class FakeMaa:
    """Signs tokens the way MAA does, with a key whose certificate we serve as the JWKS."""

    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.cert = _self_signed(self.key)
        self.jwks = [{"kid": "k1", "x5c": [base64.b64encode(self.cert.public_bytes(serialization.Encoding.DER)).decode()]}]

    def token(self, nonce: str, enclave_spki: str, *, pcr15="ab" * 32, debuggable=False, alg="RS256",
              exp_in=600, issuer=ISSUER) -> str:
        header = {"alg": alg, "kid": "k1", "typ": "JWT"}
        payload = {
            "nonce": base64.b64encode(nonce.encode()).decode(),
            "public key": base64.b64encode(enclave_spki.encode()).decode(),
            "tpm_values": base64.b64encode(json.dumps({"15": pcr15}).encode()).decode(),
        }
        claims = {
            "iss": issuer, "exp": int(time.time()) + exp_in,
            "x-ms-isolation-tee": {"x-ms-attestation-type": "sevsnpvm", "x-ms-compliance-status": "azure-compliant-cvm",
                                   "x-ms-sevsnpvm-is-debuggable": debuggable, "x-ms-sevsnpvm-launchmeasurement": "aa" * 48},
            "x-ms-runtime": {"client-payload": payload},
        }
        h, b = _b64url(json.dumps(header).encode()), _b64url(json.dumps(claims).encode())
        sig = self.key.sign(f"{h}.{b}".encode(), padding.PKCS1v15(), hashes.SHA256())
        return f"{h}.{b}.{_b64url(sig)}"


class VerifierTests(unittest.TestCase):
    def setUp(self):
        self.maa = FakeMaa()
        p = mock.patch.object(attest_verify, "_jwks", return_value=self.maa.jwks)
        p.start()
        self.addCleanup(p.stop)
        self.spki = _spki_b64(rsa.generate_private_key(public_exponent=65537, key_size=2048))

    def test_a_genuine_fresh_token_verifies(self):
        v = attest_verify.verify(self.maa.token("n" * 32, self.spki), "n" * 32)
        self.assertEqual(v.public_key, self.spki)

    def test_wrong_nonce_debuggable_alg_none_expired_and_issuer_are_refused(self):
        bad = [
            (self.maa.token("x" * 32, self.spki), "nonce"),
            (self.maa.token("n" * 32, self.spki, debuggable=True), "debuggable"),
            (self.maa.token("n" * 32, self.spki, exp_in=-3600), "expired"),
            (self.maa.token("n" * 32, self.spki, issuer="https://evil.example"), "issuer"),
        ]
        for token, why in bad:
            with self.subTest(why):
                with self.assertRaises(attest_verify.AttestationError):
                    attest_verify.verify(token, "n" * 32)
        h, b, _ = self.maa.token("n" * 32, self.spki).split(".")
        none = f"{_b64url(json.dumps({'alg': 'none', 'kid': 'k1'}).encode())}.{b}."
        with self.assertRaises(attest_verify.AttestationError):
            attest_verify.verify(none, "n" * 32)

    def test_a_tampered_payload_fails_the_signature(self):
        h, b, s = self.maa.token("n" * 32, self.spki).split(".")
        claims = json.loads(base64.urlsafe_b64decode(b + "=="))
        claims["x-ms-isolation-tee"]["x-ms-sevsnpvm-is-debuggable"] = False
        claims["exp"] += 1
        with self.assertRaises(attest_verify.AttestationError):
            attest_verify.verify(f"{h}.{_b64url(json.dumps(claims).encode())}.{s}", "n" * 32)

    def test_code_measurement_policy_warns_or_enforces(self):
        token = self.maa.token("n" * 32, self.spki, pcr15="cd" * 32)
        warn = attest_verify.verify(token, "n" * 32, attest_verify.Policy(pcr15="ab" * 32, mode="warn"))
        self.assertTrue(any("PCR15" in w for w in warn.warnings))
        with self.assertRaises(attest_verify.AttestationError):
            attest_verify.verify(token, "n" * 32, attest_verify.Policy(pcr15="ab" * 32, mode="enforce"))
        ok = attest_verify.verify(token, "n" * 32, attest_verify.Policy(pcr15="cd" * 32, mode="enforce"))
        self.assertFalse(any("PCR15" in w for w in ok.warnings))
        # Tokens say "0xCD…", tpm2_pcrread and tools/expected_pcr15.py say "cd…".
        prefixed = self.maa.token("n" * 32, self.spki, pcr15="0x" + "CD" * 32)
        attest_verify.verify(prefixed, "n" * 32, attest_verify.Policy(pcr15="cd" * 32, mode="enforce"))


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class RaTlsEndToEnd(TempDirCase):
    """The real RA-TLS server and the real client, on localhost."""

    def setUp(self):
        super().setUp()
        from enclave import ratls_server

        self.maa = FakeMaa()
        p = mock.patch.object(attest_verify, "_jwks", return_value=self.maa.jwks)
        p.start()
        self.addCleanup(p.stop)

        self.enclave_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert, key = self.path("tls_cert.pem"), self.path("key.pem")
        with open(cert, "wb") as f:
            f.write(_self_signed(self.enclave_key).public_bytes(serialization.Encoding.PEM))
        with open(key, "wb") as f:
            f.write(self.enclave_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                   serialization.NoEncryption()))
        self.attest_spki = _spki_b64(self.enclave_key)  # what the token claims
        self.seen = {}

        def attest(nonce):
            return self.maa.token(nonce, self.attest_spki)

        def ner_run(payload_path):
            # Stand-in for skald-fta: record what crossed, return a cleaned staged CSV.
            with tarfile.open(payload_path, "r:gz") as tf:
                self.seen["names"] = sorted(tf.getnames())
                data = [m for m in tf.getmembers() if m.name.startswith("data/")][0]
                text = tf.extractfile(data).read().decode()
            self.seen["data"] = text
            rows = list(csv.reader(io.StringIO(text)))
            cleaned = [rows[0]] + [[r[0]] + ["*" for _ in r[1:]] for r in rows[1:]]
            out = io.StringIO()
            csv.writer(out).writerows(cleaned)
            result = self.path("result.tgz")
            with tarfile.open(result, "w:gz") as tf:
                for name, body in (("sanitized_input.csv", out.getvalue()), ("free_text_audit.json", "{}")):
                    info = tarfile.TarInfo(name)
                    info.size = len(body.encode())
                    tf.addfile(info, io.BytesIO(body.encode()))
            return 0, result

        self.port = _free_port()
        self.server = ratls_server.serve(cert, key, attest, lambda *a: None, port=self.port, ner_run=ner_run)
        self.addCleanup(self.server.shutdown)
        self.addCleanup(self.server.server_close)

        self.data, self.out, self.cfg = self.path("data"), self.path("output"), self.path("fta_config")
        for d in (self.data, self.out, self.cfg):
            os.makedirs(d, exist_ok=True)
        with open(os.path.join(self.data, "patients.csv"), "w", newline="") as f:
            csv.writer(f).writerows([["id", "age", "remarks"], ["P1", "41", "called Ramesh 98765"], ["P2", "36", "fine"]])
        with open(os.path.join(self.cfg, "config.json"), "w") as f:
            json.dump({"data_type": "t"}, f)
        self.settings = {"enabled": True, "host": "127.0.0.1", "port": self.port, "wait_seconds": 2,
                         "attestation_mode": "warn", "reference": {"pcr15": "self"}}
        p = mock.patch.object(ner_client, "_own_pcr15", return_value="ab" * 32)  # same code as the peer
        p.start()
        self.addCleanup(p.stop)

    def run_remote(self, **override):
        settings = dict(self.settings, **override)
        with mock.patch.object(ner_client, "_setting", side_effect=lambda k, d=None: settings.get(k, d)):
            return ner_client.run_remote(self.cfg, self.data, self.out, {"columns": ["remarks"]},
                                         "sanitized_input.csv", timeout=30)

    def test_only_free_text_columns_cross_and_are_merged_back(self):
        self.assertEqual(self.run_remote(), 0)
        self.assertNotIn("41", self.seen["data"], "non-free-text columns stayed in the k-anon TEE")
        self.assertIn("remarks", self.seen["data"])
        with open(os.path.join(self.out, "sanitized_input.csv"), newline="") as f:
            rows = list(csv.reader(f))
        self.assertEqual(rows, [["id", "age", "remarks"], ["P1", "41", "*"], ["P2", "36", "*"]])
        self.assertTrue(os.path.exists(os.path.join(self.out, "free_text_audit.json")))

    def test_a_tls_key_that_is_not_the_attested_key_sends_nothing(self):
        self.attest_spki = _spki_b64(rsa.generate_private_key(public_exponent=65537, key_size=2048))
        with self.assertRaisesRegex(ner_client.NerUnavailable, "not the attested key"):
            self.run_remote()
        self.assertNotIn("data", self.seen, "the payload never reached the NER TEE")
        self.assertEqual(os.listdir(self.out), [])

    def test_enforced_code_mismatch_falls_back_without_sending(self):
        with self.assertRaises(ner_client.NerUnavailable):
            self.run_remote(attestation_mode="enforce", reference={"pcr15": "00" * 32})
        self.assertNotIn("data", self.seen)
        self.assertEqual(os.listdir(self.out), [])

    def test_enforced_self_reference_accepts_the_same_code(self):
        self.assertEqual(self.run_remote(attestation_mode="enforce"), 0)

    def test_unreachable_or_disabled_writes_nothing(self):
        with self.assertRaises(ner_client.NerUnavailable):
            self.run_remote(port=_free_port())
        with self.assertRaises(ner_client.NerUnavailable):
            self.run_remote(enabled=False)
        self.assertEqual(os.listdir(self.out), [])


class FallbackInTheStage(TempDirCase):
    """run_free_text_anonymization runs skald-fta locally whenever the NER TEE can't be used."""

    def test_remote_failure_runs_the_local_stage(self):
        import P3DX_SDK

        cfg_dir = self.path("config")
        os.makedirs(cfg_dir)
        with open(os.path.join(cfg_dir, "config.json"), "w") as f:
            json.dump({"data_type": "t", "t": {"free_text_anonymization": {"enabled": True, "columns": ["remarks"]}}}, f)
        out = self.path("output")
        os.makedirs(out)
        staged = os.path.join(out, "sanitized_input.csv")

        def local(provenance):
            with open(staged, "w") as f:
                f.write("id\n1\n")
            return 0

        with mock.patch.object(config.paths, "tee_input_config", cfg_dir), \
                mock.patch.object(config.paths, "tee_output", out), \
                mock.patch.object(ner_client, "remote_enabled", return_value=True), \
                mock.patch.object(ner_client, "run_remote", side_effect=ner_client.NerUnavailable("off")), \
                mock.patch.object(P3DX_SDK, "_verify_shared_output_mount"), \
                mock.patch.object(P3DX_SDK, "_prepare_fta_config_dir", return_value=cfg_dir), \
                mock.patch.object(P3DX_SDK, "_run_fta_local", side_effect=local) as run_local, \
                mock.patch.object(P3DX_SDK, "_swap_staged_input_into_data") as swap:
            self.assertTrue(P3DX_SDK.run_free_text_anonymization())
        run_local.assert_called_once()
        swap.assert_called_once_with(staged)


class DeterministicMeasurement(TempDirCase):
    def test_leftover_run_files_do_not_change_the_code_hash(self):
        import P3DX_SDK

        repo = self.path("repo")
        os.makedirs(repo)
        run = lambda *a: subprocess.run(["git", "-C", repo, *a], check=True, capture_output=True)
        run("init", "-q")
        with open(os.path.join(repo, "a.py"), "w") as f:
            f.write("print(1)\n")
        run("add", "a.py")
        run("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "c")
        before = P3DX_SDK.hash_enclave_manager_code(repo)
        os.makedirs(os.path.join(repo, "tee-snapshot"))
        with open(os.path.join(repo, "tee-snapshot", "status.json"), "w") as f:
            f.write("{}")
        self.assertEqual(P3DX_SDK.hash_enclave_manager_code(repo), before)
        expected = hashlib.sha256(b"a.py" + b"print(1)\n").hexdigest()
        self.assertEqual(before, expected)


if __name__ == "__main__":
    unittest.main()
