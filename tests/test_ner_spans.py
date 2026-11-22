"""NER spans for DICOM (2026-11-23): /ner/spans on the NER TEE, the k-anon
TEE's client (attest once, then pin the key), the local Unix socket the DICOM
container uses, and the span adapter (lib/ner_service.py) without its engine.

The property that matters: whenever the NER TEE can't be used, the local
socket answers 503 (the DICOM container then takes its fallback), and no text
is sent to a peer whose TLS key is not the attested one.

Run:  python3 -m unittest discover -s tests
"""

from __future__ import annotations

import http.client
import json
import os
import socket
import threading
import time
from unittest import mock

from tests.test_folder_upload import TempDirCase  # sys.path + stubs
from tests.test_ner_tee import FakeMaa, _free_port, _self_signed, _spki_b64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from lib import attest_verify, ner_client, ner_local_socket, ner_service


class _Unix(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=10)
        self._path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self._path)


def _post(path, body: bytes):
    c = _Unix(path)
    c.request("POST", "/spans", body=body, headers={"Content-Type": "application/json"})
    r = c.getresponse()
    return r.status, r.read()


class SpansOverRaTls(TempDirCase):
    """The real RA-TLS server with a /ner/spans hook, and the real client."""

    def setUp(self):
        super().setUp()
        from enclave import ratls_server

        self.maa = FakeMaa()
        p = mock.patch.object(attest_verify, "_jwks", return_value=self.maa.jwks)
        p.start()
        self.addCleanup(p.stop)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert_path, key_path = self.path("tls_cert.pem"), self.path("key.pem")
        with open(cert_path, "wb") as f:
            f.write(_self_signed(key).public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
        self.attest_spki = _spki_b64(key)
        self.attests = 0
        self.received = []

        def attest(nonce):
            self.attests += 1
            return self.maa.token(nonce, self.attest_spki)

        def ner_spans(body):
            req = json.loads(body)
            self.received.append(req)
            return 200, json.dumps({"results": [
                {"spans": [{"start": 0, "end": 6, "label": "PERSON", "source": "x", "confidence": 1.0}], "error": None}
                for _ in req["texts"]]}).encode()

        self.port = _free_port()
        self.server = ratls_server.serve(cert_path, key_path, attest, lambda *a: None, port=self.port,
                                         ner_spans=ner_spans)
        self.addCleanup(self.server.shutdown)
        self.addCleanup(self.server.server_close)
        self.settings = {"enabled": True, "host": "127.0.0.1", "port": self.port, "wait_seconds": 2,
                         "attestation_mode": "warn", "reference": {"pcr15": "self"}}
        for target, value in ((ner_client, "_own_pcr15"),):
            p = mock.patch.object(target, value, return_value="ab" * 32)
            p.start()
            self.addCleanup(p.stop)
        p = mock.patch.object(ner_client, "_setting", side_effect=lambda k, d=None: self.settings.get(k, d))
        p.start()
        self.addCleanup(p.stop)
        ner_client._spans_state.update(key=None, expires=0.0, down_until=0.0)

    def test_attests_once_then_reuses_the_pinned_key(self):
        body = json.dumps({"texts": ["Ramesh Kumar"]}).encode()
        for _ in range(3):
            reply = json.loads(ner_client.spans_remote(body))
            self.assertEqual(reply["results"][0]["spans"][0]["label"], "PERSON")
        self.assertEqual(self.attests, 1)
        self.assertEqual(len(self.received), 3)

    def test_a_tls_key_that_is_not_the_attested_key_sends_nothing(self):
        self.attest_spki = _spki_b64(rsa.generate_private_key(public_exponent=65537, key_size=2048))
        with self.assertRaisesRegex(ner_client.NerUnavailable, "not the attested key"):
            ner_client.spans_remote(b'{"texts": ["Ramesh"]}')
        self.assertEqual(self.received, [])

    def test_a_failure_fails_fast_until_the_retry_window(self):
        self.settings["port"] = _free_port()  # nothing listens
        with self.assertRaises(ner_client.NerUnavailable):
            ner_client.spans_remote(b'{"texts": ["a"]}')
        t = time.monotonic()
        with self.assertRaisesRegex(ner_client.NerUnavailable, "failed recently"):
            ner_client.spans_remote(b'{"texts": ["a"]}')
        self.assertLess(time.monotonic() - t, 0.5)

    def test_the_route_is_absent_on_k_anon_nodes(self):
        from enclave import ratls_server

        self.server.shutdown()
        self.server.server_close()
        cert_path, key_path = self.path("tls_cert.pem"), self.path("key.pem")
        self.port = self.settings["port"] = _free_port()
        self.server = ratls_server.serve(cert_path, key_path, lambda n: self.maa.token(n, self.attest_spki),
                                         lambda *a: None, port=self.port)
        with self.assertRaisesRegex(ner_client.NerUnavailable, "HTTP 404"):
            ner_client.spans_remote(b'{"texts": ["a"]}')


class LocalSocket(TempDirCase):
    def setUp(self):
        super().setUp()
        # AF_UNIX paths are limited to ~108 bytes.
        self.sock = f"/tmp/ner-local-test-{os.getpid()}/ner.sock"
        p = mock.patch.object(ner_local_socket, "socket_path", return_value=self.sock)
        p.start()
        self.addCleanup(p.stop)
        p = mock.patch.object(ner_client, "remote_enabled", return_value=True)
        p.start()
        self.addCleanup(p.stop)
        ner_local_socket._server = None
        self.addCleanup(self._stop)

    def _stop(self):
        if ner_local_socket._server is not None:
            ner_local_socket._server.shutdown()
            ner_local_socket._server.server_close()
            ner_local_socket._server = None
        if os.path.exists(self.sock):
            os.remove(self.sock)

    def test_forwards_and_reports_unavailable_as_503(self):
        with mock.patch.object(ner_client, "spans_remote", return_value=b'{"results": []}') as remote:
            self.assertTrue(ner_local_socket.start())
            self.assertEqual(oct(os.stat(os.path.dirname(self.sock)).st_mode & 0o777), "0o700")
            self.assertEqual(_post(self.sock, b'{"texts": []}'), (200, b'{"results": []}'))
            remote.assert_called_once_with(b'{"texts": []}')
        with mock.patch.object(ner_client, "spans_remote", side_effect=ner_client.NerUnavailable("off")):
            status, _ = _post(self.sock, b'{"texts": ["x"]}')
            self.assertEqual(status, 503)

    def test_not_opened_when_ner_tee_disabled(self):
        with mock.patch.object(ner_client, "remote_enabled", return_value=False):
            self.assertFalse(ner_local_socket.start())
        self.assertFalse(os.path.exists(self.sock))


class Adapter(TempDirCase):
    """lib/ner_service.py around a fake engine: the request contract and the
    span union, which run on the NER TEE and the OCR VM unchanged."""

    def test_union_spans_keeps_the_most_confident_label_per_region(self):
        audit = [
            {"label": "PERSON", "source": "a", "confidence": 0.6, "start_offset": 0, "end_offset": 12},
            {"label": "LOCATION", "source": "b", "confidence": 0.9, "start_offset": 0, "end_offset": 12},
            {"label": "Aadhaar", "source": "c", "confidence": 1.0, "start_offset": 20, "end_offset": 34},
        ]
        got = ner_service._union_spans(audit)
        self.assertEqual([(s["start"], s["end"], s["label"]) for s in got],
                         [(0, 12, "LOCATION"), (20, 34, "Aadhaar")])

    def test_requests_are_validated(self):
        for bad in ({"texts": "x"}, {"texts": [1]}, {"texts": [], "minimum_confidence": 2}, {"texts": [], "labels": "P"}, []):
            with self.assertRaises(ValueError):
                ner_service._validate(bad)

    def test_serve_unix_round_trip(self):
        path = f"/tmp/ner-svc-test-{os.getpid()}.sock"
        with mock.patch.object(ner_service, "detect", return_value={"results": [{"spans": [], "error": None}]}):
            srv = ner_service._UnixHTTPServer(path, ner_service._Handler)
            srv.ready = True
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            try:
                self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o666")
                status, body = _post(path, b'{"texts": ["x"]}')
                self.assertEqual((status, json.loads(body)), (200, {"results": [{"spans": [], "error": None}]}))
            finally:
                srv.shutdown()
                srv.server_close()
                os.remove(path)
