"""The streamed output container, and what it buys: scratch use for a per-file
folder in both ingest modes.

The container is sealed chunk by chunk into staged blocks and committed with
the header block first; `total_chunks` is fixed up front and any chunks the
output does not fill are sealed empty. These tests check the bytes against
read_output_container AND, when Node and the UI repo are available, against
the UI's own download worker (outputDownloadWorker.ts) — the path the browser
takes.

Scratch: by default a 64 MB folder, bounding peak scratch as a multiple of it.
P3DX_SCRATCH_FULL=1 measures the real 1 GiB case in each mode.

Run:  python3 -m unittest discover -s tests
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import struct
import subprocess
import tarfile
import unittest
import base64

from tests.test_folder_upload import DICOM, TempDirCase, build_tar  # sys.path + dotenv stub

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from lib import blob_folder, folder_bundle
from lib.direct_upload import head_matches_format
from lib.output_stream import (
    BlobHttp, BlockBlobUploader, ContainerStreamWriter, OutputTooLarge, StreamingTarSink,
)
from enclave.enclave_direct_upload import (
    MB, OUTPUT_MAGIC, chunk_aad, chunk_digest_root, derive_chunk_nonce, read_output_container,
)
from tests.fake_azure import FakeAzure

UI_REPO = os.environ.get("P3DX_UI_REPO", os.path.expanduser("~/Downloads/iudx-dp-pipeline-ui-v2"))
UI_WORKER = "src/components/ReusableComponents/OutputDecrypt/outputDownloadWorker.ts"
HARNESS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui_decrypt", "harness.mjs")
OUT_URL = "https://acct.blob.core.windows.net/out/result.enc"


def ui_worker_bundle(dest_dir):
    """esbuild the UI's worker into dest_dir, or None if that is not possible."""
    esbuild = os.path.join(UI_REPO, "node_modules", ".bin", "esbuild")
    if not (shutil.which("node") and os.access(esbuild, os.X_OK)
            and os.path.isfile(os.path.join(UI_REPO, UI_WORKER))):
        return None
    out = os.path.join(dest_dir, "worker.mjs")
    proc = subprocess.run([esbuild, UI_WORKER, "--bundle", "--format=esm", "--platform=neutral",
                           "--alias:@=./src", f"--outfile={out}", "--log-level=error"],
                          cwd=UI_REPO, capture_output=True, text=True)
    return out if proc.returncode == 0 else None


def ui_decrypt(worker, container_path, key, out="sha256"):
    proc = subprocess.run(["node", HARNESS, worker, container_path, key.hex(), out],
                          capture_output=True, text=True, timeout=1800)
    if proc.returncode != 0:
        raise AssertionError(f"UI worker failed: {proc.stderr}")
    return json.loads(proc.stdout)


def stream_plaintext(fh, key):
    """The browser's read loop, in Python, yielding plaintext chunk by chunk so a
    1 GiB output is never whole in memory. Returns (header, generator)."""
    assert fh.read(8) == OUTPUT_MAGIC
    (n,) = struct.unpack(">I", fh.read(4))
    header = json.loads(fh.read(n))
    iv = base64.b64decode(header["base_iv"])

    def chunks():
        digests = []
        for i in range(header["total_chunks"]):
            (ln,) = struct.unpack(">I", fh.read(4))
            plain = AESGCM(key).decrypt(derive_chunk_nonce(iv, i), fh.read(ln),
                                        chunk_aad(header["run_id"], i, header["total_chunks"]))
            digest = hashlib.sha256(plain).hexdigest()
            assert digest == header["chunk_digests"][i], f"chunk {i} digest"
            digests.append(digest)
            yield plain
        assert chunk_digest_root(digests) == header["plaintext_sha256"]
    return header, chunks()


class _ChunkReader(io.RawIOBase):
    def __init__(self, it):
        self._it, self._buf = it, b""

    def readable(self):
        return True

    def readinto(self, b):
        while not self._buf:
            try:
                self._buf = next(self._it)
            except StopIteration:
                return 0
        n = min(len(b), len(self._buf))
        b[:n], self._buf = self._buf[:n], self._buf[n:]
        return n


class Container(TempDirCase):
    def writer(self, azure, key, max_bytes, chunk_size=1 * MB):
        http = BlobHttp(session=azure, token_provider=lambda: "tok")
        return ContainerStreamWriter(BlockBlobUploader(http, OUT_URL), run_id="run-1",
                                     output_key=key, output_base_iv=os.urandom(12),
                                     filename="r.tar", content_type="application/x-tar",
                                     max_bytes=max_bytes, chunk_size=chunk_size)

    def test_round_trip_with_an_empty_tail(self):
        azure, key = FakeAzure(), os.urandom(32)
        w = self.writer(azure, key, max_bytes=8 * MB)
        data = os.urandom(2 * MB + 12345)
        for i in range(0, len(data), 300_000):              # writes that straddle chunks
            w.write(data[i:i + 300_000])
        header = w.close()
        self.assertEqual(header["total_chunks"], 8)
        self.assertEqual(header["total_bytes"], len(data))
        self.assertEqual(header["chunk_digests"][-1], hashlib.sha256(b"").hexdigest())
        blob = azure.read("out", "result.enc")
        self.assertTrue(blob.startswith(OUTPUT_MAGIC), "header block committed first")
        got_header, plain = read_output_container(io.BytesIO(blob), key)
        self.assertEqual(plain, data)
        self.assertEqual(got_header, header)

    def test_nothing_is_visible_before_close(self):
        azure, key = FakeAzure(), os.urandom(32)
        w = self.writer(azure, key, max_bytes=8 * MB)
        w.write(os.urandom(3 * MB))
        self.assertNotIn(("out", "result.enc"), azure.blobs)
        w.close()
        self.assertIn(("out", "result.enc"), azure.blobs)

    def test_an_output_past_its_bound_fails(self):
        w = self.writer(FakeAzure(), os.urandom(32), max_bytes=2 * MB)
        with self.assertRaises(OutputTooLarge):
            w.write(os.urandom(3 * MB))

    def test_the_ui_worker_decrypts_it(self):
        worker = ui_worker_bundle(self.dir)
        if worker is None:
            self.skipTest("Node, esbuild or the UI repo not available")
        azure, key = FakeAzure(), os.urandom(32)
        w = self.writer(azure, key, max_bytes=16 * MB)
        data = os.urandom(5 * MB + 1)
        w.write(data)
        w.close()
        path = os.path.join(self.dir, "c.enc")
        with open(path, "wb") as f:
            f.write(azure.read("out", "result.enc"))
        got = ui_decrypt(worker, path, key)
        self.assertEqual(got, {"filename": "r.tar", "bytes": len(data),
                               "sha256": hashlib.sha256(data).hexdigest()})


def _du(path):
    return sum(os.path.getsize(os.path.join(r, n)) for r, _, fs in os.walk(path) for n in fs
               if os.path.exists(os.path.join(r, n)))


class ScratchPeak(TempDirCase):
    """Per-file folder, each mode, output streamed. Scratch may hold the
    uploaded bundle and nothing else; a cloud folder holds nothing there.
    Each member is 'de-identified' by copying it to output/, outside scratch,
    and the output goes to blob storage (FakeAzure, on disk, also outside)."""

    FULL = os.environ.get("P3DX_SCRATCH_FULL") == "1"
    FOLDER = 1024 * MB - 4 * MB if FULL else 64 * MB      # room for tar headers under 1 GiB
    MEMBER = 8 * MB
    LIMIT = 3 * 1024 * MB

    def setUp(self):
        super().setUp()
        self.scratch, self.work, self.store = (os.path.join(self.dir, d)
                                               for d in ("scratch", "output", "azure"))
        for d in (self.scratch, self.work, self.store):
            os.makedirs(d)
        self.azure = FakeAzure(store_dir=self.store)
        self.http = BlobHttp(session=self.azure, token_provider=lambda: "tok")
        self.key = os.urandom(32)
        self.peak = 0
        self.member_hashes = {}

    def member_bytes(self, i):
        return DICOM + hashlib.sha256(str(i).encode()).digest() + os.urandom(self.MEMBER - len(DICOM) - 32)

    def sample(self):
        self.peak = max(self.peak, _du(self.scratch))

    def process(self, name, fh):
        out = os.path.join(self.work, "after_deidentification.dcm")
        h = hashlib.sha256()
        with open(out, "wb") as f:
            for block in iter(lambda: fh.read(1 << 20), b""):
                h.update(block)
                f.write(block)
        self.member_hashes[name] = h.hexdigest()
        self.sample()
        return out

    def cleanup(self):
        for n in os.listdir(self.work):
            os.unlink(os.path.join(self.work, n))
        self.sample()

    def sink(self):
        writer = ContainerStreamWriter(
            BlockBlobUploader(self.http, OUT_URL), run_id="run-1", output_key=self.key,
            output_base_iv=os.urandom(12), filename="f_anonymised.tar",
            content_type="application/x-tar", max_bytes=2 * 1024 * MB)
        return StreamingTarSink(writer)

    def verify_output(self, n_members, label):
        path = self.azure.blob_path("out", "result.enc")
        with open(path, "rb") as fh:
            header, chunks = stream_plaintext(fh, self.key)
            whole = hashlib.sha256()

            def hashed():
                for c in chunks:
                    whole.update(c)
                    yield c
            seen, manifest = {}, None
            with tarfile.open(fileobj=io.BufferedReader(_ChunkReader(hashed())), mode="r|") as tf:
                for m in tf:
                    data = tf.extractfile(m).read()
                    seen[m.name] = hashlib.sha256(data).hexdigest()
                    if m.name == folder_bundle.MANIFEST_NAME:
                        manifest = json.loads(data)
        self.assertEqual(manifest["files_succeeded"], n_members)
        for name, digest in self.member_hashes.items():
            self.assertEqual(seen[folder_bundle.output_name(name, "dicom", "x.dcm")], digest)

        worker = ui_worker_bundle(self.dir)
        if worker is not None:
            got = ui_decrypt(worker, path, self.key)
            self.assertEqual(got["sha256"], whole.hexdigest(), "UI worker decrypts the same bytes")
            ui = "UI worker: decrypted identically"
        else:
            ui = "UI worker: skipped (no Node/UI repo)"
        print(f"\n  {label}: folder {self.FOLDER / MB:.0f} MB, {n_members} files, peak scratch "
              f"{self.peak / MB:.0f} MB, output {header['total_bytes'] / MB:.0f} MB in "
              f"{header['total_chunks']} chunks; {ui}", flush=True)

    def test_uploaded_folder(self):
        n = self.FOLDER // self.MEMBER
        tar_path = os.path.join(self.scratch, "u.bin")
        with tarfile.open(tar_path, "w:", format=tarfile.PAX_FORMAT) as tf:
            for i in range(n):
                data = self.member_bytes(i)
                info = tarfile.TarInfo(f"s{i // 32}/IM{i:05d}")
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
        bundle = os.path.getsize(tar_path)
        self.sample()
        folder_bundle.run_per_file(folder_bundle.tar_members(tar_path), "dicom", self.sink(),
                                   self.process, self.cleanup)
        os.unlink(tar_path)                     # released after the last member
        self.sample()
        self.assertLess(self.peak, self.LIMIT)
        self.assertLessEqual(self.peak, bundle + MB, "scratch holds the bundle and nothing more")
        self.verify_output(n, "uploaded folder")

    def test_cloud_folder(self):
        n = self.FOLDER // self.MEMBER
        fernet_key = Fernet.generate_key()
        fernet = Fernet(fernet_key)
        blobs = os.path.join(self.dir, "blobs")
        os.makedirs(blobs)
        for i in range(n):
            p = os.path.join(blobs, f"{i}")
            with open(p, "wb") as f:
                f.write(fernet.encrypt(self.member_bytes(i)))
            self.azure.put_file("data", f"scans/s{i // 32}/IM{i:05d}.dcm.enc", p)
        plan = blob_folder.list_and_plan(self.http, "https://acct.blob.core.windows.net/data/scans/",
                                         "skald_dicom")
        folder_bundle.run_per_file(blob_folder.members(plan, self.http, fernet.decrypt, head_matches_format),
                                   "dicom", self.sink(), self.process, self.cleanup)
        self.sample()
        self.assertEqual(self.peak, 0, "a cloud folder puts nothing on scratch")
        shutil.rmtree(blobs)
        self.verify_output(n, "cloud folder")


if __name__ == "__main__":
    unittest.main()
