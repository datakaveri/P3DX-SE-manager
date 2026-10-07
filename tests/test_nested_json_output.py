"""Nested-JSON SKALD runs (`nested_json: true`): what leaves the enclave.

SKALD's nested flow (src/pipeline/nested_json.rs) writes one de-identified
document per input into `output/<output_path>/`, the key census beside them,
and its key material — salt, token vault, encrypt/FPE keys — at the top of the
output directory. The key material must never be uploaded; the documents and
the census must be.

The last class runs the real SKALD binary (SKALD_PIPELINE_BIN, or
~/k-anonymisation/SKALD) and skips without it.

Run:  python3 -m unittest discover -s tests
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import tarfile
import unittest
from unittest import mock

from tests.test_folder_upload import HAVE_SKALD, SKALD_BIN, TempDirCase, _Uploads  # sys.path + stubs

from cryptography.fernet import Fernet

import P3DX_SDK
from lib import direct_upload
from lib.config import config
from enclave.enclave_direct_upload import read_output_container

NESTED_KEYS = ("nested_json_salt.json", "nested_json_token_vault.json",
               "nested_json_symmetric_keys.json", "nested_json_fpe_encrypt_keys.json")
TABULAR_KEYS = ("symmetric_keys.json", "fpe_encrypt_keys.json", "token_vault.json")
ALL_KEYS = NESTED_KEYS + TABULAR_KEYS + ("fhir_bundle_salts.json",)

DOC = {"id": "H1", "current_road_details": {"name": "MG Road"}}


class NestedOutputCase(TempDirCase):
    """An output directory shaped exactly as SKALD's nested run leaves it."""

    def setUp(self):
        super().setUp()
        self.out = os.path.join(self.dir, "output")
        os.makedirs(self.out)
        p = mock.patch.object(config.paths, "tee_output", self.out)
        p.start()
        self.addCleanup(p.stop)

    def nested_run(self, documents=("grievances_data",), subdir="grievances",
                   reported_dir=None, mode="nested_json_deidentification", skipped=0):
        for name in NESTED_KEYS:
            with open(os.path.join(self.out, name), "w") as f:
                json.dump({"secret": name}, f)
        docs = os.path.join(self.out, subdir)
        os.makedirs(docs, exist_ok=True)
        for stem in documents:
            with open(os.path.join(docs, f"{stem}.json"), "w") as f:
                json.dump(dict(DOC, source=stem), f)
        with open(os.path.join(docs, "nested_json_census.csv"), "w") as f:
            f.write("path,seen,action,matched_by\n[].id,1,hash,[].id\n")
        with open(os.path.join(self.out, "pipeline.log"), "w") as f:
            f.write("log\n")
        status = {"status": "ok", "phase": "done", "outputs": {
            "mode": mode, "output_directory": reported_dir or f"./output/{subdir}",
            "key_census": f"./output/{subdir}/nested_json_census.csv",
            "documents_written": len(documents), "documents_skipped": skipped}}
        with open(os.path.join(self.out, "status.json"), "w") as f:
            json.dump(status, f)
        return status


# --------------------------------------------------------------------------- #
# A. Key material never selected
# --------------------------------------------------------------------------- #


class KeyMaterial(NestedOutputCase):
    def test_every_key_file_is_known(self):
        for name in ALL_KEYS:
            self.assertIn(name, P3DX_SDK._KNOWN_KEY_MATERIAL)

    def test_the_blob_upload_selection_skips_all_key_files(self):
        for name in ALL_KEYS + ("generalized.csv",):
            with open(os.path.join(self.out, name), "w") as f:
                f.write("x")
        chosen = {os.path.basename(p) for p in
                  P3DX_SDK.blob_output_files(self.out, os.path.join(self.out, "status.json"))}
        self.assertEqual(chosen & set(ALL_KEYS), set())
        self.assertIn("generalized.csv", chosen)

    def test_the_direct_selection_never_counts_them_as_a_result(self):
        for name in ALL_KEYS + ("generalized.csv",):
            with open(os.path.join(self.out, name), "w") as f:
                f.write("x")
        candidates, _ = P3DX_SDK.tabular_output_candidates(self.out, os.path.join(self.out, "status.json"))
        self.assertEqual(candidates, ["generalized.csv"])


# --------------------------------------------------------------------------- #
# B. Documents and census selected, defensively
# --------------------------------------------------------------------------- #


class Selection(NestedOutputCase):
    def test_one_document_is_the_result_with_the_census_beside_it(self):
        status = self.nested_run()
        nested = P3DX_SDK.nested_json_outputs(self.out, status)
        self.assertEqual([os.path.basename(p) for p in nested.documents], ["grievances_data.json"])
        self.assertTrue(nested.census.endswith("grievances/nested_json_census.csv"))

    def test_container_side_paths_map_onto_the_output_mount(self):
        for reported in ("/app/output/grievances", "output/grievances", "./output/grievances/"):
            with self.subTest(reported=reported):
                status = self.nested_run(reported_dir=reported)
                nested = P3DX_SDK.nested_json_outputs(self.out, status)
                self.assertEqual(nested.directory, os.path.realpath(os.path.join(self.out, "grievances")))

    def test_a_directory_outside_the_output_is_refused(self):
        status = self.nested_run(reported_dir="../../etc")
        with self.assertRaisesRegex(P3DX_SDK.NestedJsonOutputError, "not a directory inside"):
            P3DX_SDK.nested_json_outputs(self.out, status)

    def test_documents_at_the_top_beside_the_keys_are_refused(self):
        status = self.nested_run(subdir=".", reported_dir="./output")
        with self.assertRaises(P3DX_SDK.NestedJsonOutputError):
            P3DX_SDK.nested_json_outputs(self.out, status)

    def test_a_symlinked_document_is_not_followed(self):
        status = self.nested_run()
        os.symlink(os.path.join(self.out, "nested_json_salt.json"),
                   os.path.join(self.out, "grievances", "evil.json"))
        nested = P3DX_SDK.nested_json_outputs(self.out, status)
        self.assertEqual([os.path.basename(p) for p in nested.documents], ["grievances_data.json"])

    def test_a_dry_run_is_a_clear_failure(self):
        status = self.nested_run(mode="nested_json_dry_run")
        with self.assertRaisesRegex(P3DX_SDK.NestedJsonOutputError, "dry run"):
            P3DX_SDK.nested_json_outputs(self.out, status)

    def test_a_tabular_status_is_not_nested(self):
        self.assertIsNone(P3DX_SDK.nested_json_outputs(self.out, {"status": "success", "outputs": {}}))
        self.assertIsNone(P3DX_SDK.nested_json_outputs(self.out, None))

    def test_several_documents_come_back_as_an_archive_with_a_manifest(self):
        status = self.nested_run(documents=("a", "b", "c"), skipped=1)
        nested = P3DX_SDK.nested_json_outputs(self.out, status)
        archive = P3DX_SDK.nested_json_result(nested, self.out, "grievances")
        with tarfile.open(archive) as tf:
            self.assertEqual(sorted(tf.getnames()), ["_manifest.json", "a.json", "b.json", "c.json"])
            manifest = json.load(tf.extractfile("_manifest.json"))
        self.assertEqual((manifest["mode"], manifest["application"], manifest["format"]),
                         ("per_file", "skald", "json"))
        self.assertEqual((manifest["files_total"], manifest["files_succeeded"], manifest["files_failed"]),
                         (4, 3, 1))


class BlobModeUpload(NestedOutputCase):
    """encrypt_and_upload_output, blob mode, end to end: what lands in the
    consumer's output container."""

    def test_the_container_holds_the_document_and_census_and_no_key(self):
        self.nested_run()
        urls_dir = os.path.join(self.dir, "urls")
        os.makedirs(urls_dir)
        with open(os.path.join(urls_dir, "decrypted_urls.json"), "w") as f:
            json.dump({"blobUrl": "https://acct.blob.core.windows.net/data/g.json.enc",
                       "keyVaultUrl": "https://kv.vault.azure.net/secrets/k",
                       "outputContainerUrl": "https://acct.blob.core.windows.net/out"}, f)
        key = Fernet.generate_key()
        uploaded = {}

        def upload(url, path):
            with open(path, "rb") as f:
                uploaded[url.rsplit("/", 1)[1]] = Fernet(key).decrypt(f.read())

        fd = P3DX_SDK._get_fetch_data()
        with mock.patch.object(config.paths, "tee_urls", urls_dir), \
                mock.patch.object(fd, "fetch_fernet_key_from_kv", return_value=key), \
                mock.patch.object(fd, "upload_blob", side_effect=upload), \
                mock.patch.object(fd, "read_output_format", return_value="json"), \
                mock.patch.object(P3DX_SDK, "_upload_kmeans_plots"):
            primary = P3DX_SDK.encrypt_and_upload_output()

        self.assertTrue(primary.endswith("/grievances_data.json.enc"), primary)
        self.assertIn("nested_json_census.csv.enc", uploaded)
        self.assertEqual(json.loads(uploaded["grievances_data.json.enc"])["source"], "grievances_data")
        for name in ALL_KEYS:
            self.assertNotIn(name + ".enc", uploaded)


class DirectModeUpload(NestedOutputCase):
    """_upload_direct_output hands the document (and the census) to the
    manager, which seals each in its own container."""

    def test_handoff_and_finalize(self):
        self.nested_run()
        scratch = os.path.join(self.dir, "scratch")
        up = _Uploads(scratch)
        ref = up.upload("u1", "grievances.json", "json", json.dumps([DOC]).encode())
        uid = ref.rsplit("/", 1)[1]
        with open(os.path.join(scratch, f"{uid}.meta.json"), "w") as f:
            json.dump({"filename": "grievances.json", "format": "json"}, f)
        posted = {}

        def post(url, json=None, timeout=None):
            posted.update(json)
            return mock.Mock(status_code=200, json=lambda: {"outputBlobUrl": "x"})

        with mock.patch.object(direct_upload, "_scratch_dir", return_value=scratch), \
                mock.patch.object(P3DX_SDK, "load_config_file",
                                  return_value={"enclaveManagerAddress": "http://127.0.0.1:4000"}), \
                mock.patch.object(P3DX_SDK.requests, "post", post):
            P3DX_SDK._upload_direct_output(self.out, {"blobUrl": ref})

        self.assertTrue(posted["output_path"].endswith("grievances/grievances_data.json"))
        self.assertEqual(posted["filename"], "grievances_anonymised.json")
        self.assertEqual(posted["content_type"], "application/json")
        self.assertTrue(posted["census_path"].endswith("grievances/nested_json_census.csv"))

        # The manager side: both containers, separate IVs, status reports both.
        blobs = {}

        def upload(url, path):
            with open(path, "rb") as f:
                blobs[url] = f.read()

        output_key, _ = up.manager.output_key_for(uid)
        fd = P3DX_SDK._get_fetch_data()
        with mock.patch.object(direct_upload, "get_manager", return_value=up.manager), \
                mock.patch.object(direct_upload, "_scratch_dir", return_value=scratch), \
                mock.patch.object(direct_upload, "_output_blob_base_url",
                                  return_value="https://acct.blob.core.windows.net/output-data"), \
                mock.patch.object(fd, "upload_blob", side_effect=upload):
            direct_upload.finalize_output(uid, posted["output_path"], posted["filename"],
                                          posted["content_type"], census_path=posted["census_path"])

        main_url = f"https://acct.blob.core.windows.net/output-data/{uid}.enc"
        census_url = f"https://acct.blob.core.windows.net/output-data/{uid}/nested_json_census.csv.enc"
        self.assertEqual(set(blobs), {main_url, census_url})
        main_header, main = read_output_container(io.BytesIO(blobs[main_url]), output_key)
        census_header, census = read_output_container(io.BytesIO(blobs[census_url]), output_key)
        self.assertEqual(json.loads(main)["source"], "grievances_data")
        self.assertTrue(census.startswith(b"path,seen,action"))
        self.assertNotEqual(main_header["base_iv"], census_header["base_iv"], "fresh IV per container")
        with open(os.path.join(self.out, "status.json")) as f:
            status = json.load(f)
        self.assertEqual(status["outputs"]["direct"]["outputBlobUrl"], main_url)
        self.assertEqual(status["outputs"]["census"]["outputBlobUrl"], census_url)

    def test_census_path_outside_the_output_is_refused(self):
        with self.assertRaisesRegex(direct_upload.UploadError, "census_path"):
            direct_upload.finalize_output("x", "", "f", "t", census_path="/etc/passwd")


# --------------------------------------------------------------------------- #
# With the real SKALD binary
# --------------------------------------------------------------------------- #


@unittest.skipUnless(HAVE_SKALD, "SKALD pipeline binary not available")
class RealSkaldNestedRun(TempDirCase):
    CONFIG = {"data_type": "grievances", "grievances": {
        "nested_json": True, "dry_run": False, "input_path": "data",
        "output_path": "grievances", "output_directory": "output",
        "default_action": "suppress",
        "keep": ["[].current_road_details.name"],
        "suppress": ["**.phone", "**.latitude"],
        "hashing_with_salt": ["[].id", "**.complaint"],
        "qi_constraints": {"[].created": {"precision": "month"}},
    }}
    DOCS = [{"id": "G-1", "phone": "9876543210", "latitude": 12.97, "complaint": "pothole",
             "created": "2026-03-14T10:00:00", "current_road_details": {"name": "MG Road", "ward": 7}}]

    def test_skald_output_selection_returns_the_document_and_census_only(self):
        for d in ("config", "data"):
            os.makedirs(os.path.join(self.dir, d))
        with open(os.path.join(self.dir, "config", "config.json"), "w") as f:
            json.dump(self.CONFIG, f)
        with open(os.path.join(self.dir, "data", "grievances.json"), "w") as f:
            json.dump(self.DOCS, f)
        proc = subprocess.run([SKALD_BIN], cwd=self.dir, capture_output=True, text=True, timeout=120)
        out = os.path.join(self.dir, "output")
        with open(os.path.join(out, "status.json")) as f:
            status = json.load(f)
        self.assertEqual(status["outputs"]["mode"], "nested_json_deidentification",
                         f"{status}\n{proc.stdout[-1500:]}")
        self.assertTrue(os.path.isfile(os.path.join(out, "nested_json_salt.json")),
                        "SKALD writes the salt at the top of the output directory")

        chosen = P3DX_SDK.blob_output_files(out, os.path.join(out, "status.json"))
        names = [os.path.relpath(p, out) for p in chosen]
        self.assertEqual(names[:2], ["grievances/grievances.json", "grievances/nested_json_census.csv"])
        self.assertEqual(set(names) & set(ALL_KEYS), set())

        with open(chosen[0]) as f:
            doc = json.load(f)
        blob = json.dumps(doc)
        for secret in ("9876543210", "12.97", "pothole", "G-1"):
            self.assertNotIn(secret, blob)
        self.assertIn("MG Road", blob)


if __name__ == "__main__":
    unittest.main()
