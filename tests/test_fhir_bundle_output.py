"""FHIR Bundle SKALD runs (`fhir_bundle: true`): what leaves the enclave.

Added 2026-11-22 with the Anamika FHIR levels page. SKALD's FHIR flow
(src/pipeline/fhir_bundle.rs) writes one `<stem>_anonymised.fhir.json` per
input Bundle into `output/<output_path>/` with `fhir_bundle_census.csv` beside
them, and reports outputs.mode "fhir_bundle_deidentification". Its salts go to
the keys directory, never output/. Before this change the enclave did not
recognise that mode, so a FHIR run succeeded and returned nothing.

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

from tests.test_folder_upload import HAVE_SKALD, SKALD_BIN, TempDirCase, _Uploads, build_tar  # sys.path + stubs

import P3DX_SDK
from lib import direct_upload, folder_bundle
from lib.config import config
from enclave.enclave_direct_upload import read_output_container

BUNDLE = {"resourceType": "Bundle", "type": "collection", "entry": [
    {"fullUrl": "urn:uuid:p1", "resource": {"resourceType": "Patient", "id": "p1", "gender": "male"}}]}


class FhirOutputCase(TempDirCase):
    """An output directory shaped exactly as SKALD's fhir_bundle run leaves it."""

    def setUp(self):
        super().setUp()
        self.out = os.path.join(self.dir, "output")
        os.makedirs(self.out)
        p = mock.patch.object(config.paths, "tee_output", self.out)
        p.start()
        self.addCleanup(p.stop)

    def fhir_run(self, stems=("CASE_1",), subdir="nha_fhir", mode="fhir_bundle_deidentification", skipped=0):
        docs = os.path.join(self.out, subdir)
        os.makedirs(docs, exist_ok=True)
        for stem in stems:
            with open(os.path.join(docs, f"{stem}_anonymised.fhir.json"), "w") as f:
                json.dump(dict(BUNDLE, id=stem), f)
        with open(os.path.join(docs, "fhir_bundle_census.csv"), "w") as f:
            f.write("path,documents_seen,non_empty,action,matched_by,example_value\nPatient.gender,1,1,keep,Patient.gender,male\n")
        status = {"status": "ok", "phase": "done", "outputs": {
            "mode": mode, "dry_run": mode.endswith("dry_run"),
            "output_directory": f"./output/{subdir}",
            "key_census": f"./output/{subdir}/fhir_bundle_census.csv",
            "documents_examined": len(stems) + skipped, "documents_written": len(stems),
            "documents_skipped": skipped, "paths_seen": 12, "paths_kept": 5,
            "resources_dropped": 2, "propagation_suppressed": 1, "k_anonymity_applied": False}}
        with open(os.path.join(self.out, "status.json"), "w") as f:
            json.dump(status, f)
        return status


class Selection(FhirOutputCase):
    def test_one_bundle_is_the_result_with_the_census_beside_it(self):
        nested = P3DX_SDK.nested_json_outputs(self.out, self.fhir_run())
        self.assertEqual(nested.mode, P3DX_SDK.FHIR_BUNDLE_MODE)
        self.assertEqual([os.path.basename(p) for p in nested.documents], ["CASE_1_anonymised.fhir.json"])
        self.assertTrue(nested.census.endswith("nha_fhir/fhir_bundle_census.csv"))
        self.assertEqual(P3DX_SDK.nested_json_result(nested, self.out, "x"), nested.documents[0])

    def test_several_bundles_come_back_as_a_fhir_archive(self):
        nested = P3DX_SDK.nested_json_outputs(self.out, self.fhir_run(stems=("A", "B"), skipped=1))
        archive = P3DX_SDK.nested_json_result(nested, self.out, "claims")
        self.assertTrue(archive.endswith("claims_fhir_bundles.tar"))
        with tarfile.open(archive) as tf:
            self.assertEqual(sorted(tf.getnames()),
                             ["A_anonymised.fhir.json", "B_anonymised.fhir.json", "_manifest.json"])

    def test_a_dry_run_is_a_clear_failure(self):
        with self.assertRaisesRegex(P3DX_SDK.NestedJsonOutputError, "FHIR Bundle dry run"):
            P3DX_SDK.nested_json_outputs(self.out, self.fhir_run(mode="fhir_bundle_dry_run"))

    def test_documents_at_the_top_of_the_output_are_refused(self):
        status = self.fhir_run(subdir=".")
        status["outputs"]["output_directory"] = "./output"
        with self.assertRaises(P3DX_SDK.NestedJsonOutputError):
            P3DX_SDK.nested_json_outputs(self.out, status)

    def test_salts_are_never_selected_even_if_misplaced(self):
        self.fhir_run()
        for where in (self.out, os.path.join(self.out, "nha_fhir")):
            with open(os.path.join(where, "fhir_bundle_salts.json"), "w") as f:
                f.write("{}")
        chosen = [os.path.basename(p) for p in
                  P3DX_SDK.blob_output_files(self.out, os.path.join(self.out, "status.json"))]
        self.assertNotIn("fhir_bundle_salts.json", chosen)
        self.assertEqual(chosen[:2], ["CASE_1_anonymised.fhir.json", "fhir_bundle_census.csv"])


class DirectModeUpload(FhirOutputCase):
    def test_handoff_finalize_and_counts_in_status(self):
        self.fhir_run()
        scratch = os.path.join(self.dir, "scratch")
        up = _Uploads(scratch)
        ref = up.upload("u1", "CASE_1.json", "json", json.dumps(BUNDLE).encode())
        uid = ref.rsplit("/", 1)[1]
        with open(os.path.join(scratch, f"{uid}.meta.json"), "w") as f:
            json.dump({"filename": "CASE_1.json", "format": "json"}, f)
        posted = {}

        def post(url, json=None, timeout=None):
            posted.update(json)
            return mock.Mock(status_code=200, json=lambda: {"outputBlobUrl": "x"})

        with mock.patch.object(direct_upload, "_scratch_dir", return_value=scratch), \
                mock.patch.object(P3DX_SDK, "load_config_file",
                                  return_value={"enclaveManagerAddress": "http://127.0.0.1:4000"}), \
                mock.patch.object(P3DX_SDK.requests, "post", post):
            P3DX_SDK._upload_direct_output(self.out, {"blobUrl": ref})

        self.assertTrue(posted["output_path"].endswith("nha_fhir/CASE_1_anonymised.fhir.json"))
        self.assertTrue(posted["census_path"].endswith("nha_fhir/fhir_bundle_census.csv"))

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

        census_url = f"https://acct.blob.core.windows.net/output-data/{uid}/fhir_bundle_census.csv.enc"
        self.assertIn(census_url, blobs)
        _, main = read_output_container(io.BytesIO(blobs[f"https://acct.blob.core.windows.net/output-data/{uid}.enc"]), output_key)
        self.assertEqual(json.loads(main)["resourceType"], "Bundle")
        with open(os.path.join(self.out, "status.json")) as f:
            outputs = json.load(f)["outputs"]
        # The counts the Anamika output page shows survive the status rewrite;
        # container paths do not.
        self.assertEqual(outputs["mode"], "fhir_bundle_deidentification")
        self.assertEqual((outputs["documents_written"], outputs["resources_dropped"],
                          outputs["propagation_suppressed"]), (1, 2, 1))
        self.assertNotIn("output_directory", outputs)
        self.assertNotIn("key_census", outputs)
        self.assertNotIn("k_anonymity_applied", outputs)

    def test_any_other_census_name_is_still_refused(self):
        bad = os.path.join(self.out, "symmetric_keys.json")
        with open(bad, "w") as f:
            f.write("{}")
        with self.assertRaisesRegex(direct_upload.UploadError, "census_path must name"):
            direct_upload.finalize_output("x", "", "f", "t", census_path=bad)


class FreeTextStageRefused(TempDirCase):
    def write_config(self, section):
        cfg_dir = os.path.join(self.dir, "config")
        os.makedirs(cfg_dir, exist_ok=True)
        with open(os.path.join(cfg_dir, "config.json"), "w") as f:
            json.dump({"data_type": "nha", "nha": section}, f)
        p = mock.patch.object(config.paths, "tee_input_config", cfg_dir)
        p.start()
        self.addCleanup(p.stop)

    def test_fhir_with_free_text_enabled_fails_before_skald_fta_runs(self):
        self.write_config({"fhir_bundle": True, "input_path": "data", "keep": ["Bundle.type"],
                           "free_text_anonymization": {"enabled": True, "columns": ["x"]}})
        self.assertTrue(P3DX_SDK.is_fhir_bundle_run())
        with self.assertRaisesRegex(RuntimeError, "not supported for FHIR Bundles"):
            P3DX_SDK.run_free_text_anonymization()

    def test_fhir_without_free_text_goes_straight_to_skald(self):
        self.write_config({"fhir_bundle": True, "input_path": "data", "keep": ["Bundle.type"]})
        self.assertFalse(P3DX_SDK.run_free_text_anonymization())

    def test_a_tabular_config_is_not_fhir(self):
        self.write_config({"suppress": ["name"]})
        self.assertFalse(P3DX_SDK.is_fhir_bundle_run())


class FolderStaging(TempDirCase):
    def test_bundles_are_staged_one_file_each_never_combined(self):
        raw = json.dumps(BUNDLE).encode()
        tar = build_tar(self.path("in.tar"), [("claims/A.json", raw), ("claims/sub/A.json", raw),
                                              ("claims/B.json", raw), ("claims/readme.txt", b"x")])
        dest = os.path.join(self.dir, "data")
        result = folder_bundle.stage_fhir_bundles(folder_bundle.tar_members(tar), dest)
        self.assertEqual(result.files_total, 3)
        self.assertEqual(sorted(os.listdir(dest)), ["A.json", "A_1.json", "B.json"])
        with open(os.path.join(dest, "B.json"), "rb") as f:
            self.assertEqual(f.read(), raw, "staged byte for byte")

    def test_a_folder_without_json_is_refused(self):
        tar = build_tar(self.path("in.tar"), [("x/readme.txt", b"x")])
        with self.assertRaises(folder_bundle.FolderError):
            folder_bundle.stage_fhir_bundles(folder_bundle.tar_members(tar), os.path.join(self.dir, "data"))

    def test_only_a_fhir_section_takes_this_path(self):
        self.assertTrue(folder_bundle.is_fhir_section({"fhir_bundle": True}))
        self.assertFalse(folder_bundle.is_fhir_section({"nested_json": True}))
        self.assertFalse(folder_bundle.is_fhir_section(None))


@unittest.skipUnless(HAVE_SKALD, "SKALD pipeline binary not available")
class RealSkaldFhirRun(TempDirCase):
    CONFIG = {"data_type": "nha_fhir", "nha_fhir": {
        "fhir_bundle": True, "dry_run": False, "input_path": "data", "output_path": "nha_fhir",
        "output_directory": "output", "default_action": "suppress",
        "keep": ["Bundle.type", "Patient.gender"], "suppress": ["Patient.name.**"],
        "_fhir_levels": {"level": 2}}}

    def test_skald_output_selection_returns_the_bundle_and_census_only(self):
        for d in ("config", "data"):
            os.makedirs(os.path.join(self.dir, d))
        with open(os.path.join(self.dir, "config", "config.json"), "w") as f:
            json.dump(self.CONFIG, f)
        doc = json.loads(json.dumps(BUNDLE))
        doc["entry"][0]["resource"]["name"] = [{"text": "Ramesh Kumar"}]
        with open(os.path.join(self.dir, "data", "CASE_9.fhir.json"), "w") as f:
            json.dump(doc, f)
        proc = subprocess.run([SKALD_BIN], cwd=self.dir, capture_output=True, text=True, timeout=120)
        out = os.path.join(self.dir, "output")
        with open(os.path.join(out, "status.json")) as f:
            status = json.load(f)
        self.assertEqual(status["outputs"]["mode"], "fhir_bundle_deidentification",
                         f"{status}\n{proc.stdout[-1500:]}")
        chosen = P3DX_SDK.blob_output_files(out, os.path.join(out, "status.json"))
        names = [os.path.relpath(p, out) for p in chosen]
        self.assertEqual(names[:2], ["nha_fhir/CASE_9_anonymised.fhir.json", "nha_fhir/fhir_bundle_census.csv"])
        self.assertNotIn("fhir_bundle_salts.json", {os.path.basename(n) for n in names})
        with open(chosen[0]) as f:
            blob = f.read()
        self.assertNotIn("Ramesh", blob)
        self.assertIn('"male"', blob)


if __name__ == "__main__":
    unittest.main()
