"""The direct-upload status write must keep the application's query result.

It used to replace status.json wholesale with
{status, application, outputs:{direct}}. For an anonymisation run that lost
nothing — the result IS the encrypted file. For a DP query run it lost
everything: the answer is the result object and it lives nowhere else, so a DP
job over direct upload returned no result at all.

Run:  python3 -m unittest discover -s tests
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if "dotenv" not in sys.modules:
    _stub = types.ModuleType("dotenv")
    _stub.load_dotenv = lambda *a, **k: None
    sys.modules["dotenv"] = _stub

from lib import direct_upload  # noqa: E402
from lib.config import config  # noqa: E402

DIRECT = {"outputBlobUrl": "https://acct.blob.core.windows.net/out/job-1.enc",
          "filename": "patients_anonymised.csv", "bytes": 42}
PLOTS = {"plot_convergence": "https://acct/out/job-1/conv.png.enc",
         "plot_wcss": "https://acct/out/job-1/wcss.png.enc"}


class StatusMergeTestCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="p3dx-status-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.status_path = os.path.join(self.dir, "status.json")

        real_get_path = config.get_path
        config.get_path = lambda key: (
            self.status_path if key == "status" else real_get_path(key))
        self.addCleanup(setattr, config, "get_path", real_get_path)

    def write_app_status(self, payload):
        with open(self.status_path, "w") as fh:
            json.dump(payload, fh)

    def read(self):
        with open(self.status_path) as fh:
            return json.load(fh)


class TestTheApplicationResultSurvives(StatusMergeTestCase):
    def test_result_is_carried_across(self):
        self.write_app_status({"status": "success", "application": "skald-dp",
                               "result": {"query": "kmeans", "centroids": [[1, 2]]}})
        direct_upload._write_direct_status(DIRECT)
        after = self.read()
        self.assertEqual(after["result"]["centroids"], [[1, 2]])
        self.assertEqual(after["outputs"]["direct"], DIRECT)

    def test_results_plural_is_carried_across(self):
        self.write_app_status({"status": "success", "results": [{"query": "mean"}]})
        direct_upload._write_direct_status(DIRECT)
        self.assertEqual(self.read()["results"], [{"query": "mean"}])

    def test_the_direct_contract_still_describes_this_write(self):
        # The application's own status/application/outputs must NOT survive:
        # they describe the container's contract, and the UI reads a
        # direct-upload run's shape off these fields.
        self.write_app_status({"status": "error", "application": "skald-dp",
                               "outputs": {"total_records": 7},
                               "result": {"query": "kmeans"}})
        direct_upload._write_direct_status(DIRECT)
        after = self.read()
        self.assertEqual(after["status"], "success")
        self.assertEqual(after["application"], "direct-upload")
        self.assertNotIn("total_records", after["outputs"])

    def test_an_absent_application_status_is_fine(self):
        direct_upload._write_direct_status(DIRECT)
        after = self.read()
        self.assertEqual(after["outputs"]["direct"], DIRECT)
        self.assertNotIn("result", after)

    def test_unparseable_application_status_is_fine(self):
        with open(self.status_path, "w") as fh:
            fh.write("{not json")
        direct_upload._write_direct_status(DIRECT)
        self.assertEqual(self.read()["status"], "success")


class TestPlotUrlsAreAttachedToTheResult(StatusMergeTestCase):
    def test_they_land_on_the_kmeans_object(self):
        self.write_app_status({"status": "success",
                               "result": {"query": "kmeans", "k": 3}})
        direct_upload._write_direct_status(DIRECT, plot_urls=PLOTS)
        result = self.read()["result"]
        self.assertEqual(result["plot_convergence"], PLOTS["plot_convergence"])
        self.assertEqual(result["plot_wcss"], PLOTS["plot_wcss"])
        self.assertEqual(result["k"], 3, "the application's own fields stay")

    def test_they_land_on_a_nested_kmeans_object(self):
        # The application owns the result's shape; the k-means object is found
        # wherever it is rather than at an assumed path.
        self.write_app_status({"status": "success", "results": [
            {"query": "mean", "value": 1},
            {"query": "kmeans", "k": 2},
        ]})
        direct_upload._write_direct_status(DIRECT, plot_urls=PLOTS)
        results = self.read()["results"]
        self.assertNotIn("plot_convergence", results[0])
        self.assertEqual(results[1]["plot_convergence"], PLOTS["plot_convergence"])

    def test_no_kmeans_object_is_survivable(self):
        self.write_app_status({"status": "success", "result": {"query": "mean"}})
        direct_upload._write_direct_status(DIRECT, plot_urls=PLOTS)
        after = self.read()
        self.assertEqual(after["result"], {"query": "mean"})
        self.assertEqual(after["status"], "success", "the run still succeeded")

    def test_no_plot_or_plot_grid_field_is_invented(self):
        self.write_app_status({"status": "success", "result": {"query": "kmeans"}})
        direct_upload._write_direct_status(DIRECT, plot_urls=PLOTS)
        result = self.read()["result"]
        self.assertNotIn("plot", result)
        self.assertNotIn("plot_grid", result)


class TestAQueryOnlyRunHasNoDirectOutput(StatusMergeTestCase):
    def test_outputs_direct_is_omitted(self):
        # A DP query run encrypts no result file, so there is no blob to
        # describe — but the result and its plots still have to be reported.
        self.write_app_status({"status": "success", "result": {"query": "kmeans"}})
        direct_upload._write_direct_status(None, plot_urls=PLOTS)
        after = self.read()
        self.assertNotIn("direct", after["outputs"])
        self.assertEqual(after["result"]["plot_wcss"], PLOTS["plot_wcss"])


class TestTheOutputKeysMustAgree(StatusMergeTestCase):
    """The browser stores ONE output key per job and the decrypt hook has no
    fallback. The enclave receives that key twice by unrelated routes — the
    bundle (unwrapped in the deploy subprocess) and upload/init (unwrapped
    into the UploadManager session) — and nothing inside the enclave ties them
    together. If they disagree, encrypting anyway hands the user output they
    can never open, so the run is failed instead.
    """

    SESSION_KEY = b"s" * 32

    def setUp(self):
        super().setUp()
        import P3DX_SDK
        self.P3DX_SDK = P3DX_SDK

        self.addCleanup(setattr, config.paths, "tee_output", config.paths.tee_output)
        self.addCleanup(setattr, config.direct_upload, "output_container",
                        getattr(config.direct_upload, "output_container", None))
        config.paths.tee_output = self.dir          # no plots in here
        config.direct_upload.output_container = "acct/out"

        self.released = []
        manager = types.SimpleNamespace(
            output_key_for=lambda uid: (self.SESSION_KEY, b"v" * 12),
            release=self.released.append,
        )
        real_get_manager = direct_upload.get_manager
        direct_upload.get_manager = lambda: manager
        self.addCleanup(setattr, direct_upload, "get_manager", real_get_manager)

        self.uploads = []
        real_fetch = direct_upload._get_fetch_data
        direct_upload._get_fetch_data = lambda: types.SimpleNamespace(
            upload_blob=lambda url, path: self.uploads.append(url))
        self.addCleanup(setattr, direct_upload, "_get_fetch_data", real_fetch)

    def finalize(self, key_check):
        return direct_upload.finalize_output(
            "job-1", output_path="", filename="out", content_type="text/csv",
            output_key_check=key_check)

    def test_a_mismatch_is_refused(self):
        from enclave.enclave_direct_upload import UploadError
        self.write_app_status({"status": "success", "result": {"query": "kmeans"}})
        wrong = self.P3DX_SDK.output_key_check_value(b"other" * 8)

        with self.assertRaises(UploadError) as ctx:
            self.finalize(wrong)

        self.assertEqual(ctx.exception.status, 409)
        self.assertEqual(self.uploads, [], "nothing may be encrypted or uploaded")
        self.assertEqual(self.read()["result"], {"query": "kmeans"},
                         "the application's status must be left alone")

    def test_a_match_proceeds(self):
        self.write_app_status({"status": "success", "result": {"query": "kmeans"}})
        self.finalize(self.P3DX_SDK.output_key_check_value(self.SESSION_KEY))
        self.assertEqual(self.read()["status"], "success")
        self.assertEqual(self.released, ["job-1"])

    def test_an_absent_check_proceeds_unverified(self):
        # An older UI sends no per-run key in the bundle, so the subprocess has
        # nothing to compare; the session's key stands alone rather than the
        # run failing.
        self.write_app_status({"status": "success", "result": {"query": "kmeans"}})
        self.finalize(None)
        self.assertEqual(self.read()["status"], "success")


if __name__ == "__main__":
    unittest.main(verbosity=2)
