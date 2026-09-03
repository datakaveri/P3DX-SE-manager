"""Which file a direct upload returns.

This is the step that decides what the requester actually receives, and it had
no coverage at all — which is how `_select_tabular_output` came to read the
wrong level of status.json and return None for every run ever made. Nothing
noticed, because CSV input writes exactly one file and the caller's fallback
picked it. The first workbook submitted wrote generalized.csv AND
generalized.xlsx, and the run failed as "ambiguous" having anonymised the data
perfectly well.

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

# The SDK pulls in python-dotenv purely to load an .env that is absent here.
if "dotenv" not in sys.modules:
    _stub = types.ModuleType("dotenv")
    _stub.load_dotenv = lambda *a, **k: None
    sys.modules["dotenv"] = _stub

import P3DX_SDK  # noqa: E402


class SelectionTestCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="p3dx-output-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.status_path = os.path.join(self.dir, "status.json")

    def write(self, name, content=b"x"):
        path = os.path.join(self.dir, name)
        with open(path, "wb") as fh:
            fh.write(content)
        return path

    def write_status(self, payload):
        with open(self.status_path, "w") as fh:
            json.dump(payload, fh)

    def select(self):
        return P3DX_SDK._select_tabular_output(self.dir, self.status_path)


class TestStatusNamesTheResult(SelectionTestCase):
    def test_the_path_is_read_from_the_outputs_section(self):
        """The regression. SKALD nests these alongside the run statistics; they
        are not top-level fields, and reading only the top level made this
        function dead code from the day it was written."""
        self.write("generalized.csv")
        self.write("generalized.xlsx")
        self.write_status({
            "status": "success",
            "outputs": {
                "final_output_path": "./output/generalized.csv",
                "format_matched_output_path": "./output/generalized.xlsx",
            },
        })
        self.assertEqual(os.path.basename(self.select()), "generalized.xlsx",
                         "the workbook is what the requester submitted")

    def test_a_top_level_path_still_works(self):
        """Kept so a container that promotes these to the root does not break."""
        self.write("generalized.csv")
        self.write_status({"final_output_path": "./output/generalized.csv"})
        self.assertEqual(os.path.basename(self.select()), "generalized.csv")

    def test_the_restored_workbook_wins(self):
        for name in ("generalized.csv", "generalized.xlsx", "restored.xlsx"):
            self.write(name)
        self.write_status({"outputs": {
            "final_output_path": "./output/generalized.csv",
            "format_matched_output_path": "./output/generalized.xlsx",
            "restored_workbook_path": "./output/restored.xlsx",
        }})
        self.assertEqual(os.path.basename(self.select()), "restored.xlsx")

    def test_a_named_file_that_does_not_exist_falls_through(self):
        self.write("generalized.csv")
        self.write_status({"outputs": {
            "format_matched_output_path": "./output/generalized.xlsx",
            "final_output_path": "./output/generalized.csv",
        }})
        self.assertEqual(os.path.basename(self.select()), "generalized.csv")

    def test_a_path_outside_the_output_directory_is_refused(self):
        """status.json is written by the container, so treating a path in it as
        authoritative would let a compromised image name any file on the host
        and have it encrypted and uploaded."""
        self.write("generalized.csv")
        outside = os.path.join(self.dir, "..", "escape.csv")
        with open(outside, "wb") as fh:
            fh.write(b"secret")
        self.addCleanup(os.remove, outside)
        self.write_status({"outputs": {"final_output_path": outside}})
        # Only the basename is used, so this resolves inside the directory and
        # finds nothing rather than escaping.
        self.assertIsNone(self.select())

    def test_missing_or_unparseable_status_returns_none(self):
        self.assertIsNone(self.select())
        with open(self.status_path, "w") as fh:
            fh.write("{not json")
        self.assertIsNone(self.select())

    def test_a_status_naming_nothing_returns_none(self):
        self.write("generalized.csv")
        self.write_status({"status": "success", "outputs": {"total_records": 10}})
        self.assertIsNone(self.select())


class TestFallbackOnSubmittedFormat(SelectionTestCase):
    """When status.json names nothing, the submitted format decides.

    Someone who uploads a workbook should get a workbook back — which is also
    what SKALD's own log says it wrote.
    """

    def choose(self, candidates, fmt):
        return P3DX_SDK._select_by_submitted_format(self.dir, candidates, fmt)

    def test_excel_input_gets_the_workbook(self):
        self.write("generalized.csv")
        self.write("generalized.xlsx")
        chosen = self.choose(["generalized.xlsx", "generalized.csv"], "excel")
        self.assertEqual(os.path.basename(chosen), "generalized.xlsx")

    def test_json_input_gets_the_json(self):
        self.write("generalized.csv")
        self.write("generalized.json")
        chosen = self.choose(["generalized.json", "generalized.csv"], "json")
        self.assertEqual(os.path.basename(chosen), "generalized.json")

    def test_csv_input_gets_the_csv(self):
        self.write("generalized.csv")
        self.write("generalized.xlsx")
        chosen = self.choose(["generalized.xlsx", "generalized.csv"], "csv")
        self.assertEqual(os.path.basename(chosen), "generalized.csv")

    def test_it_falls_back_to_csv_when_the_sibling_is_absent(self):
        self.write("generalized.csv")
        chosen = self.choose(["generalized.csv"], "excel")
        self.assertEqual(os.path.basename(chosen), "generalized.csv")

    def test_an_unknown_format_does_not_guess(self):
        self.write("generalized.csv")
        self.write("generalized.xlsx")
        self.assertIsNone(self.choose(["generalized.xlsx", "generalized.csv"], "parquet"))
        self.assertIsNone(self.choose(["generalized.xlsx", "generalized.csv"], None))

    def test_an_unexpected_file_makes_it_refuse(self):
        """Outside SKALD's generalized.* family there is no principled choice,
        and guessing is worse than an explicit ambiguity error — the wrong file
        here means shipping data that was never anonymised."""
        self.write("generalized.csv")
        self.write("staged_free_text.csv")
        self.assertIsNone(
            self.choose(["generalized.csv", "staged_free_text.csv"], "csv"))


class TestTheWholeSelectionTogether(SelectionTestCase):
    """The wiring, not just the pieces.

    `_select_tabular_output` was correct in isolation for its whole life and
    simply never returned anything, so testing the parts would not have caught
    the original bug. This exercises the actual decision the run makes.
    """

    def resolve(self, fmt="csv"):
        return P3DX_SDK.resolve_tabular_output_path(self.dir, self.status_path, fmt)

    def test_the_workbook_run_that_failed_in_production_now_resolves(self):
        """c74e519e: an Excel upload, preprocess-only, SKALD wrote both files.
        It failed three times across two TEEs having anonymised the data
        correctly."""
        self.write("generalized.csv")
        self.write("generalized.xlsx")
        self.write("symmetric_keys.json")
        self.write("fpe_encrypt_keys.json")
        self.write("pipeline.log")
        self.write_status({"status": "success", "outputs": {"total_records": 5}})
        self.assertEqual(os.path.basename(self.resolve("excel")), "generalized.xlsx")

    def test_status_beats_the_format_fallback(self):
        self.write("generalized.csv")
        self.write("generalized.xlsx")
        self.write_status({"outputs": {"final_output_path": "./output/generalized.csv"}})
        self.assertEqual(os.path.basename(self.resolve("excel")), "generalized.csv",
                         "an explicit answer must win over an inferred one")

    def test_a_single_candidate_still_works_without_status(self):
        self.write("generalized.csv")
        self.write("pipeline.log")
        self.assertEqual(os.path.basename(self.resolve("csv")), "generalized.csv")

    def test_diagnostics_and_key_material_are_never_the_result(self):
        self.write("generalized.csv")
        for noise in ("symmetric_keys.json", "fpe_encrypt_keys.json",
                      "parameter_grid.txt", "equivalence_class_stats.json",
                      "top_ola2_nodes.json", "pipeline.log"):
            self.write(noise)
        self.assertEqual(os.path.basename(self.resolve("csv")), "generalized.csv")

    def test_a_preserved_status_from_a_retry_is_not_counted(self):
        """The scheduler requeues onto another TEE and may land back here, so a
        previous attempt's preserved status must not read as an extra result."""
        self.write("generalized.csv")
        self.write("status.json" + P3DX_SDK.PIPELINE_STATUS_SUFFIX)
        self.assertEqual(os.path.basename(self.resolve("csv")), "generalized.csv")

    def test_genuine_ambiguity_still_refuses(self):
        self.write("generalized.csv")
        self.write("something_else.csv")
        with self.assertRaises(RuntimeError):
            self.resolve("csv")


class TestTheContainerStatusIsPreserved(SelectionTestCase):
    """A failure must not destroy the record of what the pipeline produced.

    Diagnosing the first workbook upload meant reconstructing the run from
    pipeline.log, because the error status had already replaced the real one.
    """

    def test_the_original_status_is_kept_alongside_the_error(self):
        self.write_status({"status": "success", "outputs": {"total_records": 7}})

        real_get_path = P3DX_SDK.config.get_path
        P3DX_SDK.config.get_path = lambda key: (
            self.status_path if key == "status" else real_get_path(key))
        try:
            P3DX_SDK._write_direct_error_status("something went wrong")
        finally:
            P3DX_SDK.config.get_path = real_get_path

        with open(self.status_path) as fh:
            self.assertEqual(json.load(fh)["status"], "error")

        preserved = self.status_path + P3DX_SDK.PIPELINE_STATUS_SUFFIX
        self.assertTrue(os.path.isfile(preserved), "the pipeline's status was lost")
        with open(preserved) as fh:
            self.assertEqual(json.load(fh)["outputs"]["total_records"], 7)


class TestTwoPassKAnonPassOne(SelectionTestCase):
    """Pass 1 of two-pass k-anon produces no result file on purpose.

    It writes a parameter grid for the user to choose k from and stops. The
    direct-upload finaliser used to demand exactly one result file, fail with
    'found 0', and — via _write_direct_error_status — overwrite the grid with a
    generic error before the completion callback could carry it to the UI. A
    successful analysis was reported as a failure and the grid destroyed.
    """

    # A real pass-1 status.json, shape confirmed against a live enclave run.
    PASS1_STATUS = {
        "status": "success",
        "phase": "awaiting_pass2",
        "outputs": {
            "pass": "pass1",
            "k_optimal": 10,
            "suppression_limit": 0.01,
            "total_records": 10,
            "parameter_grid": [
                {"k": 5, "suppression_limit": 0.0, "best_node": [48, 374020],
                 "dm_star": 100, "num_equivalence_classes": 1,
                 "suppression_count": 0, "feasible": True},
            ],
        },
    }

    def _patch_status_path(self):
        real_get_path = P3DX_SDK.config.get_path
        P3DX_SDK.config.get_path = lambda key: (
            self.status_path if key == "status" else real_get_path(key))
        self.addCleanup(setattr, P3DX_SDK.config, "get_path", real_get_path)

    def test_pass1_returns_none_without_uploading(self):
        self.write_status(self.PASS1_STATUS)
        self._patch_status_path()
        # urls with an enclave upload blobUrl so we know the early return, not
        # the blobUrl guard, is what stops it. If the pass-1 branch were absent
        # this would proceed to meta parsing / finalize_output (a network call)
        # rather than returning None.
        result = P3DX_SDK._upload_direct_output(
            self.dir, {"blobUrl": "enclave://upload/job-123"})
        self.assertIsNone(result)

    def test_pass1_leaves_the_grid_intact(self):
        self.write_status(self.PASS1_STATUS)
        self._patch_status_path()
        P3DX_SDK._upload_direct_output(
            self.dir, {"blobUrl": "enclave://upload/job-123"})

        # status.json must NOT be overwritten to an error, and no .pipeline
        # backup created — the grid is what the completion callback forwards.
        with open(self.status_path) as fh:
            after = json.load(fh)
        self.assertEqual(after["phase"], "awaiting_pass2")
        self.assertEqual(after["outputs"]["k_optimal"], 10)
        self.assertFalse(
            os.path.isfile(self.status_path + P3DX_SDK.PIPELINE_STATUS_SUFFIX),
            "pass 1 must not trigger the error-status rewrite")

    def test_a_real_error_status_still_refuses(self):
        # The pass-1 branch must not swallow a genuine failure: an error status
        # still raises rather than being mistaken for a no-file success.
        self.write_status({"status": "error", "error": "boom"})
        self._patch_status_path()
        with self.assertRaises(RuntimeError):
            P3DX_SDK._upload_direct_output(
                self.dir, {"blobUrl": "enclave://upload/job-123"})


class TestPipelineStatusInErrorMessage(SelectionTestCase):
    """The 'found N' failure should name what the pipeline actually did, not
    just the finaliser's file count."""

    def test_error_status_is_surfaced(self):
        self.write_status({"status": "error", "error": "SKALD crashed on column X"})
        note = P3DX_SDK._describe_pipeline_status(self.status_path)
        self.assertIn("SKALD crashed on column X", note)

    def test_success_but_no_file_is_named(self):
        self.write_status({"status": "success", "phase": "some_phase"})
        note = P3DX_SDK._describe_pipeline_status(self.status_path)
        self.assertIn("success", note)
        self.assertIn("some_phase", note)
        self.assertIn("no", note.lower())

    def test_absent_status_falls_back_to_guidance(self):
        note = P3DX_SDK._describe_pipeline_status(
            os.path.join(self.dir, "does-not-exist.json"))
        self.assertIn("Narrow the pipeline's output", note)

    def test_the_full_message_embeds_the_pipeline_note(self):
        # resolve_tabular_output_path with two ambiguous files and an error
        # status must carry the pipeline's reason into the RuntimeError.
        self.write("generalized.csv")
        self.write("extra.csv")
        self.write_status({"status": "error", "error": "downstream boom"})
        real_get_path = P3DX_SDK.config.get_path
        P3DX_SDK.config.get_path = lambda key: (
            self.status_path if key == "status" else real_get_path(key))
        self.addCleanup(setattr, P3DX_SDK.config, "get_path", real_get_path)
        with self.assertRaises(RuntimeError) as ctx:
            P3DX_SDK.resolve_tabular_output_path(self.dir, self.status_path, "csv")
        self.assertIn("downstream boom", str(ctx.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
