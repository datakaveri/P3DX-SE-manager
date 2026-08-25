#!/usr/bin/env python3
"""
Offline tests for the skald-fta pre-stage wiring in P3DX_SDK.

Covers the branching that decides whether free-text anonymisation runs, where
its artifacts land, and which files are withheld from the output upload — all
of it pure Python, so it runs on a dev box with no CVM, no Managed Identity
and no containers.

    python3 tools/fta_stage_test.py
"""

from __future__ import annotations

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import P3DX_SDK as sdk  # noqa: E402
from lib.config import config  # noqa: E402

FAILURES: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label} {detail}")
        FAILURES.append(label)


def expect_raises(label: str, fn, needle: str = "") -> None:
    try:
        fn()
    except RuntimeError as exc:
        if needle and needle.lower() not in str(exc).lower():
            print(f"  FAIL {label} — wrong error: {exc}")
            FAILURES.append(label)
        else:
            print(f"  ok   {label}")
        return
    print(f"  FAIL {label} — no RuntimeError raised")
    FAILURES.append(label)


class Sandbox:
    """Point config at scratch dirs so tests never touch the live TEE mounts."""

    def __enter__(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = self.tmp.name
        self.cfg_dir = os.path.join(root, "config")
        self.data_dir = os.path.join(root, "data")
        self.out_dir = os.path.join(root, "output")
        self.keys_dir = os.path.join(root, "keys")
        for d in (self.cfg_dir, self.data_dir, self.out_dir, self.keys_dir):
            os.makedirs(d)
        self.compose = os.path.join(root, "docker-compose.yml")

        self.fta_cfg_dir = os.path.join(root, "fta_config")

        self.saved = (config.paths.tee_input_config, config.paths.tee_input_data,
                      config.paths.tee_output, config.paths.keys_dir,
                      config.paths.tee_fta_config)
        self.saved_base = config._base_dir
        config.paths.tee_input_config = self.cfg_dir
        config.paths.tee_input_data = self.data_dir
        config.paths.tee_output = self.out_dir
        config.paths.keys_dir = self.keys_dir
        config.paths.tee_fta_config = self.fta_cfg_dir
        config._base_dir = root
        return self

    def __exit__(self, *exc):
        (config.paths.tee_input_config, config.paths.tee_input_data,
         config.paths.tee_output, config.paths.keys_dir,
         config.paths.tee_fta_config) = self.saved
        config._base_dir = self.saved_base
        self.tmp.cleanup()

    def write_app_config(self, payload, name="generated-config.json"):
        with open(os.path.join(self.cfg_dir, name), "w") as f:
            json.dump(payload, f)

    def write_compose(self, text):
        with open(self.compose, "w") as f:
            f.write(text)

    def touch_output(self, *names):
        for n in names:
            with open(os.path.join(self.out_dir, n), "w") as f:
                f.write("x")


FTA_BLOCK = {
    "enabled": True,
    "columns": ["notes"],
    "minimum_confidence": 0.8,
    "staged_input_path": "output/sanitized_input.csv",
    "audit_output_path": "output/free_text_audit.json",
    "on_failure": "fail",
}

SKALD_NOISE = {
    "k_anonymize": 5, "quasi_identifiers": ["age", "zip"], "suppress": ["ssn"],
    "hashing_with_salt": ["id"], "generalize": {"age": 5}, "size": 1000,
    "insensitive_columns": ["notes"],
}


def test_block_discovery():
    print("\nblock discovery (config[data_type].free_text_anonymization)")
    # 1. nested under the key data_type names — the documented shape
    block, where = sdk._find_free_text_block(
        {"data_type": "tabular", "tabular": {**SKALD_NOISE, "free_text_anonymization": FTA_BLOCK}})
    check("nested under data_type", block == FTA_BLOCK, f"got {where}")
    check("provenance names the path", where == "tabular.free_text_anonymization", f"got {where}")

    # 2. top level
    block, where = sdk._find_free_text_block({**SKALD_NOISE, "free_text_anonymization": FTA_BLOCK})
    check("top level", block == FTA_BLOCK)

    # 3. nested but data_type absent — found by scanning one level
    block, where = sdk._find_free_text_block({"tabular": {"free_text_anonymization": FTA_BLOCK}})
    check("nested without a data_type key", block == FTA_BLOCK, f"got {where}")

    # 4. genuinely absent
    block, where = sdk._find_free_text_block({**SKALD_NOISE, "format": "csv"})
    check("absent -> None", block is None and where is None)

    # 5. SKALD-only config must not trip the gate
    block, _ = sdk._find_free_text_block({"data_type": "tabular", "tabular": SKALD_NOISE})
    check("SKALD-only config -> None", block is None)


def test_enabled_coercion():
    print("\nenabled flag coercion")
    for value, expected in [(True, True), (False, False), ("true", True), ("false", False),
                            ("True", True), (1, True), (0, False), (None, False), ("", False)]:
        check(f"_as_bool({value!r}) == {expected}", sdk._as_bool(value) is expected)


def test_artifact_paths():
    print("\nstaged/audit path validation")
    check("output/-relative resolves to basename",
          sdk._fta_output_basename("output/sanitized_input.csv", "d.csv", "staged_input_path")
          == "sanitized_input.csv")
    check("bare filename accepted",
          sdk._fta_output_basename("sanitized.csv", "d.csv", "staged_input_path") == "sanitized.csv")
    check("absolute /app/output accepted",
          sdk._fta_output_basename("/app/output/s.csv", "d.csv", "staged_input_path") == "s.csv")
    check("empty falls back to the config.yml default",
          sdk._fta_output_basename(None, "sanitized_input.csv", "staged_input_path")
          == "sanitized_input.csv")

    expect_raises("absolute path outside /app/output rejected",
                  lambda: sdk._fta_output_basename("/tmp/s.csv", "d.csv", "staged_input_path"),
                  "under /app/output")
    expect_raises("path traversal rejected",
                  lambda: sdk._fta_output_basename("output/../../etc/s.csv", "d.csv", "staged_input_path"))
    expect_raises("subdirectory rejected",
                  lambda: sdk._fta_output_basename("output/sub/s.csv", "d.csv", "staged_input_path"),
                  "directly inside")
    expect_raises("data/ path rejected",
                  lambda: sdk._fta_output_basename("data/s.csv", "d.csv", "staged_input_path"))
    for reserved in ("status.json", "generalized.csv", "pipeline.log"):
        expect_raises(f"reserved name {reserved} rejected",
                      lambda r=reserved: sdk._fta_output_basename(f"output/{r}", "d.csv", "audit_output_path"),
                      "reserved")


def test_gate_is_noop_when_disabled():
    print("\ngate short-circuits (no container, no ledger)")
    with Sandbox() as sb:
        sb.write_app_config({"data_type": "tabular", "tabular": SKALD_NOISE})
        check("absent block -> returns False", sdk.run_free_text_anonymization() is False)
        check("absent block -> nothing to exclude", sdk.free_text_artifact_names() == set())

    with Sandbox() as sb:
        sb.write_app_config({"data_type": "tabular",
                             "tabular": {**SKALD_NOISE,
                                         "free_text_anonymization": {**FTA_BLOCK, "enabled": False}}})
        check("enabled:false -> returns False", sdk.run_free_text_anonymization() is False)
        check("enabled:false -> nothing to exclude", sdk.free_text_artifact_names() == set())

    with Sandbox() as sb:
        check("no config at all -> returns False", sdk.run_free_text_anonymization() is False)


def test_artifact_exclusion():
    print("\nupload exclusion set")
    with Sandbox() as sb:
        sb.write_app_config({"data_type": "tabular",
                             "tabular": {**SKALD_NOISE, "free_text_anonymization": FTA_BLOCK}})
        names = sdk.free_text_artifact_names()
        check("config-declared artifacts excluded",
              names == {"sanitized_input.csv", "free_text_audit.json"}, f"got {names}")

        sdk._record_free_text_artifacts({"sanitized_input.csv", "free_text_audit.json", "ner_cache.bin"})
        names = sdk.free_text_artifact_names()
        check("ledger unions with config",
              names == {"sanitized_input.csv", "free_text_audit.json", "ner_cache.bin"}, f"got {names}")
        check("ledger lives outside output/ (it would list itself)",
              not os.path.exists(os.path.join(sb.out_dir, "fta_artifacts.json")))

        sdk.clear_free_text_artifacts()
        check("clear drops the ledger, keeps config-declared",
              sdk.free_text_artifact_names() == {"sanitized_input.csv", "free_text_audit.json"})

    # A stale ledger must not survive into a run that never enabled the stage.
    with Sandbox() as sb:
        sb.write_app_config({"data_type": "tabular", "tabular": SKALD_NOISE})
        sdk._record_free_text_artifacts({"sanitized_input.csv"})
        check("stale ledger present before clear", sdk.free_text_artifact_names() == {"sanitized_input.csv"})
        sdk.clear_free_text_artifacts()
        check("cleared -> disabled run withholds nothing", sdk.free_text_artifact_names() == set())

    # SKALD's real result can never be excluded, even via the ledger.
    with Sandbox() as sb:
        sb.write_app_config({"free_text_anonymization": FTA_BLOCK})
        sdk._record_free_text_artifacts({"generalized.csv", "status.json", "sanitized_input.csv"})
        names = sdk.free_text_artifact_names()
        check("SKALD result never excluded", "generalized.csv" not in names, f"got {names}")
        check("status.json never excluded", "status.json" not in names, f"got {names}")


COMPOSE_OK = """services:
  skald-anonymisation:
    image: ghcr.io/datakaveri/skald:latest
    volumes:
      - {data}:/app/data
      - {cfg}:/app/config
      - {out}:/app/output
"""

COMPOSE_MISMATCH = """services:
  skald-anonymisation:
    image: ghcr.io/datakaveri/skald:latest
    volumes:
      - {data}:/app/data
      - /tmp/some_other_output:/app/output
"""

COMPOSE_NAMED_VOLUME = """services:
  skald-anonymisation:
    image: ghcr.io/datakaveri/skald:latest
    volumes:
      - results:/app/output
volumes:
  results:
"""

COMPOSE_LONG_FORM = """services:
  skald-anonymisation:
    image: ghcr.io/datakaveri/skald:latest
    volumes:
      - type: bind
        source: {out}
        target: /app/output
"""

COMPOSE_WITH_FTA_FIRST = """services:
  skald-fta:
    image: ghcr.io/datakaveri/skald-fta:latest
    volumes:
      - {out}:/app/output
  skald-anonymisation:
    image: ghcr.io/datakaveri/skald:latest
    volumes:
      - {out}:/app/output
"""


def test_shared_output_mount():
    print("\nshared output mount verification")
    with Sandbox() as sb:
        sb.write_compose(COMPOSE_OK.format(data=sb.data_dir, cfg=sb.cfg_dir, out=sb.out_dir))
        try:
            sdk._verify_shared_output_mount("skald-fta")
            check("matching host dir passes", True)
        except RuntimeError as exc:
            check("matching host dir passes", False, str(exc))

    with Sandbox() as sb:
        sb.write_compose(COMPOSE_LONG_FORM.format(out=sb.out_dir))
        try:
            sdk._verify_shared_output_mount("skald-fta")
            check("long-form bind syntax understood", True)
        except RuntimeError as exc:
            check("long-form bind syntax understood", False, str(exc))

    with Sandbox() as sb:
        sb.write_compose(COMPOSE_WITH_FTA_FIRST.format(out=sb.out_dir))
        try:
            sdk._verify_shared_output_mount("skald-fta")
            check("fta service in compose is skipped, not compared", True)
        except RuntimeError as exc:
            check("fta service in compose is skipped, not compared", False, str(exc))

    with Sandbox() as sb:
        sb.write_compose(COMPOSE_MISMATCH.format(data=sb.data_dir))
        expect_raises("different host dir rejected before running",
                      lambda: sdk._verify_shared_output_mount("skald-fta"), "DATA_MISSING")

    with Sandbox() as sb:
        sb.write_compose(COMPOSE_NAMED_VOLUME)
        expect_raises("named volume rejected (not a host bind)",
                      lambda: sdk._verify_shared_output_mount("skald-fta"), "DATA_MISSING")

    # Advisory, not fatal: a compose shape this code can't read must not break
    # deployments that work today.
    with Sandbox() as sb:
        sb.write_compose("services:\n  skald-anonymisation:\n    image: x\n")
        try:
            sdk._verify_shared_output_mount("skald-fta")
            check("no /app/output mount -> warns, does not raise", True)
        except RuntimeError as exc:
            check("no /app/output mount -> warns, does not raise", False, str(exc))


def test_image_resolution():
    print("\nimage resolution and compose extraction")
    with Sandbox() as sb:
        sb.write_compose(COMPOSE_WITH_FTA_FIRST.format(out=sb.out_dir))
        image, src = sdk._resolve_fta_image()
        check("compose service wins for skald-fta",
              image == "ghcr.io/datakaveri/skald-fta:latest", f"got {image} from {src}")
        app = sdk.extract_docker_image_from_compose(sb.compose)
        check("app image skips the fta service", app == "ghcr.io/datakaveri/skald:latest", f"got {app}")

    with Sandbox() as sb:
        sb.write_compose(COMPOSE_OK.format(data=sb.data_dir, cfg=sb.cfg_dir, out=sb.out_dir))
        image, src = sdk._resolve_fta_image()
        check("falls back to the config.yml pin",
              image == config.free_text_anonymization.image, f"got {image} from {src}")


def test_config_staging():
    print("\nconfig staging (skald-fta requires the exact name config.json)")
    # This is the live failure: the bundle lands generated-config.json, skald-fta
    # opens /app/config/config.json and dies with "Could not read config".
    with Sandbox() as sb:
        payload = {"data_type": "tabular",
                   "tabular": {**SKALD_NOISE, "free_text_anonymization": FTA_BLOCK}}
        sb.write_app_config(payload, name="generated-config.json")
        staged = sdk._prepare_fta_config_dir("generated-config.json")

        target = os.path.join(staged, "config.json")
        check("config.json exists in the staged dir", os.path.isfile(target))
        check("staged content is byte-identical",
              open(target, "rb").read()
              == open(os.path.join(sb.cfg_dir, "generated-config.json"), "rb").read())
        check("original config dir left untouched",
              sorted(os.listdir(sb.cfg_dir)) == ["generated-config.json"],
              f"got {sorted(os.listdir(sb.cfg_dir))}")
        check("staged dir is NOT the dir SKALD reads",
              os.path.realpath(staged) != os.path.realpath(sb.cfg_dir))
        # One file only: an auto-discovering skald-fta must not see two configs.
        check("exactly one file staged", os.listdir(staged) == ["config.json"],
              f"got {sorted(os.listdir(staged))}")

    # A config already named config.json is used as-is, not re-copied over.
    with Sandbox() as sb:
        sb.write_app_config({"free_text_anonymization": FTA_BLOCK}, name="config.json")
        staged = sdk._prepare_fta_config_dir("config.json")
        check("existing config.json passes through",
              json.load(open(os.path.join(staged, "config.json")))["free_text_anonymization"]
              == FTA_BLOCK)

    # An unrelated sibling config (skald-image's) must NOT be staged - it would
    # make the directory ambiguous to a scanning skald-fta.
    with Sandbox() as sb:
        sb.write_app_config({"free_text_anonymization": FTA_BLOCK}, name="generated-config.json")
        sb.write_app_config({"temp_dir": "/tmp/skald-image"}, name="pipeline_config.json")
        staged = sdk._prepare_fta_config_dir("generated-config.json")
        check("unrelated sibling configs not staged",
              os.listdir(staged) == ["config.json"], f"got {sorted(os.listdir(staged))}")
        check("staged config is the one holding the gate",
              "free_text_anonymization" in json.load(open(os.path.join(staged, "config.json"))))

    # Stale staging must never be what skald-fta reads.
    with Sandbox() as sb:
        os.makedirs(sb.fta_cfg_dir, exist_ok=True)
        with open(os.path.join(sb.fta_cfg_dir, "stale.json"), "w") as f:
            f.write("{}")
        sb.write_app_config({"free_text_anonymization": FTA_BLOCK}, name="generated-config.json")
        staged = sdk._prepare_fta_config_dir("generated-config.json")
        check("stale staged files cleared", "stale.json" not in os.listdir(staged),
              f"got {sorted(os.listdir(staged))}")


def test_failure_reaches_the_ui():
    print("\nstage failure writes status.json (UI must not hang)")
    with Sandbox() as sb:
        sb.write_app_config({"free_text_anonymization": FTA_BLOCK})
        try:
            sdk._fail_free_text("boom")
            check("_fail_free_text raises", False)
        except RuntimeError:
            check("_fail_free_text raises", True)
        sp = config.get_path('status')
        check("status.json written", os.path.isfile(sp))
        if os.path.isfile(sp):
            st = json.load(open(sp))
            check("status is error", st.get("status") == "error", f"got {st}")
            check("description carries the message", st.get("description") == "boom")
            check("status.json lands in output/ where get_app_status reads it",
                  os.path.dirname(os.path.realpath(sp)) == os.path.realpath(sb.out_dir))


def test_data_swap():
    print("\ndata/ swap (SKALD must not be able to read the raw input)")
    with Sandbox() as sb:
        raw = os.path.join(sb.data_dir, "haryana_grievance.csv")
        with open(raw, "w") as f:
            f.write("S.No,Complaint\n1,Mr. Ramesh Kumar has not received his pension\n")
        staged = os.path.join(sb.out_dir, "sanitized_input.csv")
        with open(staged, "w") as f:
            f.write("S.No,Complaint\n1,* has not received his pension\n")

        sdk._swap_staged_input_into_data(staged)

        files = sorted(os.listdir(sb.data_dir))
        check("data/ holds exactly one input", files == ["haryana_grievance.csv"], f"got {files}")
        body = open(raw).read()
        check("data/ input is now the sanitised text", "* has not received" in body)
        check("raw name no longer present in data/", "Ramesh Kumar" not in body)
        check("staged file kept in output/ for the audit", os.path.isfile(staged))

    # A workbook submission: the swapped input must be .csv (skald-fta emits CSV),
    # and the original extension must not survive with CSV bytes inside it.
    with Sandbox() as sb:
        raw = os.path.join(sb.data_dir, "grievances.xlsx")
        with open(raw, "wb") as f:
            f.write(b"PK\x03\x04 fake workbook")
        staged = os.path.join(sb.out_dir, "sanitized_input.csv")
        with open(staged, "w") as f:
            f.write("a,b\n1,*\n")

        sdk._swap_staged_input_into_data(staged)
        files = sorted(os.listdir(sb.data_dir))
        check("xlsx replaced by a .csv, single file", files == ["grievances.csv"], f"got {files}")
        check("original .xlsx removed", not os.path.exists(raw))

    # Ambiguity must be a hard error, never a guess.
    with Sandbox() as sb:
        for n in ("a.csv", "b.csv"):
            with open(os.path.join(sb.data_dir, n), "w") as f:
                f.write("x\n")
        staged = os.path.join(sb.out_dir, "sanitized_input.csv")
        with open(staged, "w") as f:
            f.write("a\n*\n")
        expect_raises("two inputs in data/ rejected",
                      lambda: sdk._swap_staged_input_into_data(staged), "ambiguous")

    with Sandbox() as sb:
        staged = os.path.join(sb.out_dir, "sanitized_input.csv")
        with open(staged, "w") as f:
            f.write("a\n*\n")
        expect_raises("empty data/ rejected",
                      lambda: sdk._swap_staged_input_into_data(staged), "found 0")

    # Non-data files must not be counted as the input.
    with Sandbox() as sb:
        with open(os.path.join(sb.data_dir, "dataset.enc"), "wb") as f:
            f.write(b"\x80encrypted")
        with open(os.path.join(sb.data_dir, "real.csv"), "w") as f:
            f.write("a\n1\n")
        staged = os.path.join(sb.out_dir, "sanitized_input.csv")
        with open(staged, "w") as f:
            f.write("a\n*\n")
        sdk._swap_staged_input_into_data(staged)
        check("leftover .enc ignored, csv swapped",
              open(os.path.join(sb.data_dir, "real.csv")).read() == "a\n*\n")


def test_stale_artifacts_not_mistaken_for_success():
    print("\nstale artifacts from an earlier run are purged up front")
    # /run/*_pipeline never calls ensure_tee_folders(), so output/ can still hold
    # a previous free-text run's staged CSV.
    for label, cfg in [
        ("enabled run", {"data_type": "tabular", "tabular": {
            **SKALD_NOISE, "free_text_anonymization": {
                **FTA_BLOCK, "audit_output_path": "output/anonymization_audit.json"}}}),
        # The dangerous case: nothing marks the leftovers as intermediates, so
        # without the purge they would be uploaded as results.
        ("disabled run", {"data_type": "tabular", "tabular": {
            **SKALD_NOISE, "free_text_anonymization": {
                **FTA_BLOCK, "enabled": False,
                "audit_output_path": "output/anonymization_audit.json"}}}),
        ("no block at all", {"data_type": "tabular", "tabular": SKALD_NOISE}),
    ]:
        with Sandbox() as sb:
            sb.touch_output("sanitized_input.csv", "anonymization_audit.json",
                            "generalized.csv", "status.json")
            sb.write_app_config(cfg)
            sdk.clear_free_text_artifacts()
            left = sorted(os.listdir(sb.out_dir))
            check(f"{label}: stale staged CSV purged", "sanitized_input.csv" not in left, f"got {left}")
            check(f"{label}: SKALD result untouched", "generalized.csv" in left, f"got {left}")
            check(f"{label}: status.json untouched", "status.json" in left, f"got {left}")

    # The default names are purged even when the config names nothing.
    with Sandbox() as sb:
        sb.touch_output("free_text_audit.json", "generalized.csv")
        sdk.clear_free_text_artifacts()
        left = sorted(os.listdir(sb.out_dir))
        check("config.yml default audit name purged", "free_text_audit.json" not in left, f"got {left}")


def main() -> int:
    print("=" * 60)
    print("skald-fta pre-stage offline tests")
    print("=" * 60)
    test_block_discovery()
    test_enabled_coercion()
    test_artifact_paths()
    test_gate_is_noop_when_disabled()
    test_artifact_exclusion()
    test_shared_output_mount()
    test_image_resolution()
    test_config_staging()
    test_failure_reaches_the_ui()
    test_data_swap()
    test_stale_artifacts_not_mistaken_for_success()

    print("\n" + "=" * 60)
    if FAILURES:
        print(f"{len(FAILURES)} FAILED: {FAILURES}")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
