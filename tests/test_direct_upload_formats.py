"""Direct upload for every format: content validation and the image branch.

Covers the security-critical part — a file's magic bytes must match the format
the browser declared, since that format now selects which parser runs — and the
per-format caps that widened to include image and rose to 300 MB.

Run:  python3 -m unittest discover -s tests
"""

from __future__ import annotations

import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if "dotenv" not in sys.modules:
    _stub = types.ModuleType("dotenv")
    _stub.load_dotenv = lambda *a, **k: None
    sys.modules["dotenv"] = _stub

from lib.direct_upload import _content_matches_format  # noqa: E402
from enclave.enclave_direct_upload import MAX_TOTAL_BYTES_BY_FORMAT, MB  # noqa: E402

# Minimal real magic for each format.
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 32
BMP = b"BM" + b"\x00" * 32
TIFF_LE = b"II*\x00" + b"\x00" * 32
WEBP = b"RIFF\x00\x00\x00\x00WEBP" + b"\x00" * 32
XLSX = b"PK\x03\x04" + b"\x00" * 32
XLS = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" + b"\x00" * 32
CSV = b"id,age,city\n1,34,Mumbai\n2,41,Pune\n"
JSON = b'  [\n  {"id": 1, "age": 34}\n]\n'


def _dicom(preamble_fill=b"\x00"):
    return preamble_fill * 128 + b"DICM" + b"\x00" * 32


class MagicByteValidation(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.dir = tempfile.mkdtemp(prefix="p3dx-fmt-")
        self.addCleanup(__import__("shutil").rmtree, self.dir, ignore_errors=True)

    def write(self, content: bytes) -> str:
        path = os.path.join(self.dir, "f.bin")
        with open(path, "wb") as fh:
            fh.write(content)
        return path

    def ok(self, content, fmt):
        return _content_matches_format(self.write(content), fmt)

    # ── each format accepts its own magic ───────────────────────────────────

    def test_each_format_accepts_its_own_content(self):
        for content, fmt in (
            (CSV, "csv"), (JSON, "json"), (XLSX, "excel"), (XLS, "excel"),
            (_dicom(), "dicom"),
            (PNG, "image"), (JPEG, "image"), (BMP, "image"),
            (TIFF_LE, "image"), (WEBP, "image"),
        ):
            with self.subTest(fmt=fmt, magic=content[:4]):
                self.assertTrue(self.ok(content, fmt), f"{fmt} rejected its own content")

    # ── the attack it exists to stop ────────────────────────────────────────

    def test_a_zip_claiming_to_be_csv_is_rejected(self):
        # xlsx/zip reaching a CSV/text parser — the classic confusion.
        self.assertFalse(self.ok(XLSX, "csv"))

    def test_a_zip_claiming_to_be_dicom_is_rejected(self):
        self.assertFalse(self.ok(XLSX, "dicom"))

    def test_an_image_claiming_to_be_excel_is_rejected(self):
        self.assertFalse(self.ok(PNG, "excel"))

    def test_a_csv_claiming_to_be_an_image_is_rejected(self):
        self.assertFalse(self.ok(CSV, "image"))

    def test_dicom_without_the_preamble_marker_is_rejected(self):
        # A .dcm is DICM at offset 128, not at the start.
        self.assertFalse(self.ok(b"DICM" + b"\x00" * 200, "dicom"))

    def test_binary_claiming_to_be_csv_is_rejected(self):
        self.assertFalse(self.ok(b"\x00\x01\x02\x03" * 8, "csv"))

    def test_non_json_text_claiming_to_be_json_is_rejected(self):
        self.assertFalse(self.ok(CSV, "json"))

    # ── robustness ──────────────────────────────────────────────────────────

    def test_an_unknown_format_is_not_a_second_allowlist(self):
        # Format is already checked upstream; this must not become a stricter
        # gate that rejects something the caps table allowed.
        self.assertTrue(self.ok(b"anything", "parquet"))

    def test_a_missing_file_is_a_mismatch_not_a_crash(self):
        self.assertFalse(_content_matches_format(
            os.path.join(self.dir, "nope.bin"), "csv"))


class Caps(unittest.TestCase):
    def test_image_is_present_and_bulk_formats_are_300mb(self):
        self.assertEqual(MAX_TOTAL_BYTES_BY_FORMAT["csv"], 300 * MB)
        self.assertEqual(MAX_TOTAL_BYTES_BY_FORMAT["json"], 300 * MB)
        self.assertEqual(MAX_TOTAL_BYTES_BY_FORMAT["dicom"], 300 * MB)
        self.assertEqual(MAX_TOTAL_BYTES_BY_FORMAT["excel"], 25 * MB)
        self.assertEqual(MAX_TOTAL_BYTES_BY_FORMAT["image"], 25 * MB)


if __name__ == "__main__":
    unittest.main(verbosity=2)
