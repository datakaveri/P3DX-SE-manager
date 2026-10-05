"""Cloud folders: in blob mode, a `blobUrl` ending in `/` names a blob prefix.

Listing, limits and format all come from one frozen listing, before any member
is downloaded; members are downloaded conditional on their listed ETag and
decrypted one at a time; tabular folders take the joint path and DICOM/image
folders the per-file path, as an uploaded folder tar does.

Azure Blob Storage is tests/fake_azure.FakeAzure, which records every request.

Run:  python3 -m unittest discover -s tests
"""

from __future__ import annotations

import csv
import json
import os
import tarfile
import unittest
from unittest import mock

from tests.test_folder_upload import (  # also sets up sys.path and the dotenv stub
    DICOM, PNG, JointJson, SdkFolderCase, TempDirCase, _patient, skald_section,
)

from cryptography.fernet import Fernet

from lib import blob_folder, folder_bundle
from lib.config import config
from lib.direct_upload import head_matches_format
from lib.folder_bundle import FolderError, MemberFailure
from lib.output_stream import BlobHttp
from enclave.enclave_direct_upload import MB
from tests.fake_azure import FakeAzure

ACCOUNT = "https://acct.blob.core.windows.net"
SAS = "sv=2022-11-02&sr=c&sp=rl&se=2030-01-01&sig=abc%3D"


class CloudCase(TempDirCase):
    def setUp(self):
        super().setUp()
        self.azure = FakeAzure()
        self.http = BlobHttp(session=self.azure, token_provider=lambda: "tok")
        self.key = Fernet.generate_key()
        self.fernet = Fernet(self.key)

    def put(self, name, plaintext, container="data"):
        self.azure.put(container, name, self.fernet.encrypt(plaintext))

    def plan(self, url, application):
        return blob_folder.list_and_plan(self.http, url, application)

    def members(self, plan):
        return blob_folder.members(plan, self.http, self.fernet.decrypt, head_matches_format)


# --------------------------------------------------------------------------- #
# URL, SAS, listing rules
# --------------------------------------------------------------------------- #


class FolderUrls(unittest.TestCase):
    def test_the_signal_is_a_trailing_slash_on_the_path(self):
        self.assertTrue(blob_folder.is_folder_url(f"{ACCOUNT}/data/scans/"))
        self.assertTrue(blob_folder.is_folder_url(f"{ACCOUNT}/data/scans/?{SAS}"))
        self.assertFalse(blob_folder.is_folder_url(f"{ACCOUNT}/data/patients.csv.enc"))
        self.assertFalse(blob_folder.is_folder_url(f"{ACCOUNT}/data/patients.csv.enc?{SAS}"))
        self.assertFalse(blob_folder.is_folder_url("enclave://upload/0f8fad5b-d9cb-469f-a165-70867728950e"))

    def test_parse(self):
        f = blob_folder.parse_folder_url(f"{ACCOUNT}/data/2025/ct%20scans/?{SAS}")
        self.assertEqual(f.prefix, "2025/ct scans/")
        self.assertEqual(f.name, "ct scans")
        self.assertTrue(f.container_url.startswith(f"{ACCOUNT}/data?"))
        self.assertTrue(f.has_sas)

    def test_a_folder_segment_below_the_container_is_required(self):
        with self.assertRaisesRegex(FolderError, "below the container"):
            blob_folder.parse_folder_url(f"{ACCOUNT}/data/")

    def test_https_and_azure_only(self):
        with self.assertRaisesRegex(FolderError, "https"):
            blob_folder.parse_folder_url("http://acct.blob.core.windows.net/data/x/")
        with self.assertRaisesRegex(FolderError, "Azure Blob"):
            blob_folder.parse_folder_url("https://evil.example.com/data/x/")

    def test_dot_dot_segment(self):
        with self.assertRaisesRegex(FolderError, r"'\.\.'"):
            blob_folder.parse_folder_url(f"{ACCOUNT}/data/a/../b/")


class Sas(unittest.TestCase):
    def check(self, query):
        blob_folder.parse_folder_url(f"{ACCOUNT}/data/x/?{query}&sig=abc")

    def test_container_and_directory_sas_with_list_pass(self):
        self.check("sr=c&sp=rl")
        self.check("sr=d&sp=rl")
        self.check("ss=b&srt=co&sp=rl")

    def test_without_list_permission_is_a_clear_failure_not_an_empty_folder(self):
        with self.assertRaisesRegex(FolderError, "lacks list permission"):
            self.check("sr=c&sp=r")

    def test_a_single_blob_sas_cannot_list(self):
        with self.assertRaisesRegex(FolderError, "single blob"):
            self.check("sr=b&sp=rl")

    def test_account_sas_needs_container_resource_type(self):
        with self.assertRaisesRegex(FolderError, "srt"):
            self.check("ss=b&srt=o&sp=rl")


class Listing(CloudCase):
    def test_markers_zero_size_and_clutter_are_left_out(self):
        self.put("scans/IM1.dcm.enc", DICOM)
        self.put("scans/sub/IM2.dcm.enc", DICOM)
        self.azure.put("data", "scans/sub/", b"")                         # directory marker
        self.azure.put("data", "scans/adls", b"", meta={"hdi_isfolder": "true"})
        self.azure.put("data", "scans/empty.dcm.enc", b"")                 # zero size
        self.put("scans/.DS_Store.enc", b"x")
        self.put("scans/__MACOSX/IM1.dcm.enc", DICOM)
        self.put("scans/Thumbs.db.enc", b"x")
        self.put("other/IM9.dcm.enc", DICOM)                               # outside the prefix
        plan = self.plan(f"{ACCOUNT}/data/scans/", "skald_dicom")
        self.assertEqual([e.member_name for e in plan.entries], ["IM1.dcm", "sub/IM2.dcm"])
        self.assertEqual(plan.mode, "per_file")

    def test_a_mixed_prefix_fails_with_counts(self):
        for i in range(2):
            self.put(f"p/a{i}.csv.enc", b"id\n1\n")
        self.put("p/b.json.enc", b'{"id": 1}')
        with self.assertRaisesRegex(FolderError, r"mixes file types \(2 csv, 1 json\)"):
            self.plan(f"{ACCOUNT}/data/p/", "skald")

    def test_a_format_the_application_cannot_take_fails(self):
        self.put("p/x.png.enc", PNG)
        with self.assertRaisesRegex(FolderError, "skald_dicom cannot take image"):
            self.plan(f"{ACCOUNT}/data/p/", "skald_dicom")

    def test_extensionless_members_are_dicom_only(self):
        self.put("p/IM0001.enc", DICOM)
        self.put("p/1.2.840.10008.enc", DICOM)
        plan = self.plan(f"{ACCOUNT}/data/p/", "skald_dicom")
        self.assertEqual(plan.fmt, "dicom")
        self.assertEqual(plan.presumed, {"IM0001", "1.2.840.10008"})
        self.put("q/notes.enc", b"id\n1\n")
        self.put("q/a.csv.enc", b"id\n1\n")
        with self.assertRaisesRegex(FolderError, "no recognised extension"):
            self.plan(f"{ACCOUNT}/data/q/", "skald")

    def test_listing_refused_is_reported_as_refused(self):
        self.put("p/a.csv.enc", b"id\n1\n")
        self.azure.refuse_listing = (403, "AuthorizationPermissionMismatch")
        with self.assertRaisesRegex(FolderError, "refused.*403.*AuthorizationPermissionMismatch"):
            self.plan(f"{ACCOUNT}/data/p/", "skald")

    def test_an_empty_folder(self):
        with self.assertRaisesRegex(FolderError, "empty"):
            self.plan(f"{ACCOUNT}/data/nothing/", "skald")

    def test_listing_pages(self):
        self.azure.page_size = 3
        for i in range(8):
            self.put(f"p/f{i}.csv.enc", b"id\n1\n")
        self.assertEqual(self.plan(f"{ACCOUNT}/data/p/", "skald").files_total, 8)

    def test_a_sas_folder_sends_the_sas_and_no_token(self):
        self.put("p/a.csv.enc", b"id\n1\n")
        self.plan(f"{ACCOUNT}/data/p/?{SAS}", "skald")
        self.assertTrue(all("Authorization" not in c[3] for c in self.azure.calls))


class LimitsFromTheListing(CloudCase):
    """Each limit fails before a single member is downloaded."""

    def assert_fails_without_download(self, pattern, application):
        with self.assertRaisesRegex(FolderError, pattern):
            self.plan(f"{ACCOUNT}/data/p/", application)
        self.assertEqual(self.azure.gets(), [], "no member may be downloaded before the limits pass")

    def test_10001_blobs(self):
        for i in range(10_001):
            self.azure.put("data", f"p/f{i:05d}.csv.enc", b"x")
        self.assert_fails_without_download("more than 10,000 files", "skald")

    def test_a_member_over_its_per_file_cap(self):
        self.azure.put("data", "p/big.png.enc", b"", size=40 * MB)        # > 25 MB image cap
        self.assert_fails_without_download(r"over the 25 MB limit", "skald_image")

    def test_sizes_summing_past_the_folder_cap(self):
        for i in range(5):                                                 # 5 x ~225 MB > 1 GiB
            self.azure.put("data", f"p/IM{i}.dcm.enc", b"", size=300 * MB)
        self.assert_fails_without_download(r"1024 MB limit for a DICOM folder", "skald_dicom")

    def test_fernet_overhead_does_not_count_against_the_cap(self):
        # base64 makes the ciphertext ~4/3 of the plaintext; a member just under
        # its cap must still pass from the listing.
        n = 290 * MB
        decoded = 57 + (n // 16 + 1) * 16          # Fernet framing + PKCS7-padded body
        token_len = -(-decoded // 3) * 4           # base64, padded
        bound = blob_folder.fernet_plaintext_bound(token_len)
        self.assertGreaterEqual(bound, n)
        self.assertLess(bound - n, 64)
        self.azure.put("data", "p/big.csv.enc", b"", size=token_len)
        self.assertEqual(self.plan(f"{ACCOUNT}/data/p/", "skald").files_total, 1)

    def test_the_bound_is_never_below_the_real_plaintext(self):
        f = Fernet(Fernet.generate_key())
        for n in (0, 1, 15, 16, 17, 1000, 4097):
            self.assertGreaterEqual(blob_folder.fernet_plaintext_bound(len(f.encrypt(b"a" * n))), n)


# --------------------------------------------------------------------------- #
# Members: conditional download, decrypt, sniff
# --------------------------------------------------------------------------- #


class Members(CloudCase):
    def test_a_blob_changed_after_listing_fails_the_job_in_joint_mode(self):
        self.put("p/a.csv.enc", b"id,age\n1,30\n")
        self.put("p/b.csv.enc", b"id,age\n2,40\n")
        plan = self.plan(f"{ACCOUNT}/data/p/", "skald")
        self.azure.change("data", "p/b.csv.enc", self.fernet.encrypt(b"id,age\n2,99\n"))
        section = skald_section(quasi_identifiers={"numerical": [{"column": "age", "type": "int"}]},
                                insensitive_columns=["id"])
        with self.assertRaisesRegex(FolderError, "'b.csv'.*changed after the folder was listed"):
            folder_bundle.combine_tabular(self.members(plan), "csv", section,
                                          self.path("data", "p.csv"), os.path.join(self.dir, "data"))

    def test_a_blob_changed_after_listing_fails_only_that_member_in_per_file_mode(self):
        for n in ("a", "b", "c"):
            self.put(f"p/{n}.dcm.enc", DICOM + n.encode())
        plan = self.plan(f"{ACCOUNT}/data/p/", "skald_dicom")
        self.azure.change("data", "p/b.dcm.enc", self.fernet.encrypt(DICOM + b"new"))
        self.azure.blobs.pop(("data", "p/c.dcm.enc"))

        def process(name, fh):
            p = self.path("o", "out.dcm")
            with open(p, "wb") as f:
                f.write(fh.read())
            return p
        manifest, _ = folder_bundle.run_per_file(
            self.members(plan), "dicom", folder_bundle.LocalTarSink(self.path("out.tar")),
            process, lambda: None)
        self.assertEqual([f["status"] for f in manifest["files"]], ["ok", "failed", "failed"])
        self.assertEqual(manifest["files"][1]["error"], "the file changed after the folder was listed")
        self.assertEqual(manifest["files"][2]["error"], "the file was removed after the folder was listed")

    def test_downloads_are_conditional_on_the_listed_etag(self):
        self.put("p/a.dcm.enc", DICOM)
        plan = self.plan(f"{ACCOUNT}/data/p/", "skald_dicom")
        with self.members(plan).__next__().open():
            pass
        (_, _, _, headers), = self.azure.gets()
        self.assertEqual(headers["If-Match"], self.azure.blobs[("data", "p/a.dcm.enc")]["etag"])

    def test_content_is_sniffed_after_decryption(self):
        self.put("p/fake.dcm.enc", b"PK\x03\x04 a zip, not a DICOM" + b"\0" * 200)
        self.put("p/IM0002.enc", b"plain text")
        plan = self.plan(f"{ACCOUNT}/data/p/", "skald_dicom")
        errors = []
        for m in self.members(plan):
            with self.assertRaises(MemberFailure) as ctx:
                m.open()
            errors.append(str(ctx.exception))
        self.assertEqual(errors, ["has no recognised extension and is not a DICOM file",   # IM0002
                                  "does not match the folder's format 'dicom'"])          # fake.dcm

    def test_a_blob_under_another_key_does_not_decrypt(self):
        self.azure.put("data", "p/a.dcm.enc", Fernet(Fernet.generate_key()).encrypt(DICOM))
        plan = self.plan(f"{ACCOUNT}/data/p/", "skald_dicom")
        with self.assertRaisesRegex(MemberFailure, "could not be decrypted"):
            next(self.members(plan)).open()


# --------------------------------------------------------------------------- #
# End to end through Fetch_data and P3DX_SDK
# --------------------------------------------------------------------------- #


class CloudThroughTheSdk(SdkFolderCase):
    def setUp(self):
        super().setUp()
        import fetch_data
        self.fd = fetch_data
        self.key = Fernet.generate_key()
        self.fernet = Fernet(self.key)
        self.urls_dir = os.path.join(self.dir, "urls")
        self.cfg_dir = os.path.join(self.dir, "cfg")
        os.makedirs(self.urls_dir)
        os.makedirs(self.cfg_dir)
        self.output_key = os.urandom(32)
        patches = [
            mock.patch.object(config.paths, "tee_urls", self.urls_dir),
            mock.patch.object(config.paths, "tee_input_config", self.cfg_dir),
            mock.patch.object(self.fd, "get_mi_token", return_value="tok"),
            mock.patch.object(self.fd, "fetch_fernet_key_from_kv", return_value=self.key),
            mock.patch("lib.output_stream.BlobHttp", side_effect=lambda **kw: self.http),
            mock.patch.object(self.sdk, "_output_crypto",
                              {"key": self.output_key, "base_iv": os.urandom(12), "run_id": "run-77"}),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def application(self, name):
        p = mock.patch.object(self.sdk, "_compose_url",
                              f"https://raw.githubusercontent.com/datakaveri/Docker-Compose/main/{name}/docker-compose.yml")
        p.start()
        self.addCleanup(p.stop)

    def urls(self, blob_url):
        urls = {"blobUrl": blob_url, "keyVaultUrl": "https://kv.vault.azure.net/secrets/k",
                "outputContainerUrl": self.OUTPUT_CONTAINER}
        with open(config.get_path("decrypted_urls"), "w") as f:
            json.dump(urls, f)
        return urls

    def put(self, name, plaintext):
        self.azure.put("data", name, self.fernet.encrypt(plaintext))

    def test_dicom_folder_per_file(self):
        self.application("skald-dicom")
        self.put("studies/ct/IM0001.dcm.enc", DICOM + b"1")
        self.put("studies/ct/sub/IM0002.dcm.enc", DICOM + b"2")
        self.put("studies/ct/IM0003.enc", DICOM + b"3")                    # no extension
        self.azure.put("data", "studies/ct/sub/", b"")                     # directory marker
        self.urls(f"{ACCOUNT}/data/studies/ct/")

        with mock.patch.object(self.sdk, "_run_application_once", self.fake_container):
            self.fd.fetch_and_decrypt_tee()
            self.assertEqual(self.azure.gets(), [], "per-file: nothing downloaded at staging")
            self.sdk.run_docker_containers()
            url = self.sdk.encrypt_and_upload_output()

        self.assertEqual(url, f"{self.OUTPUT_CONTAINER}/ct_anonymised.tar.enc")
        header, tf = self.open_output(url, self.output_key)
        self.assertEqual(header["run_id"], "run-77")
        self.assertEqual(sorted(tf.getnames()), ["IM0001_anonymised.dcm", "IM0003_anonymised.dcm",
                                                 "_manifest.json", "sub/IM0002_anonymised.dcm"])
        manifest = json.load(tf.extractfile("_manifest.json"))
        self.assertEqual((manifest["mode"], manifest["files_succeeded"], manifest["paths_deidentified"]),
                         ("per_file", 3, False))
        with open(config.get_path("status")) as f:
            status = json.load(f)
        direct = status["outputs"]["direct"]
        self.assertEqual((direct["outputBlobUrl"], direct["filename"], direct["bytes"]),
                         (url, "ct_anonymised.tar", header["total_bytes"]))
        self.assertIn("expires_at", direct)
        self.assertEqual(status["outputs"]["folder"], {"mode": "per_file", "files_total": 3,
                                                       "files_succeeded": 3, "files_failed": 0})
        self.assertEqual(self.staged_names, ["input.dcm"] * 3)

    def test_csv_folder_is_one_combined_input_reported_like_a_single_blob_run(self):
        self.application("skald")
        with open(os.path.join(self.cfg_dir, "generated-config.json"), "w") as f:
            json.dump({"data_type": "visits", "visits": skald_section(
                quasi_identifiers={"numerical": [{"column": "age", "type": "int"}]},
                insensitive_columns=["id"])}, f)
        self.put("exports/visits/a.csv.enc", b"id,age\n1,30\n2,31\n")
        self.put("exports/visits/b.csv.enc", b"id,age\n3,40\n")
        self.urls(f"{ACCOUNT}/data/exports/visits/")

        self.fd.fetch_and_decrypt_tee()
        self.assertIsNone(self.sdk._cloud_folder, "a tabular folder leaves no folder state behind")
        self.assertEqual(os.listdir(self.data), ["visits.csv"])
        with open(os.path.join(self.data, "visits.csv"), newline="") as f:
            self.assertEqual(sorted(r["id"] for r in csv.DictReader(f)), ["1", "2", "3"])

        # SKALD's result, uploaded by the unchanged single-file blob path.
        with open(os.path.join(self.out, "generalized.csv"), "w") as f:
            f.write("id,age\n1,[30-31]\n")
        uploaded = []
        with mock.patch.object(self.fd, "upload_blob", side_effect=lambda u, p: uploaded.append(u)), \
                mock.patch.object(self.sdk, "_upload_kmeans_plots"):
            url = self.sdk.encrypt_and_upload_output()
        self.assertEqual(url, f"{self.OUTPUT_CONTAINER}/generalized.csv.enc")
        self.assertEqual(uploaded, [url])

    def test_one_patient_per_json_blob_is_one_record_per_blob(self):
        self.application("skald")
        with open(os.path.join(self.cfg_dir, "generated-config.json"), "w") as f:
            json.dump({"data_type": "patients", "patients": JointJson.SECTION}, f)
        for i in range(6):
            self.put(f"p/patient{i}.json.enc", json.dumps(_patient(i)).encode())
        self.urls(f"{ACCOUNT}/data/p/")
        self.fd.fetch_and_decrypt_tee()
        with open(os.path.join(self.data, "p.json")) as f:
            self.assertEqual(len(json.load(f)), 6)

    def test_a_column_the_config_never_mentions_fails_and_is_listed(self):
        self.application("skald")
        with open(os.path.join(self.cfg_dir, "generated-config.json"), "w") as f:
            json.dump({"data_type": "v", "v": skald_section(insensitive_columns=["id"])}, f)
        self.put("v/a.csv.enc", b"id\n1\n")
        self.put("v/b.csv.enc", b"id,ssn\n2,x\n")
        self.urls(f"{ACCOUNT}/data/v/")
        with self.assertRaisesRegex(ValueError, r"\['ssn'\]"):
            self.fd.fetch_and_decrypt_tee()

    def test_dp_with_a_folder_url_fails_with_the_dp_message(self):
        self.application("differential-privacy")
        self.put("p/a.csv.enc", b"id\n1\n")
        self.urls(f"{ACCOUNT}/data/p/")
        with self.assertRaisesRegex(ValueError, "folder input is not supported for differential privacy"):
            self.fd.fetch_and_decrypt_tee()
        self.assertEqual(self.azure.calls, [], "refused before listing")

    def test_a_single_blob_url_takes_the_unchanged_path(self):
        self.application("skald")
        self.urls(f"{ACCOUNT}/data/patients.csv.enc")
        with mock.patch.object(self.fd, "download_blob") as dl, \
                mock.patch.object(self.fd, "decrypt_file") as dec, \
                mock.patch.object(self.fd.os, "remove"), \
                mock.patch.object(self.fd, "_stage_cloud_folder") as cloud:
            self.fd.fetch_and_decrypt_tee()
        cloud.assert_not_called()
        dl.assert_called_once()
        self.assertEqual(os.path.basename(dec.call_args[0][2]), "patients.csv")
        self.assertEqual(self.azure.calls, [])


if __name__ == "__main__":
    unittest.main()
