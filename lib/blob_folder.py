"""
Cloud folders: in blob mode, the decrypted `blobUrl` may name a FOLDER — a blob
prefix — instead of one blob. The signal is the URL itself: its path (before any
`?`) ends in `/`. Every encrypted blob under the prefix is a member, encrypted
exactly like today's single-blob input with the key from `keyVaultUrl`, and the
members go through the same two pipelines as an uploaded folder tar
(lib/folder_bundle.py): joint for tabular, per file for DICOM / image.

Order of work, so nothing is read that the job could not use:

1. Validate the URL, and any SAS for list permission.
2. List once, flat (recursive), and FREEZE the list: name, size, ETag.
3. Drop what the UI drops for a local folder; derive each member's name
   (relative path, one trailing `.enc` removed) and format.
4. Check every limit from the listing — count, per-member cap, folder cap,
   non-empty, one format the application can take — before a single download.
5. Download each member only when its pipeline reaches it, conditional on the
   frozen ETag, decrypt it, re-check its real size and sniff its content.

Blob sizes are Fernet ciphertext, which is base64 and so about a third larger
than the plaintext. Listing-time caps use the plaintext bound that size
implies (`fernet_plaintext_bound`) rather than the raw size, or a 290 MB CSV
would be refused against a 300 MB cap.
"""

from __future__ import annotations

import io
import posixpath
import urllib.parse
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, Iterator, Optional

from enclave.enclave_direct_upload import (
    MAX_FOLDER_BYTES_BY_FORMAT,
    MAX_FOLDER_FILES,
    MAX_TOTAL_BYTES_BY_FORMAT,
    MB,
)
from lib.folder_bundle import (
    FolderError,
    Member,
    MemberFailure,
    _check_path,
    _printable,
    mode_for,
)
from lib.output_stream import BlobHttp, blob_url

DP_REJECTION = "folder input is not supported for differential privacy"

#: Formats each application takes. An unknown application (a /run re-run, or a
#: hand deploy) is not narrowed beyond "one format for the whole folder".
FORMATS_BY_APPLICATION = {
    "skald": ("csv", "json", "excel"),
    "skald_dicom": ("dicom",),
    "skald_image": ("image",),
}

_FORMAT_BY_EXTENSION = {
    ".csv": "csv", ".json": "json", ".xlsx": "excel", ".xls": "excel",
    ".dcm": "dicom", ".dicom": "dicom",
    ".png": "image", ".jpg": "image", ".jpeg": "image", ".bmp": "image",
    ".tif": "image", ".tiff": "image", ".webp": "image",
}

#: OS clutter the UI drops from a local folder; matched per path segment.
_CLUTTER_NAMES = {"thumbs.db", "desktop.ini"}
_CLUTTER_DIRS = {"__macosx"}

#: Fernet framing: version (1) + timestamp (8) + IV (16) + HMAC (32), plus at
#: least one byte of PKCS7 padding.
_FERNET_OVERHEAD = 58

_LIST_PAGE = 5000


def is_folder_url(url) -> bool:
    return isinstance(url, str) and urllib.parse.urlsplit(url).path.endswith("/")


def fernet_plaintext_bound(ciphertext_bytes: int) -> int:
    """The most plaintext a Fernet token of this many bytes can hold."""
    return max(0, ciphertext_bytes * 3 // 4 - _FERNET_OVERHEAD)


# --------------------------------------------------------------------------- #
# 1. URL and SAS
# --------------------------------------------------------------------------- #


@dataclass
class FolderUrl:
    container_url: str     # https://acct.blob.core.windows.net/container[?sas]
    prefix: str            # "a/b/" — decoded, always ends in "/"
    name: str              # last folder segment, for naming the output
    has_sas: bool


def parse_folder_url(url: str) -> FolderUrl:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https":
        raise FolderError("the folder URL must use https")
    host = (parts.hostname or "").lower()
    if not host.endswith(".blob.core.windows.net"):
        raise FolderError("the folder URL must be an Azure Blob Storage URL")
    segments = [urllib.parse.unquote(s) for s in parts.path.split("/")[1:-1]]
    if len(segments) < 2 or not all(segments):
        raise FolderError(
            "the folder URL must name a folder below the container, ending in '/' "
            "(https://<account>.blob.core.windows.net/<container>/<folder>/)"
        )
    if any(s in (".", "..") for s in segments):
        raise FolderError("the folder URL has a '.' or '..' path segment")
    query = urllib.parse.parse_qs(parts.query)
    has_sas = "sig" in query
    if has_sas:
        check_sas(query)
    container_url = urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, "/" + urllib.parse.quote(segments[0]), parts.query, ""))
    return FolderUrl(container_url, "/".join(segments[1:]) + "/", segments[-1], has_sas)


def check_sas(query: dict) -> None:
    """A SAS must let the enclave LIST the folder and READ its blobs. Checked
    before any request so a missing permission is reported as such, not as an
    empty folder."""
    def one(key):
        return (query.get(key) or [""])[0]

    sp = one("sp")
    if "l" not in sp:
        raise FolderError("the SAS in the folder URL lacks list permission (sp must include 'l')")
    if "r" not in sp:
        raise FolderError("the SAS in the folder URL lacks read permission (sp must include 'r')")
    sr, srt = one("sr"), one("srt")
    if sr:
        if sr not in ("c", "d"):
            raise FolderError(
                f"the SAS in the folder URL is scoped to a single blob (sr={sr}); listing a "
                f"folder needs a container or directory SAS (sr=c or sr=d)"
            )
    elif srt:
        if "c" not in srt or "o" not in srt:
            raise FolderError(
                "the account SAS in the folder URL must allow container and object access "
                "(srt must include 'c' and 'o')"
            )
        if "b" not in one("ss"):
            raise FolderError("the account SAS in the folder URL does not cover the blob service")
    else:
        raise FolderError("the SAS in the folder URL has neither 'sr' nor 'srt'")


# --------------------------------------------------------------------------- #
# 2-3. List once, freeze, filter
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class BlobEntry:
    blob_name: str         # full name in the container
    member_name: str       # relative to the prefix, one trailing ".enc" removed
    size: int              # ciphertext bytes, as listed
    etag: str              # quoted, as If-Match wants it


def _is_clutter(member_name: str) -> bool:
    for seg in member_name.split("/"):
        low = seg.lower()
        if seg.startswith(".") or low in _CLUTTER_DIRS:
            return True
    return posixpath.basename(member_name).lower() in _CLUTTER_NAMES


def _quoted(etag: str) -> str:
    etag = etag.strip()
    return etag if etag.startswith('"') else f'"{etag}"'


def _azure_error_code(resp) -> str:
    try:
        node = ET.fromstring(resp.content).find("Code")
        return node.text if node is not None and node.text else ""
    except ET.ParseError:
        return ""


def list_folder(http: BlobHttp, folder: FolderUrl) -> list:
    """Flat listing of every blob under the prefix, filtered and frozen. Stops
    as soon as the member count passes MAX_FOLDER_FILES."""
    entries, seen, marker = [], set(), ""
    while True:
        params = {"restype": "container", "comp": "list", "prefix": folder.prefix,
                  "include": "metadata", "maxresults": str(_LIST_PAGE)}
        if marker:
            params["marker"] = marker
        parts = urllib.parse.urlsplit(folder.container_url)
        query = parts.query + ("&" if parts.query else "") + urllib.parse.urlencode(params)
        url = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))
        try:
            resp = http.request("GET", url, timeout=(10, 60))
        except Exception as exc:
            raise FolderError(f"could not list the folder: {type(exc).__name__}") from None
        if resp.status_code != 200:
            code = _azure_error_code(resp)
            raise FolderError(
                f"listing the folder was refused by Azure Storage (HTTP {resp.status_code}"
                f"{', ' + code if code else ''}). The enclave's identity, or the SAS in the "
                f"folder URL, needs permission to list it."
            )
        try:
            root = ET.fromstring(resp.content)
        except ET.ParseError:
            raise FolderError("Azure Storage returned an unreadable folder listing") from None

        for blob in root.iter("Blob"):
            name_node = blob.find("Name")
            name = (name_node.text or "") if name_node is not None else ""
            if name_node is not None and name_node.get("Encoded") == "true":
                name = urllib.parse.unquote(name)
            props = blob.find("Properties")
            size = int(props.findtext("Content-Length") or 0) if props is not None else 0
            etag = (props.findtext("Etag") or "") if props is not None else ""
            resource_type = (props.findtext("ResourceType") or "") if props is not None else ""
            meta = blob.find("Metadata")
            is_dir_marker = (
                name.endswith("/") or resource_type == "directory"
                or (meta is not None and (meta.findtext("hdi_isfolder") or "").lower() == "true")
            )
            if not name.startswith(folder.prefix) or is_dir_marker or size <= 0:
                continue
            member = name[len(folder.prefix):]
            if member.lower().endswith(".enc"):
                member = member[:-4]
            if not member or _is_clutter(member):
                continue
            _check_path(member)
            if member in seen:
                raise FolderError(f"folder member '{_printable(member)}' appears twice")
            seen.add(member)
            entries.append(BlobEntry(name, member, size, _quoted(etag)))
            if len(entries) > MAX_FOLDER_FILES:
                raise FolderError(f"the folder has more than {MAX_FOLDER_FILES:,} files")

        marker = root.findtext("NextMarker") or ""
        if not marker:
            return entries


# --------------------------------------------------------------------------- #
# 3-4. Format and limits, from the listing alone
# --------------------------------------------------------------------------- #


@dataclass
class FolderPlan:
    folder: FolderUrl
    fmt: str
    mode: str
    entries: list = field(default_factory=list)
    estimated_bytes: int = 0
    #: member_name -> True when its format was presumed (no recognised
    #: extension) and must be confirmed by content after decryption.
    presumed: set = field(default_factory=set)

    @property
    def files_total(self) -> int:
        return len(self.entries)


def format_of(member_name: str) -> Optional[str]:
    return _FORMAT_BY_EXTENSION.get(posixpath.splitext(member_name)[1].lower())


def plan_folder(folder: FolderUrl, entries: list, application: Optional[str]) -> FolderPlan:
    """Decide the folder's one format and check every limit, without reading
    any member.

    A member with no recognised extension (`IM0001`, `1.2.840…`) can only be a
    DICOM file — scanners export them that way — and only DICOM is
    recognisable from its content (`DICM` at 128). So it is presumed DICOM
    where DICOM is what the folder holds, confirmed after decryption, and
    refused up front anywhere else, rather than downloaded to be refused."""
    if not entries:
        raise FolderError("the folder is empty")
    allowed = FORMATS_BY_APPLICATION.get(application or "")

    known = {e.member_name: format_of(e.member_name) for e in entries}
    counts = Counter(f for f in known.values() if f)
    unknown = [n for n, f in known.items() if f is None]
    if unknown:
        dicom_folder = (allowed == ("dicom",)) or (allowed is None and set(counts) <= {"dicom"})
        if not dicom_folder:
            raise FolderError(
                f"{len(unknown)} file(s) have no recognised extension (first "
                f"'{_printable(unknown[0])}'); only DICOM files are recognised without one"
            )
        counts["dicom"] += len(unknown)

    if len(counts) > 1:
        detail = ", ".join(f"{n} {f}" for f, n in counts.most_common())
        raise FolderError(f"the folder mixes file types ({detail}); every file must be one type")
    fmt = next(iter(counts))
    if allowed is not None and fmt not in allowed:
        first = next(n for n, f in known.items() if f == fmt)
        raise FolderError(
            f"{application} cannot take {fmt} files (first '{_printable(first)}'); it takes "
            f"{', '.join(allowed)}"
        )

    per_member_cap = MAX_TOTAL_BYTES_BY_FORMAT[fmt]
    folder_cap = MAX_FOLDER_BYTES_BY_FORMAT[fmt]
    total = 0
    for e in entries:
        estimate = fernet_plaintext_bound(e.size)
        if estimate > per_member_cap:
            raise FolderError(
                f"folder member '{_printable(e.member_name)}' is over the "
                f"{per_member_cap // MB} MB limit for {fmt.upper()} files"
            )
        total += estimate
    if total > folder_cap:
        raise FolderError(
            f"the folder's files add up to more than the {folder_cap // MB} MB limit "
            f"for a {fmt.upper()} folder"
        )
    return FolderPlan(folder, fmt, mode_for(fmt), list(entries), total, set(unknown))


def list_and_plan(http: BlobHttp, url: str, application: Optional[str]) -> FolderPlan:
    folder = parse_folder_url(url)
    return plan_folder(folder, list_folder(http, folder), application)


# --------------------------------------------------------------------------- #
# 5. Members, one download at a time
# --------------------------------------------------------------------------- #


def members(plan: FolderPlan, http: BlobHttp, decrypt: Callable[[bytes], bytes],
            head_matches: Callable[[bytes, str], bool]) -> Iterator[Member]:
    """Members whose `open()` downloads (If-Match the frozen ETag), decrypts,
    re-checks the real size, and sniffs the content — only when the pipeline
    reaches them. Raises MemberFailure with a content-free reason; the joint
    path turns that into a job failure, the per-file path into a failed member."""
    cap = MAX_TOTAL_BYTES_BY_FORMAT[plan.fmt]

    def opener(entry: BlobEntry):
        def open_member():
            url = blob_url(plan.folder.container_url, entry.blob_name)
            try:
                resp = http.request("GET", url, headers={"If-Match": entry.etag},
                                    timeout=(10, 600))
            except Exception:
                raise MemberFailure("could not be downloaded") from None
            if resp.status_code == 412:
                raise MemberFailure("the file changed after the folder was listed")
            if resp.status_code == 404:
                raise MemberFailure("the file was removed after the folder was listed")
            if resp.status_code != 200:
                raise MemberFailure(f"could not be downloaded (HTTP {resp.status_code})")
            token = resp.content
            del resp
            try:
                plaintext = decrypt(token)
            except Exception:
                raise MemberFailure("could not be decrypted with the job's key") from None
            del token
            if len(plaintext) > cap:
                raise MemberFailure(f"is over the {cap // MB} MB limit for {plan.fmt.upper()} files")
            if not head_matches(plaintext[:512], plan.fmt):
                if entry.member_name in plan.presumed:
                    raise MemberFailure("has no recognised extension and is not a DICOM file")
                raise MemberFailure(f"does not match the folder's format '{plan.fmt}'")
            return io.BytesIO(plaintext)
        return open_member

    for entry in plan.entries:
        yield Member(entry.member_name, opener(entry))
