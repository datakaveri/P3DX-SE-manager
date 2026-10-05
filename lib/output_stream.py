"""
Streaming the SPIDROU1 output container straight to a block blob.

A per-file folder (DICOM / image) produces its output one member at a time.
Building that output as a tar on scratch, then encrypting a full copy for
upload, costs about three times the folder in RAM — at the 1 GiB folder cap it
does not fit. Here each member's bytes go into a tar STREAM, the stream is cut
into chunks, each chunk is encrypted and sent as one staged block (Put Block),
and the blob is assembled at the end with Put Block List. Neither the tar nor
its ciphertext is ever whole anywhere; peak memory is about two chunks.

The container bytes are exactly those write_output_container produces, with two
consequences of not knowing the output's size before the first chunk is sealed:

- The header must PRECEDE the chunks but holds every chunk's digest. Block
  lists may commit blocks in any order, so the header block is uploaded last
  and committed first.
- Each chunk's AAD binds `total_chunks`, which must therefore be fixed before
  chunk 0 is encrypted. It is set from an upper bound on the output, and any
  chunks the output does not fill are sealed as EMPTY chunks (a 16-byte tag
  each). The browser reader (outputDownloadWorker.ts) and
  read_output_container() both read exactly `total_chunks` length-framed
  chunks, check each digest and the root, and accept any chunk length, so an
  empty tail decrypts to nothing. An output that would need more than
  `total_chunks` chunks fails the job rather than writing a container nobody
  can read.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
import tarfile
import time
import urllib.parse
from email.utils import formatdate
from typing import Callable, Optional

from enclave.enclave_direct_upload import (
    MB,
    OUTPUT_MAGIC,
    chunk_digest_root,
    encrypt_chunk,
)

#: Plaintext per output chunk. The browser holds about two of these at once
#: while decrypting; smaller than the 64 MiB input chunk because nothing here
#: needs fewer round trips, and RAM in the enclave is the scarce thing.
STREAM_CHUNK_SIZE = 16 * MB

_X_MS_VERSION = "2020-10-02"
_HEADER_BLOCK = "h"
_CHUNK_BLOCK = "c"


class OutputTooLarge(Exception):
    """The output outgrew the chunk count fixed in its header."""


def chunks_for(max_bytes: int, chunk_size: int = STREAM_CHUNK_SIZE) -> int:
    """`total_chunks` for an output of at most `max_bytes`."""
    return max(1, -(-max_bytes // chunk_size))


def _block_id(kind: str, index: int) -> str:
    # Every block id in one blob must encode to the same length.
    return base64.b64encode(f"{kind}{index:09d}".encode("ascii")).decode("ascii")


# --------------------------------------------------------------------------- #
# Azure block blob, over plain HTTP
# --------------------------------------------------------------------------- #


class BlobHttp:
    """Azure Blob requests with the credential today's single-blob paths use:
    the enclave's managed identity, or — when the URL carries a SAS — the SAS
    alone. `session` is anything with requests' `request()`; tests pass a fake.
    The identity token is refreshed before it can expire mid-run."""

    _TOKEN_TTL = 30 * 60

    def __init__(self, session=None, token_provider: Optional[Callable[[], str]] = None):
        if session is None:
            import requests  # noqa: PLC0415
            session = requests.Session()
        self.session = session
        self._token_provider = token_provider
        self._token = None
        self._token_at = 0.0

    def _bearer(self) -> str:
        if self._token is None or time.time() - self._token_at > self._TOKEN_TTL:
            if self._token_provider is None:
                raise RuntimeError("no managed-identity token provider configured")
            self._token = self._token_provider()
            self._token_at = time.time()
        return self._token

    def request(self, method: str, url: str, *, headers=None, data=None,
                timeout=(10, 300), stream=False):
        h = {"x-ms-version": _X_MS_VERSION, "x-ms-date": formatdate(usegmt=True)}
        if not has_sas(url):
            h["Authorization"] = f"Bearer {self._bearer()}"
        h.update(headers or {})
        return self.session.request(method, url, headers=h, data=data,
                                    timeout=timeout, stream=stream)


def has_sas(url: str) -> bool:
    return "sig" in urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)


def blob_url(container_url: str, name: str) -> str:
    """`name` under a container (or folder) URL, keeping any SAS query."""
    parts = urllib.parse.urlsplit(container_url)
    path = parts.path.rstrip("/") + "/" + urllib.parse.quote(name, safe="/")
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, path, parts.query, ""))


def _with_query(url: str, extra: dict) -> str:
    parts = urllib.parse.urlsplit(url)
    query = parts.query + ("&" if parts.query else "") + urllib.parse.urlencode(extra)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def bare_url(url: str) -> str:
    """The URL without its query, for reporting: a SAS must never be echoed
    into status.json."""
    parts = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


class BlockBlobUploader:
    """Put Block / Put Block List against one blob."""

    def __init__(self, http: BlobHttp, url: str):
        self.http = http
        self.url = url

    def put_block(self, block_id: str, data: bytes) -> None:
        resp = self.http.request("PUT", _with_query(self.url, {"comp": "block", "blockid": block_id}),
                                 headers={"Content-Length": str(len(data))}, data=data)
        if resp.status_code != 201:
            raise RuntimeError(f"Put Block failed: HTTP {resp.status_code}")

    def commit(self, block_ids: list, content_type: str = "application/octet-stream") -> None:
        body = ('<?xml version="1.0" encoding="utf-8"?><BlockList>'
                + "".join(f"<Latest>{b}</Latest>" for b in block_ids)
                + "</BlockList>").encode("utf-8")
        resp = self.http.request("PUT", _with_query(self.url, {"comp": "blocklist"}),
                                 headers={"Content-Length": str(len(body)),
                                          "x-ms-blob-content-type": content_type},
                                 data=body)
        if resp.status_code != 201:
            raise RuntimeError(f"Put Block List failed: HTTP {resp.status_code}")


# --------------------------------------------------------------------------- #
# The container, as a write-only stream
# --------------------------------------------------------------------------- #


class ContainerStreamWriter:
    """File-like `write()` target that seals the SPIDROU1 container chunk by
    chunk into staged blocks. `close()` seals the tail, uploads the header and
    commits; until then nothing is visible at the blob URL."""

    def __init__(self, uploader: BlockBlobUploader, *, run_id: str, output_key: bytes,
                 output_base_iv: bytes, filename: str, content_type: str,
                 max_bytes: int, chunk_size: int = STREAM_CHUNK_SIZE):
        self._up = uploader
        self._run_id = run_id
        self._key = output_key
        self._iv = output_base_iv
        self._filename = filename
        self._content_type = content_type
        self.chunk_size = chunk_size
        self.total_chunks = chunks_for(max_bytes, chunk_size)
        self._buf = bytearray()
        self._digests = []
        self._plain_bytes = 0
        self.stored_bytes = 0
        self._closed = False

    def write(self, data) -> int:
        self._buf += data
        while len(self._buf) >= self.chunk_size:
            block = bytes(self._buf[:self.chunk_size])
            del self._buf[:self.chunk_size]
            self._seal(block)
        return len(data)

    def _seal(self, plaintext: bytes) -> None:
        index = len(self._digests)
        if index >= self.total_chunks:
            raise OutputTooLarge(
                f"the output is larger than the {self.total_chunks * self.chunk_size // MB} MB "
                f"this container was sized for"
            )
        ct = encrypt_chunk(self._key, self._iv, self._run_id, index, self.total_chunks, plaintext)
        self._up.put_block(_block_id(_CHUNK_BLOCK, index), struct.pack(">I", len(ct)) + ct)
        self._digests.append(hashlib.sha256(plaintext).hexdigest())
        self._plain_bytes += len(plaintext)
        self.stored_bytes += 4 + len(ct)

    def close(self) -> dict:
        if self._closed:
            raise RuntimeError("container already closed")
        if self._buf:
            self._seal(bytes(self._buf))
            self._buf = bytearray()
        while len(self._digests) < self.total_chunks:
            self._seal(b"")
        header = {
            "filename": self._filename,
            "content_type": self._content_type,
            "total_bytes": self._plain_bytes,
            "chunk_size": self.chunk_size,
            "total_chunks": self.total_chunks,
            "base_iv": base64.b64encode(self._iv).decode("ascii"),
            "chunk_digests": self._digests,
            "plaintext_sha256": chunk_digest_root(self._digests),
            "run_id": self._run_id,
        }
        header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
        head = OUTPUT_MAGIC + struct.pack(">I", len(header_bytes)) + header_bytes
        self._up.put_block(_block_id(_HEADER_BLOCK, 0), head)
        self.stored_bytes += len(head)
        self._up.commit([_block_id(_HEADER_BLOCK, 0)]
                        + [_block_id(_CHUNK_BLOCK, i) for i in range(self.total_chunks)])
        self._closed = True
        return header


class StreamingTarSink:
    """The per-file folder output: a tar written straight into a
    ContainerStreamWriter. Implements the sink protocol run_per_file uses —
    add_file(arcname, path), close(manifest_bytes) -> header, abort()."""

    def __init__(self, writer: ContainerStreamWriter):
        self.writer = writer
        self._tar = tarfile.open(fileobj=writer, mode="w|", format=tarfile.PAX_FORMAT)
        self._now = int(time.time())

    def _info(self, arcname: str, size: int) -> tarfile.TarInfo:
        info = tarfile.TarInfo(arcname)
        info.size, info.mode, info.mtime = size, 0o644, self._now
        return info

    def add_file(self, arcname: str, path: str) -> None:
        import os  # noqa: PLC0415
        with open(path, "rb") as fh:
            self._tar.addfile(self._info(arcname, os.fstat(fh.fileno()).st_size), fh)

    def close(self, manifest_name: str, manifest: bytes) -> dict:
        import io  # noqa: PLC0415
        self._tar.addfile(self._info(manifest_name, len(manifest)), io.BytesIO(manifest))
        self._tar.close()
        return self.writer.close()

    def abort(self) -> None:
        # Staged blocks that are never committed are discarded by the storage
        # service (after 7 days); nothing is visible at the URL meanwhile.
        self._tar = None
