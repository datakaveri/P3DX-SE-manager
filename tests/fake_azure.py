"""An in-process stand-in for the slice of Azure Blob Storage the enclave uses:
flat List Blobs (with paging, prefix, metadata), conditional Get Blob, and
Put Block / Put Block List. It is a `session` for lib.output_stream.BlobHttp.

Every request is recorded in `calls`, so a test can assert that no member was
downloaded before the limits were checked. Committed blobs can live on disk
(`store_dir`) so a 1 GiB output does not have to sit in the test's RAM.
"""

from __future__ import annotations

import base64
import html
import itertools
import os
import urllib.parse
import xml.etree.ElementTree as ET


class Response:
    def __init__(self, status_code, content=b"", headers=None):
        self.status_code = status_code
        self.content = content
        self.headers = headers or {}

    @property
    def text(self):
        return self.content.decode("utf-8", "replace")


class FakeAzure:
    def __init__(self, account="acct", store_dir=None, page_size=5000):
        self.host = f"{account}.blob.core.windows.net"
        self.blobs = {}        # (container, name) -> {"data"|"path", "etag", "meta"}
        self.staged = {}       # (container, name) -> {block_id: data or path}
        self.calls = []        # (method, path, query dict, headers)
        self.store_dir = store_dir
        self.page_size = page_size
        self.refuse_listing = None   # e.g. (403, "AuthorizationPermissionMismatch")
        self._etags = itertools.count(1)

    # ── fixture helpers ──────────────────────────────────────────────────

    def put(self, container, name, data=b"", meta=None, size=None):
        """`size` overrides the listed Content-Length without allocating it, for
        limit checks that must fail before any download."""
        blob = {"data": data, "etag": self._new_etag(), "meta": meta or {}}
        if size is not None:
            blob["size"] = size
        self.blobs[(container, name)] = blob

    def put_file(self, container, name, path):
        self.blobs[(container, name)] = {"path": path, "etag": self._new_etag(), "meta": {}}

    def change(self, container, name, data):
        self.blobs[(container, name)].update(data=data, etag=self._new_etag())

    def read(self, container, name) -> bytes:
        blob = self.blobs[(container, name)]
        if "path" in blob:
            with open(blob["path"], "rb") as f:
                return f.read()
        return blob["data"]

    def blob_path(self, container, name):
        return self.blobs[(container, name)].get("path")

    def gets(self):
        """Blob downloads (not listings)."""
        return [c for c in self.calls if c[0] == "GET" and c[2].get("comp") != "list"]

    def _new_etag(self):
        return f'"0x8D{next(self._etags):012X}"'

    # ── the session interface BlobHttp uses ──────────────────────────────

    def request(self, method, url, headers=None, data=None, timeout=None, stream=False):
        parts = urllib.parse.urlsplit(url)
        assert parts.hostname == self.host, parts.hostname
        query = {k: v[0] for k, v in urllib.parse.parse_qs(parts.query).items()}
        path = urllib.parse.unquote(parts.path).lstrip("/")
        container, _, name = path.partition("/")
        headers = headers or {}
        self.calls.append((method, path, query, dict(headers)))
        if "sig" not in query:
            assert headers.get("Authorization", "").startswith("Bearer "), "no credential sent"
        else:
            assert "Authorization" not in headers, "a SAS request must not also carry a token"

        if method == "GET" and query.get("comp") == "list":
            return self._list(container, query)
        if method == "GET":
            return self._get(container, name, headers)
        if method == "PUT" and query.get("comp") == "block":
            return self._put_block(container, name, query["blockid"], data)
        if method == "PUT" and query.get("comp") == "blocklist":
            return self._commit(container, name, data)
        return Response(400)

    def _list(self, container, query):
        if self.refuse_listing:
            status, code = self.refuse_listing
            return Response(status, f"<Error><Code>{code}</Code></Error>".encode())
        if "sig" in query and "l" not in query.get("sp", ""):
            return Response(403, b"<Error><Code>AuthorizationPermissionMismatch</Code></Error>")
        prefix = query.get("prefix", "")
        names = sorted(n for (c, n) in self.blobs if c == container and n.startswith(prefix))
        start = int(query.get("marker") or 0)
        page = names[start:start + int(query.get("maxresults", self.page_size))]
        nxt = str(start + len(page)) if start + len(page) < len(names) else ""
        out = ['<?xml version="1.0" encoding="utf-8"?><EnumerationResults><Blobs>']
        for n in page:
            blob = self.blobs[(container, n)]
            size = blob.get("size") or (os.path.getsize(blob["path"]) if "path" in blob
                                        else len(blob["data"]))
            meta = "".join(f"<{k}>{html.escape(v)}</{k}>" for k, v in blob["meta"].items())
            out.append(f"<Blob><Name>{html.escape(n)}</Name><Properties>"
                       f"<Content-Length>{size}</Content-Length><Etag>{blob['etag']}</Etag>"
                       f"</Properties><Metadata>{meta}</Metadata></Blob>")
        out.append(f"</Blobs><NextMarker>{nxt}</NextMarker></EnumerationResults>")
        return Response(200, "".join(out).encode())

    def _get(self, container, name, headers):
        blob = self.blobs.get((container, name))
        if blob is None:
            return Response(404)
        if headers.get("If-Match") and headers["If-Match"] != blob["etag"]:
            return Response(412)
        return Response(200, self.read(container, name), {"ETag": blob["etag"]})

    def _put_block(self, container, name, block_id, data):
        base64.b64decode(block_id, validate=True)
        blocks = self.staged.setdefault((container, name), {})
        if self.store_dir:
            p = os.path.join(self.store_dir, f"blk-{len(self.staged)}-{len(blocks)}")
            with open(p, "wb") as f:
                f.write(data)
            blocks[block_id] = p
        else:
            blocks[block_id] = bytes(data)
        return Response(201)

    def _commit(self, container, name, body):
        ids = [n.text for n in ET.fromstring(body).iter("Latest")]
        blocks = self.staged.pop((container, name))
        if self.store_dir:
            path = os.path.join(self.store_dir, f"blob-{len(self.blobs)}")
            with open(path, "wb") as out:
                for i in ids:
                    with open(blocks[i], "rb") as f:
                        out.write(f.read())
                    os.unlink(blocks[i])
            self.blobs[(container, name)] = {"path": path, "etag": self._new_etag(), "meta": {}}
        else:
            self.blobs[(container, name)] = {"data": b"".join(blocks[i] for i in ids),
                                             "etag": self._new_etag(), "meta": {}}
        return Response(201)
