"""Span-level access to the shared NER engine (skald-fta), for callers that
mask text themselves.

Added 2026-11-23. Kailash: "i want both in OCR and DICOM" to use the same NER
as the k-anon pipeline. skald-fta's batch entry point rewrites whole files
(CSV, FHIR); the OCR pipeline (boxes on a page image) and the DICOM
de-identifier (burned-in text, free-text tags) instead need WHERE the personal
data is, so each can mask it in its own medium. This adapter calls the very
same engine function the batch jobs use (anonymizer.pipeline.anonymize: the
same models, rules, thresholds and allow lists) and returns only the spans.

It runs INSIDE the pinned skald-fta image, which is where the engine and its
cached models live. Nothing here changes the image; the file is mounted in:

    docker run --rm -v $PWD/ner_service.py:/svc/ner_service.py:ro <skald-fta> \
        python /svc/ner_service.py --serve 8099 --host 0.0.0.0     # OCR sidecar
    docker run --rm --network none -v $WORK:/work ... \
        python /svc/ner_service.py --oneshot /work/req.json /work/resp.json   # one-shot
    docker run -d --network none -v $SOCKDIR:/sock ... \
        python /svc/ner_service.py --serve-unix /sock/ner.sock   # NER TEE (lib/ner_runner.py)

Request  {"texts": ["...", ...], "minimum_confidence": 0.5,
          "labels": ["PERSON", ...] (optional: model labels to report, default all)}
Response {"results": [{"spans": [{"start", "end", "label", "source", "confidence"}],
                       "error": null}, ...]}   (one result per text, same order)

Offsets index the text exactly as sent: source-text normalisation is switched
off, so a caller can map a span straight back onto its OCR box or tag value.
Overlapping detections are reported as the union the engine itself redacts,
labelled by the most confident detection inside it.

The OCR and DICOM repos carry vendored copies of this file; this one in
P3DX-SE-manager is canonical (the NER TEE measures and runs it).
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ENGINE_DIR = os.environ.get("SKALD_FTA_APP", "/app/app")  # where the image keeps the engine
MAX_TEXTS = 20000
MAX_BODY = 64 * 1024 * 1024
_engine_lock = threading.Lock()  # the models are not re-entrant; one batch at a time


def _engine():
    if ENGINE_DIR not in sys.path:
        sys.path.insert(0, ENGINE_DIR)
    from anonymizer.config import DetectionSettings, MODEL_LABELS  # noqa: E402
    from anonymizer.pipeline import anonymize  # noqa: E402

    return anonymize, DetectionSettings, MODEL_LABELS


def _validate(request) -> tuple:
    if not isinstance(request, dict):
        raise ValueError("the request must be a JSON object")
    texts = request.get("texts")
    if not isinstance(texts, list) or not all(isinstance(t, str) for t in texts):
        raise ValueError("'texts' must be a list of strings")
    if len(texts) > MAX_TEXTS:
        raise ValueError(f"at most {MAX_TEXTS} texts per request")
    conf = request.get("minimum_confidence", 0.0)
    if not isinstance(conf, (int, float)) or not 0 <= conf <= 1:
        raise ValueError("'minimum_confidence' must be a number between 0 and 1")
    labels = request.get("labels")
    if labels is not None and (not isinstance(labels, list) or not all(isinstance(x, str) for x in labels)):
        raise ValueError("'labels' must be a list of strings")
    return texts, float(conf), labels


def _union_spans(audit: list) -> list:
    """One span per replaced region, as redact_text grouped them."""
    regions: dict = {}
    for entry in audit:
        key = (int(entry["start_offset"]), int(entry["end_offset"]))
        best = regions.get(key)
        if best is None or float(entry.get("confidence") or 0) > float(best.get("confidence") or 0):
            regions[key] = entry
    return [
        {
            "start": start,
            "end": end,
            "label": entry["label"],
            "source": entry.get("source", ""),
            "confidence": float(entry.get("confidence") or 0),
        }
        for (start, end), entry in sorted(regions.items())
    ]


def detect(request) -> dict:
    """Run the engine over request["texts"]; see the module docstring."""
    texts, conf, labels = _validate(request)
    anonymize, DetectionSettings, MODEL_LABELS = _engine()
    redact_labels = tuple(labels) if labels else MODEL_LABELS
    settings = DetectionSettings(
        minimum_confidence=conf,
        normalize_source_text=False,  # offsets must index the caller's own text
        ner_redact_labels=tuple(x for x in redact_labels if x in MODEL_LABELS) or MODEL_LABELS,
    )
    # One "column" for every text: the engine keys results by (column, text),
    # and these texts are not table cells. The column only names a hash salt,
    # which callers never see (they get spans, not replacements).
    with _engine_lock, contextlib.redirect_stdout(sys.stderr):  # engine progress must not corrupt --stdin output
        found = anonymize((("text", t) for t in texts if t), settings)
    results = []
    for text in texts:
        res = found.get(("text", text)) if text else None
        if res is None:
            results.append({"spans": [], "error": None})
        elif res.error:
            results.append({"spans": [], "error": res.error})
        else:
            results.append({"spans": _union_spans(res.audit), "error": None})
    return {"results": results}


class _Handler(BaseHTTPRequestHandler):
    server_version = "ner-core/1"

    def log_message(self, fmt, *args):  # never log request contents; status lines only
        sys.stderr.write("ner-core %s\n" % (fmt % args))

    def _reply(self, status: int, body: dict) -> None:
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):  # noqa: N802
        if self.path == "/health":
            self._reply(200, {"status": "ok", "ready": self.server.ready})
        else:
            self._reply(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        if self.path != "/spans":
            return self._reply(404, {"error": "not found"})
        try:
            size = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            size = -1
        if size <= 0 or size > MAX_BODY:
            return self._reply(413 if size > MAX_BODY else 400, {"error": "bad Content-Length"})
        try:
            request = json.loads(self.rfile.read(size))
            return self._reply(200, detect(request))
        except ValueError as e:
            return self._reply(400, {"error": str(e)})
        except Exception as e:  # engine failure: the caller falls back to its own detection
            return self._reply(500, {"error": f"{type(e).__name__}: {e}"})


class _UnixHTTPServer(ThreadingHTTPServer):
    """HTTP on a Unix socket: for the NER TEE, whose container has no network
    at all (--network none) and is reached through a socket on a tmpfs mount."""

    address_family = socket.AF_UNIX

    def server_bind(self):
        if os.path.exists(self.server_address):
            os.remove(self.server_address)
        self.socket.bind(self.server_address)
        # The container runs as root; the enclave manager connecting from the
        # host does not. The socket's directory (0700, the manager's) is what
        # keeps everyone else out.
        os.chmod(self.server_address, 0o666)

    def get_request(self):
        conn, _ = self.socket.accept()
        return conn, ("unix", 0)


def serve(port: int, host: str, unix_path: str | None = None) -> None:
    if unix_path:
        httpd = _UnixHTTPServer(unix_path, _Handler)
        where = unix_path
    else:
        httpd = ThreadingHTTPServer((host, port), _Handler)
        where = f"{host}:{port}"
    httpd.ready = False
    print(f"ner-core listening on {where}; loading models", file=sys.stderr, flush=True)

    def warm():
        try:
            detect({"texts": ["Ramesh Kumar lives in Model Town, phone 9876543210."]})
            httpd.ready = True
            print("ner-core models loaded", file=sys.stderr, flush=True)
        except Exception as e:  # stay up: /spans then reports the error and callers fall back
            print(f"ner-core warm-up failed: {e}", file=sys.stderr, flush=True)

    threading.Thread(target=warm, daemon=True).start()
    httpd.serve_forever()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--serve", type=int, metavar="PORT", help="HTTP: POST /spans, GET /health")
    mode.add_argument("--serve-unix", metavar="PATH", help="the same HTTP API on a Unix socket")
    mode.add_argument("--stdin", action="store_true", help="one request on stdin, one response on stdout")
    # Files, for `docker run` callers: piping stdin through docker is not
    # reliable everywhere (snap docker drops it), a mounted tmpfs file is.
    mode.add_argument("--oneshot", nargs=2, metavar=("IN", "OUT"), help="one request file, one response file")
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args(argv)
    if args.serve or args.serve_unix:
        serve(args.serve or 0, args.host, args.serve_unix)
        return 0
    try:
        if args.oneshot:
            with open(args.oneshot[0], encoding="utf-8") as f:
                request = json.load(f)
        else:
            request = json.load(sys.stdin)
        response = detect(request)
        code = 0
    except ValueError as e:
        response, code = {"error": str(e)}, 2
    except Exception as e:
        response, code = {"error": f"{type(e).__name__}: {e}"}, 1
    if args.oneshot:
        with open(args.oneshot[1], "w", encoding="utf-8") as f:
            json.dump(response, f)
    else:
        sys.stdout.write(json.dumps(response))
        sys.stdout.flush()
    return code


if __name__ == "__main__":
    sys.exit(main())
