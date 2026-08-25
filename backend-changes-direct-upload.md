# Direct dataset upload — exact changes for middleware and TEE

Companion to `direct-dataset-upload-plan.md`. **The frontend is built and working** against a mock; this is everything the backend needs to do to meet it.

Reference implementation of every crypto operation below: **`docs/reference/enclave_direct_upload.py`**. It is not pseudocode — it runs, it self-tests (`python3 docs/reference/enclave_direct_upload.py`), and it has been verified byte-for-byte against the browser's actual code. Drop it into the enclave rather than reimplementing.

---

## 0. Verify before you build

Two commands prove the contract holds before any backend work:

```bash
# Browser crypto vs enclave crypto — nonce derivation, AAD, digests, round trip
bun run tools/crypto-interop-emit.ts > /tmp/vectors.json
python3 tools/crypto_interop_verify.py /tmp/vectors.json

# Full protocol against a local mock: init -> chunks -> complete -> run -> download
python3 tools/mock_enclave.py --port 8787 &
python3 tools/e2e_smoke.py --port 8787
```

Both currently pass. The smoke test also asserts that a tampered chunk, a wrong root digest, a misplaced chunk, a cross-user access, and a wrong decryption key are all **rejected** — so it doubles as the security regression suite.

---

## 1. Middleware

### 1.1 nginx

```nginx
# Chunked dataset upload — 64 MiB bodies, streamed, never spooled.
location ~ ^/enclave/upload/ {
    client_max_body_size        80m;
    client_body_buffer_size     128k;
    proxy_request_buffering      off;
    proxy_http_version          1.1;
    proxy_set_header            Connection "";
    proxy_read_timeout          300s;
    proxy_send_timeout          300s;
    proxy_pass                  https://enclave_upstream;
}

# Encrypted output download — response side, also unbuffered.
location ~ ^/enclave/output/ {
    proxy_buffering             off;
    proxy_http_version          1.1;
    proxy_set_header            Connection "";
    proxy_read_timeout          300s;
    proxy_pass                  https://enclave_upstream;
}
```

Three of these are load-bearing and will each break the feature on their own:

| Directive | Default | What happens if left alone |
|---|---|---|
| `client_max_body_size 80m` | **1m** | Every chunk PUT gets a 413. This breaks first. |
| `proxy_request_buffering off` | **on** | nginx writes the full 64 MiB body to its own disk before forwarding a byte — doubles latency per chunk *and puts ciphertext on the proxy's disk*, which is what this design exists to avoid. |
| `proxy_read_timeout 300s` | **60s** | A 64 MiB chunk is ~54 s at 10 Mbps and ~107 s at 5 Mbps. Any ordinary connection times out. |

Also check for a WAF/CDN in front: Cloudflare's free/pro tiers cap request bodies at 100 MB. 64 MiB fits, but there is no headroom to grow the chunk later.

### 1.2 Routes to proxy

| Method | Path | Notes |
|---|---|---|
| `POST` | `/enclave/upload/init` | JSON |
| `PUT` | `/enclave/upload/{id}/chunk/{index}` | binary, streamed |
| `GET` | `/enclave/upload/{id}/status` | JSON |
| `POST` | `/enclave/upload/{id}/complete` | JSON |
| `DELETE` | `/enclave/upload/{id}` | abort/cleanup |
| `GET` | `/enclave/output/download?url=…` | streams the encrypted container |

### 1.3 Application layer

1. **Validate the Bearer JWT on all six routes**, exactly as `/enclave/dicom-output` already does.
2. **Propagate the caller's `sub`** to the enclave (header or mTLS identity). The enclave needs it for the ownership check in §2.5 — without it, user A can reference user B's `upload_id`.
3. **Stream chunk bodies** — `request.stream`, never `request.get_data()`, which materialises the whole 64 MiB.
4. **Reject oversized `total_bytes` at `init`**, before the upload starts. Belt and braces with the enclave check.
5. **Abuse controls** — this accepts arbitrary bulk data: 1 concurrent upload session per user, a per-user bytes/hour quota, rate limiting on the chunk route.
6. **CORS** — allow `PUT`, and headers `Authorization`, `Content-Type`, `X-Chunk-SHA256`.
7. **Never log or persist** chunk bodies, `wrapped_key`, `output_wrapped_key`, or either IV.

### 1.4 The output download proxy

`GET /enclave/output/download?url=<url-encoded blob URL>` is the one genuinely new piece of middleware logic. It:

1. Validates the Bearer token.
2. **Validates that `url` points at our own storage account and container** — this is a user-supplied URL being fetched server-side, i.e. a textbook SSRF sink. Allow-list the host and container prefix; reject anything else. Do not skip this.
3. Adds the storage credential (short-lived SAS, or reads server-side with the managed identity).
4. Streams the bytes back with `Content-Type: application/octet-stream` and a `Content-Disposition` filename.

The browser never receives a SAS token, and could not use a plain `<a href download>` anyway because that cannot carry the Bearer header. This generalises the existing `/enclave/dicom-output` endpoint — worth merging the two rather than maintaining both.

---

## 2. TEE / enclave

All of this is implemented in `docs/reference/enclave_direct_upload.py`. Wire your HTTP layer to `UploadManager` and `write_output_container`.

### 2.1 `POST /enclave/upload/init`

Request:
```jsonc
{
  "filename": "patients.csv",
  "format": "csv",                     // csv | json | excel | dicom
  "content_type": "text/csv",
  "total_bytes": 104857600,
  "chunk_size": 67108864,
  "total_chunks": 2,
  "cipher": "AES-256-GCM",
  "key_wrap": "RSA-OAEP-SHA256",
  "wrapped_key": "<base64 RSA-OAEP(32-byte AES key)>",
  "base_iv": "<base64, 12 bytes>",
  "output_wrapped_key": "<base64 RSA-OAEP(32-byte AES key)>",
  "output_base_iv": "<base64, 12 bytes>"
}
```

Response `201`: `{ "upload_id": "<uuid4>", "expires_at": "…" }`

Enclave must:
- Validate limits **here**, before 100 MB is on the wire. `413` if `total_bytes` exceeds the per-format cap; `400` if `total_chunks != ceil(total_bytes / chunk_size)` or `> MAX_CHUNKS`.
- RSA-OAEP-SHA256 unwrap **both** keys with the enclave private key — the one whose public half is published in the MAA `x-ms-runtime.client-payload["public key"]` claim, i.e. the same key the config bundle already uses. No new key material, no attestation changes.
- Assert each unwraps to exactly 32 bytes. Hold them **in memory only, never on disk**.
- Preallocate the scratch file (`truncate` to `total_bytes`).

`output_wrapped_key` is a **second, independent** key. Not the same one, because the browser and the enclave would otherwise both encrypt under one key and a base-IV collision would mean catastrophic AES-GCM nonce reuse. Two keys removes the failure class for the cost of one RSA block.

### 2.2 `PUT /enclave/upload/{id}/chunk/{index}`

```
Content-Type: application/octet-stream
X-Chunk-SHA256: <hex sha256 of the PLAINTEXT chunk>
body: ciphertext || 16-byte GCM tag
```

```python
nonce = derive_chunk_nonce(base_iv, index)              # (int(base_iv) + index) % 2^96
aad   = f"{upload_id}:{index}:{total_chunks}".encode()
pt    = AESGCM(dataset_key).decrypt(nonce, body, aad)
assert sha256(pt).hexdigest() == request.headers["X-Chunk-SHA256"]
with open(scratch_path, "r+b") as fh:                   # write at offset,
    fh.seek(index * chunk_size)                         # NOT an in-RAM accumulator
    fh.write(pt)
```

Response `200`: `{ "index": 1, "received_chunks": 2, "total_chunks": 2 }`

- **Idempotent** — re-PUTting an index overwrites. This is what makes retry and resume work; do not reject duplicates.
- Reject `index >= total_chunks` and bodies `> chunk_size + 64`.
- On auth failure return a **generic** message. A detailed one turns this into an oracle.

### 2.3 `GET /enclave/upload/{id}/status`

`{ "received_chunks": [0], "total_chunks": 2, "expires_at": "…" }`

The UI calls this on load to offer a resume. Return `404` for unknown/expired.

### 2.4 `POST /enclave/upload/{id}/complete`

Request `{ "plaintext_sha256": "<hex root>" }` where the root is
`SHA256( concat( raw sha256 of each chunk, in index order ) )`.

Not a plain SHA-256 of the file: WebCrypto has no streaming digest, so a whole-file hash would force the browser into a second full read. This falls out of the encryption pass it already makes.

Verify all indices present, size matches, root matches → zeroise the dataset key →
`{ "dataset_ref": "enclave://upload/<id>", "bytes": …, "sha256_verified": true }`

### 2.5 Pipeline integration — two changes

**a) Input resolver.** The bundle format is unchanged; only the value differs. After decrypting the bundle, branch on the scheme of `blobUrl`:

| Value | Action |
|---|---|
| `https://…` | Download from Azure Blob, exactly as today |
| `enclave://upload/<id>` | Use the reassembled scratch file |

```python
scratch = manager.resolve_dataset_ref(user_sub, dataset_ref)
```

**`resolve_dataset_ref` verifies the session's `user_sub` matches the authenticated caller.** Without that check, user A can name user B's `upload_id` and read their data. This is the single most important authorisation check in the feature.

Also expect these sentinels in direct mode, and do not try to use them as URLs:
- `keyVaultUrl` = `enclave://none` — no Azure key vault; the dataset key came from the wrapped key at init
- `outputContainerUrl` = `enclave://download` — write the encrypted container instead of a normal output

**b) Free the scratch file** as soon as the pipeline has loaded the dataset (`manager.release(upload_id)`). Scratch is tmpfs, i.e. RAM, and holding it for the duration of the run wastes ~1× the dataset size out of 8 GiB.

### 2.6 Writing the output

```python
output_key, output_base_iv = manager.output_key_for(upload_id)
with open(container_path, "wb") as fh:
    write_output_container(
        anonymised_path, fh,
        run_id=upload_id,                 # run_id IS the upload_id
        output_key=output_key, output_base_iv=output_base_iv,
        filename="patients_anonymised.csv", content_type="text/csv",
    )
# upload container_path to blob storage, then report it in /enclave/status
```

Container layout (all integers big-endian) — `write_output_container` produces exactly this:

```
magic       8 bytes   b"SPIDROU1"
header_len  4 bytes   uint32
header      header_len bytes, UTF-8 JSON
per chunk:  4 bytes   uint32 ciphertext length
            N bytes   ciphertext || 16-byte GCM tag
```

Then `/enclave/status` reports:
```jsonc
{ "status": "success",
  "outputs": { "direct": {
    "outputBlobUrl": "https://…/output-data/<run_id>.enc",
    "filename": "patients_anonymised.csv",
    "bytes": 91234567,
    "expires_at": "2026-08-06T15:05:00Z",
    "rows_out": 512340, "rows_suppressed": 1203, "k": 10 } } }
```
`rows_out` / `rows_suppressed` / `k` are optional; the UI shows them if present.

### 2.7 Limits and housekeeping

| Setting | Value |
|---|---|
| `MAX_CHUNKS` | 16 |
| `MAX_CHUNK_BYTES` | 64 MiB + 64 |
| `MAX_TOTAL_BYTES` | CSV/JSON 100 MB · Excel 25 MB · DICOM 100 MB |
| `MAX_CONCURRENT_SESSIONS_PER_USER` | 1 |
| Upload session TTL | 30 min idle |
| Output blob TTL | 2 hours |

- **TTL sweeper** for both upload sessions (delete scratch + keys) and output blobs.

**Scratch on tmpfs.** `Standard_DC2as_v5` has no local temp disk, so RAM is the only storage inside the SEV-SNP boundary — the secure choice anyway. The enclave runs as a **container inside the confidential VM**, so this belongs in the container spec, not the host's `/etc/fstab` — a host mount would not appear inside the container's namespace.

Docker / podman:
```
--tmpfs /enclave/scratch:rw,size=1g,mode=0700,noexec,nosuid,nodev
```

docker-compose:
```yaml
tmpfs:
  - /enclave/scratch:rw,size=1g,mode=0700,noexec,nosuid,nodev
```

Kubernetes:
```yaml
volumes:
  - name: enclave-scratch
    emptyDir: { medium: Memory, sizeLimit: 1Gi }
```

> **On Kubernetes, `medium: Memory` counts against the container's memory limit.** If the limit isn't raised by the same 1Gi, the container is OOMKilled the moment scratch fills — and it will present as the pipeline dying mid-run, not as a storage error. `emptyDir` also can't set `noexec,nosuid,nodev`; if those matter, use a CSI ephemeral volume or run under docker/podman where `--tmpfs` accepts them.

`size=1g` is a cap, not a reservation — tmpfs allocates pages on write, so it costs nothing until used. Sizing: ~100 MB reassembled dataset plus ~100 MB output container per concurrent run, so 1Gi is comfortable.

Set `ENCLAVE_SCRATCH_DIR=/enclave/scratch` in the container environment, or the module falls back to its own default and you get a silent path mismatch.

**Gunicorn: run a single worker.**

```
--workers 1 --worker-class gthread --threads 8 --timeout 300
```

`UploadManager` holds sessions in an in-process dict, and the unwrapped AES keys live in that process's memory deliberately — they must never reach disk or a shared store. With 2+ workers, a session created by `/init` in worker A is invisible to worker B, so chunk PUTs land on the wrong worker at random and fail with "Unknown or expired upload session". It presents as a flaky network bug.

One worker costs little here: 2 vCPU, and the pipeline is the CPU hog rather than the HTTP layer. Threads are what stop a 64 MiB PUT blocking `/status` for other callers.

`--timeout 300` matters independently: gunicorn's **default is 30s** and it kills the worker mid-upload. A 64 MiB chunk is ~54s at 10 Mbps. Match nginx's 300s.

If the pipeline currently runs inline in the request handler, move it to a background thread — with a single worker it would otherwise block every other request for the whole anonymisation run.

### 2.8 Enclave memory on DC2as_v5 (8 GiB, 2 vCPU)

| Item | Bytes |
|---|---|
| OS + Python runtime + server | ~1.5 GiB |
| One chunk in flight (ciphertext + plaintext during `AESGCM.decrypt`) | 128 MiB |
| Reassembled dataset in tmpfs (freed after load) | 1 × D |
| Pipeline peak (pandas + SKALD hierarchies + intermediates) | ~8 × D |

At D = 100 MB that is ~3.4 GiB — comfortable. **Memory is not the constraint; 2 vCPU is.** A 100 MB k-anonymisation job on two cores may run for a long time, and I have no credible number without measuring. Time one run at the cap on the real SKU and set the final limit from that. If runtime is the problem, `Standard_DC4as_v5` is a drop-in fix that changes nothing in this design.

Read the chunk body into a single preallocated buffer rather than `request.get_data()` to keep the in-flight cost at 2× rather than 3×.

---

## 3. What the frontend already does

For reference when testing — none of this needs backend work:

| Concern | Where |
|---|---|
| Key generation, RSA wrapping, chunk encryption | `src/components/ReusableComponents/DatasetUploadWorker/datasetUploadWorker.ts` |
| Output streaming + decryption + integrity checks | `.../outputDownloadWorker.ts` |
| Crypto primitives (shared, verified against Python) | `src/utils/cryptoUtils.ts` |
| Head-slice preview (never parses the whole file) | `src/utils/headPreview.ts` |
| Session keys + resume state (IndexedDB, non-extractable keys) | `src/utils/idb.ts` |
| Third data-source option, size gates | `src/components/pages/LocalDataSelector/LocalDataSelector.tsx` |
| Upload orchestration, progress, resume banner | `src/components/pages/LocalFileSelector/LocalFileSelector.tsx` |
| Output download UI | `src/components/pages/OutputPage/DirectOutput.tsx` |
| Limits and chunk size | `src/environments/environments.ts` → `direct_upload` |

Client-side behaviour worth knowing about:

- **Chunks are uploaded strictly one at a time.** Not a limitation to optimise away — two 64 MiB chunks in flight would double peak browser memory past the 128 MiB budget.
- **Retries re-encrypt from the file** rather than caching ciphertext, so a retried chunk is byte-identical. 3 attempts, exponential backoff.
- **Resume** re-PUTs only the indices missing from `/status`, using the same key and IV from IndexedDB. This is why chunk PUTs must be idempotent.
- The UI verifies the **attested key fingerprint** before resuming. If the enclave was redeployed, the old wrapped key is undecryptable and the UI discards the session rather than uploading into a dead one.

---

## 4. Do not "fix" the Fernet key ordering

Unrelated to this feature, but it will come up when someone reads `cryptoUtils.ts`.

A Fernet key is 32 bytes split in half. **Per spec the first 16 bytes are the HMAC signing key and the last 16 are the AES-128-CBC key.** `encryptWithFernet` does the opposite. Verified against Python's stock `cryptography.fernet.Fernet`:

```
signing=first16, encryption=last16     HMAC=OK    plaintext=b'SPIDEr config payload test'
encryption=first16, signing=last16     HMAC=FAIL  plaintext=b'\x1e\xcc\x8a\xa8M\x16/o9...'
```

So the tokens the UI produces are **not valid Fernet** — a stock `Fernet(key).decrypt(token)` rejects them. The config path works in production only because the enclave mirrors the same swap. Both ends are consistently non-standard and interoperate.

Consequences: correcting either end alone breaks config decryption immediately, and nothing new should be built on it. The direct-upload path uses stock AES-256-GCM on both sides precisely so this question never arises again.
