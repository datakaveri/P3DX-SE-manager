# Direct Dataset Upload to TEE — Implementation Plan

**Branch:** `build/p3dx-384-curated-v1`
**Status:** **Frontend is implemented, built and verified.** Backend work outstanding.
**Enclave:** `Standard_DC2as_v5` — 2 vCPU / 8 GiB / no local temp disk (confirmed).

> ### If you are implementing the middleware or the TEE, start here instead
>
> This document is the **design rationale** — why the numbers are what they are, what was rejected and why. Useful context, but it is not the build instruction.
>
> | You want | Read |
> |---|---|
> | Exact endpoints, payloads, nginx config, security checks | **`backend-changes-direct-upload.md`** |
> | Drop-in enclave code (session manager, crypto, output writer) | **`reference/enclave_direct_upload.py`** — runs and self-tests, not pseudocode |
> | Why a design decision was made the way it was | this document |
>
> The crypto in the reference module has been verified byte-for-byte against the browser's actual code (`tools/crypto_interop_verify.py`). Use it rather than reimplementing from prose — nonce derivation and AAD encoding are exactly the details that are easy to get subtly wrong and painful to debug across two codebases.

---

## 1. What we're building

Today the Data step (`LocalDataSelector`, wizard steps 3–4) offers two options:

| Mode | What happens |
|---|---|
| `upload` | File is read in the browser **for preview + config building only**. The enclave still reads the real data from an Azure blob URL the user supplies at `BlobUrlsStep`. |
| `existing` | User picks a curated sample; its blob URL is pre-filled. |

Both require the data to already live in Azure Blob Storage. The new third mode removes that requirement:

| Mode | What happens |
|---|---|
| `direct` **(new)** | The whole dataset is chunked, encrypted in the browser with a per-upload symmetric key, that key is wrapped with the **attested** TEE public key, and the chunks are streamed through the middleware to the enclave. The enclave unwraps the key, decrypts, reassembles, and runs the normal pipeline. The result is then encrypted back to a browser-held key and **downloaded directly in the UI** (§8). Azure Blob is not involved at all — not for input, not for output. |

A direct-mode run therefore touches **no persistent storage anywhere in the system**: the input exists only in enclave RAM, and the output only long enough for the user to download it.

Security property to preserve end to end: **the middleware is a dumb pipe.** In both directions it carries ciphertext plus an RSA-wrapped key it cannot unwrap. Only the enclave — whose public key we obtained from the MAA attestation token — can decrypt the input; only the browser can decrypt the output.

---

## 2. What already exists (and what we reuse)

This repo already implements the exact hybrid-encryption pattern this feature needs, just for the *config* rather than the *data*:

| Piece | File | Reuse? |
|---|---|---|
| TEE public key from MAA attestation claims (`x-ms-runtime.client-payload["public key"]`, base64 SPKI PEM) | `src/utils/cryptoUtils.ts` → `extractPublicKeyFromJwtClaims`, `importRSAPublicKey` | **Yes, as-is** |
| RSA-OAEP-SHA256 key wrapping (guards at 190 bytes; a 32-byte key fits) | `src/utils/cryptoUtils.ts` → `encryptWithRSA` | **Yes, as-is** |
| Public key plumbed into Redux once attestation verifies | `src/hooks/useTeePublicKey.ts`, `src/store/encryption/encryptionSlice.ts` | **Yes, as-is** |
| Encryption in a Web Worker (Vite `?worker` import) | `src/components/ReusableComponents/EncryptionWorker/` | **Pattern only** — new worker |
| Fernet encryption of config + URLs, bundle POSTed to `/enclave/bundle/upload` | `encryptionWorker.ts`, `sendBundleToTeeThunk.ts` | **Yes, unchanged** — see §5.5 |
| File handle held outside Redux | `src/store/localDataset/localFileRef.ts` | **Yes, as-is** |

So the new work is genuinely additive. We are not redesigning the trust model — we are applying the existing one to a second, much larger payload.

### 2.1 Reference projects — what we take and what we deliberately don't

From `Tanuh-browser-ratls/src/lib/index.ts` and `TANUH-buffertee/.../server/submit.go`:

**Adopt:**
- Per-upload random 256-bit key, AES-256-GCM per chunk.
- 12-byte random base IV; per-chunk nonce = `base_iv + chunk_index` (big-endian add with carry). Guarantees no (key, nonce) reuse.
- Per-chunk AAD binding index + total + upload id — makes chunk reorder, splice, drop, and cross-upload replay all fail decryption rather than silently corrupting data.
- A plaintext SHA-256 commitment verified by the enclave after reassembly.
- Hard `max_chunks` guard server-side.

**Do not adopt:**
- **HPKE / X25519 key wrapping.** Tanuh uses HPKE because it has an RA-TLS channel with its own enclave key material. We already have an attested RSA-OAEP public key in the MAA token and working code for it. Switching to HPKE means new enclave key material, new attestation claims, and a new crypto dependency on both ends for zero security gain here.
- **One giant PUT containing all chunks** (`[4-byte hdr len][hdr JSON][4-byte len + ct]…`). Tanuh talks browser→enclave more or less directly. We go through a reverse proxy + middleware, where a single 200 MB request means: proxy body limits, gateway timeouts, full buffering somewhere in the path, no progress indication, and no resume. We use **one HTTP request per chunk** instead — see §4.

---

## 3. Size limits — analysis and decision

### 3.1 What actually constrains us

1. **Browser encryption memory — a hard budget, see §3.3.** We slice the `File` (`file.slice(off, off+N)`), so total file size never dictates memory. But `crypto.subtle.encrypt` is one-shot and allocates a **fresh** output buffer, so plaintext and ciphertext are both live at the moment it returns. That puts the floor at **2× chunk size**, and it means chunk size and upload concurrency together set the peak. Budget: **128 MiB peak, at a 64 MiB chunk size.**

2. **Browser *parsing* memory — currently the hard blocker.** `FileUploader.tsx:162` calls `Papa.parse(file, {…})` with **no `preview:` option**, so the entire file becomes a JS array of row objects; `data.slice(0, PREVIEW_ROWS_COUNT)` only trims *after*. A 100 MB CSV becomes roughly 0.8–1.5 GB of JS objects and kills the tab. Same for `XLSX.read(new Uint8Array(buf))` at `LocalDataSelector.tsx:397`, which needs the whole workbook decompressed in memory. **Direct mode must parse only a head slice** — see §5.4.

3. **Enclave RAM — the real ceiling.** After reassembly the pipeline loads the dataset into pandas. A CSV typically occupies **3–5×** its on-disk size as a DataFrame, and SKALD's generalization hierarchies + intermediate copies push peak to roughly **8–10×**. So a 100 MB CSV wants ~1 GB of headroom on top of the reassembled file itself.

4. **Wire time.** 100 MB at 10 Mbps uplink ≈ 80 s; at 50 Mbps ≈ 16 s. Acceptable with a progress bar; unacceptable without one.

5. **Proxy limits.** nginx default `client_max_body_size` is **1 MB** — it will reject our chunks today. Must be raised (§6).

### 3.2 Decision

| Constant | Value | Reasoning |
|---|---|---|
| `CHUNK_SIZE` | **64 MiB** (67,108,864 B) plaintext | Fewer round trips: a 100 MB dataset is 2 requests instead of 6 at a 16 MiB chunk. Body = chunk + 16 B GCM tag. Peak memory 128 MiB (§3.3). |
| `MEMORY_BUDGET` | **128 MiB** | Exactly 2× chunk — the WebCrypto floor. See the note below. |
| `CONCURRENCY` | **1** — strictly sequential | **This is what bounds memory.** Two 64 MiB chunks in flight would put peak at 256 MiB. Not a performance knob. |
| `MAX_CHUNKS` | **16** | Runaway guard (16 × 64 MiB = 1 GiB), well above the policy limits below. |
| `RETRIES` | **3** per chunk, exponential backoff | Chunk PUTs are idempotent by index, so retry is safe. Retries **re-slice and re-encrypt from the `File`** rather than holding a spare copy — see §5.5. |
| `CHUNK_TIMEOUT` | **300 s** | 64 MiB is ~54 s at 10 Mbps, ~107 s at 5 Mbps. Needs real headroom. |
| `SESSION_TTL` | **30 min** idle | Bounds enclave scratch usage. |

> **On the exact 128 MiB figure.** WebCrypto has no streaming or in-place AES-GCM, so **2× chunk size is a hard floor**, not something we can optimise away. A 64 MiB chunk therefore peaks at 128 MiB + 16 B, plus a small amount of worker runtime overhead — i.e. the budget is met *at* the floor, with no headroom. If it must be strictly under 128 MiB, drop the chunk to 60 MiB (peak ~120 MiB). Either way it cannot go below 2× chunk.
>
> One caveat outside our control: handing a `Uint8Array` to the request lets the browser copy it into the **network stack**, not the JS heap. That transient copy shows in OS-level process memory but not in JS heap measurements, and there is no API to avoid it short of shrinking the chunk. At 64 MiB that copy is itself 64 MiB, so OS-level process memory will read higher than the JS-heap budget suggests.

**Honest note on the speed win.** Going 16 MiB → 64 MiB cuts a 100 MB upload from 6 requests to 2. That saves per-request overhead (TLS handshakes if connections aren't reused, headers, round trips), which is worth real time on a high-latency link but is close to negligible on a bandwidth-limited one, where the bytes dominate either way. The cost is retry granularity: one failed chunk now means re-encrypting and re-sending 64 MiB instead of 16 MiB, so on a flaky connection the larger chunk can be *slower* overall. It is a reasonable trade — just don't expect a large speedup on most links. If wall-clock time is the real goal, the bigger lever is raising `CONCURRENCY`, and that is exactly what the memory budget forbids.

**Max dataset size, by format — sized for the confirmed enclave, `Standard_DC2as_v5`.**

That SKU is **2 vCPU / 8 GiB RAM**, and — because it is the `as` variant, not `ads` — it has **no local temp disk**. Two consequences drive everything below:

- **Scratch must be tmpfs, i.e. RAM.** With no local disk, the only storage inside the SEV-SNP encrypted memory boundary is RAM. That is actually the *right* answer for security (see §3.4), but it means the reassembled dataset counts against the same 8 GiB as the pipeline.
- **2 vCPU makes CPU, not memory, the binding constraint.** See the note below.

Memory budget on 8 GiB:

| Item | Bytes |
|---|---|
| OS + Python runtime + enclave server | ~1.5 GiB |
| One chunk in flight (ciphertext + plaintext during `AESGCM.decrypt`) | 128 MiB |
| Reassembled dataset in tmpfs (freed right after `pd.read_csv`) | 1 × D |
| Pipeline peak (pandas DataFrame + SKALD hierarchies + intermediates) | ~8 × D |
| Safety margin | ~1 GiB |

Solving `1.5 + 0.125 + 8D + 1.0 ≤ 8 GiB` gives **D ≈ 680 MB** on memory alone — so memory is not what limits us.

| Format | Limit | Reasoning |
|---|---|---|
| CSV | **100 MB** | Memory supports far more (~680 MB); **2 vCPU does not.** k-anonymity generalization is largely single-threaded and superlinear in row count — 100 MB is ≈700k rows, already a long job on two cores. Start here, raise after measuring actual runtime. |
| JSON | **100 MB** | Same, and JSON→DataFrame is usually worse than CSV. |
| Excel (`.xlsx`) | **25 MB** | `.xlsx` is zip-compressed; openpyxl commonly expands a worksheet **20–50×**. 25 MB compressed can already mean >1 GB resident — this one *is* memory-bound. |
| DICOM | **100 MB** | Single file, near-1× multiplier, and de-identification is cheap compared to k-anon. |

> **The limit to watch is wall-clock, not RAM.** On 2 vCPU a 100 MB k-anonymization job may run for many minutes; I can't give a credible number without measuring, and neither should anyone else. Phase 5 should time a run at the cap on the real SKU and set the final limit from that. If runtime turns out to be the problem, `Standard_DC4as_v5` (4 vCPU / 16 GiB) is the drop-in fix — the whole design is unchanged by it.
>
> Keep every one of these in a single exported config object (`direct_upload` in `environments.ts`) and mirrored server-side, so changing them is a one-line edit on each end rather than a hunt.
>
> *Please sanity-check the SKU specs against current Azure docs before implementation — VM series details do change.*

### 3.3 Browser peak-memory budget

**Requirement: peak ≤ 128 MiB at a 64 MiB chunk size, all encryption in a Web Worker, buffers zeroed and released as soon as they are done with.**

Steady-state peak, per chunk cycle:

| Live at once | Bytes |
|---|---|
| Plaintext chunk (`file.slice().arrayBuffer()`) | 64 MiB |
| Ciphertext + tag (fresh buffer from `crypto.subtle.encrypt`) | 64 MiB + 16 B |
| SHA-256 digest | 32 B |
| **Peak (the instant `encrypt` returns)** | **128 MiB + 48 B** |

Everything that makes this hold is listed as a hard implementation rule in §5.5. The three that matter most:

- **Concurrency 1.** Sequential upload is not a simplification, it is the memory bound.
- **No base64 anywhere on the data path.** Base64-encoding a 64 MiB chunk produces an ~89.5 M-character JS string ≈ **179 MB** as UTF-16 — on its own that exceeds the entire budget, before counting the plaintext and ciphertext already live. This is a decisive argument for raw-binary AES-GCM over Fernet (§4.7).
- **Slice inside the worker.** Pass the `File` handle to the worker (structured-clone of a `File` is a cheap reference, not a data copy) and slice there. Reading on the main thread and `postMessage`-ing ArrayBuffers would put a full copy on both sides.

Because the budget is met exactly at the 2× floor with no headroom, **every rule in §5.5 is load-bearing** — there is no slack to absorb one extra live copy.

### 3.4 Enclave-side reassembly: tmpfs, not disk

The Tanuh enclave accumulates plaintext in a growing RAM buffer (`var assembled []byte`). We do better in one respect and are forced into a constraint in another:

**Write each decrypted chunk to a preallocated file at offset `index * chunk_size`**, and hand the pipeline a path rather than a buffer. This makes idempotent chunk re-PUT trivial (just rewrite the same offset), avoids the realloc-and-copy growth pattern, and is what makes resume (§9) work cleanly.

**That file must live on tmpfs.** `Standard_DC2as_v5` has no local temp disk, so the only options are tmpfs (RAM) or the remote OS managed disk. Use tmpfs:

- tmpfs is RAM-backed, so it sits **inside the SEV-SNP encrypted-memory boundary** — plaintext never leaves the confidentiality guarantee.
- The OS disk would only be safe if Confidential Disk Encryption is confirmed enabled, and even then it is a remote disk: slower, and it widens the trust surface for zero benefit.
- Cost: the reassembled dataset counts against the 8 GiB RAM budget (already accounted for in §3.2), and it must be **unlinked immediately after the pipeline loads it** (`pd.read_csv` → delete) so it isn't held for the duration of the run.

Mount the scratch tmpfs with an explicit `size=` cap so a bug cannot exhaust enclave RAM, and set `noexec,nosuid,nodev`.

The enclave runs as a **container inside the confidential VM**, so this is declared in the container spec, not the host's `/etc/fstab` — a host mount would not be visible in the container's namespace. Exact snippets for docker / compose / Kubernetes are in `backend-changes-direct-upload.md` §2.7, along with the Kubernetes caveat that `emptyDir: {medium: Memory}` counts against the container memory limit.

---

## 4. Wire protocol

All routes require `Authorization: Bearer <IUDX JWT>`, matching the existing `/enclave/dicom-output` proxy. All are served on `tee_url` (`https://flowgate.iudx.org.in`) and proxied to the enclave.

```
POST   /enclave/upload/init
PUT    /enclave/upload/{upload_id}/chunk/{index}
GET    /enclave/upload/{upload_id}/status
POST   /enclave/upload/{upload_id}/complete
DELETE /enclave/upload/{upload_id}

GET    /enclave/output/download?url=<blob url>    # §8 — output download
```

That is the complete list. **Six endpoints, not more** — the output is a single encrypted blob fetched in one streamed request, not a manifest plus per-chunk fetches.

### 4.1 `POST /enclave/upload/init`

```jsonc
{
  "filename": "patients.csv",
  "format": "csv",                  // csv | json | excel | dicom
  "content_type": "text/csv",
  "total_bytes": 104857600,
  "chunk_size": 67108864,
  "total_chunks": 2,
  "cipher": "AES-256-GCM",
  "key_wrap": "RSA-OAEP-SHA256",
  "wrapped_key": "<base64 RSA-OAEP(32-byte AES key)>",
  "base_iv": "<base64, 12 bytes>",

  // §8 — the browser also supplies the key the enclave will use to encrypt
  // the OUTPUT back to it. Same wrapping, separate key, never reused.
  "output_wrapped_key": "<base64 RSA-OAEP(32-byte AES key)>",
  "output_base_iv": "<base64, 12 bytes>"
}
```

Response `201`:
```jsonc
{ "upload_id": "9f3c…", "expires_at": "2026-08-06T12:30:00Z" }
```

Enclave validates limits **here**, before 100 MB is on the wire, and unwraps `wrapped_key` immediately so a bad key fails fast. Reject with `413` if `total_bytes` exceeds the per-format limit, `400` if `total_chunks != ceil(total_bytes / chunk_size)` or `total_chunks > MAX_CHUNKS`.

### 4.2 `PUT /enclave/upload/{upload_id}/chunk/{index}`

```
Content-Type: application/octet-stream
X-Chunk-SHA256: <hex sha256 of the PLAINTEXT chunk>

<raw bytes: ciphertext || 16-byte GCM tag>
```

- **Nonce** for chunk `i` = `base_iv` (12 B) interpreted big-endian, `+ i`, with carry.
- **AAD** for chunk `i` = UTF-8 of `` `${upload_id}:${index}:${total_chunks}` ``.

Response `200`: `{ "index": 1, "received_chunks": 2, "total_chunks": 2 }`

Idempotent — re-PUTting the same index overwrites. This is what makes retry and resume work.

> Binding the AAD to the **server-issued** `upload_id` (rather than a client-generated file id as in Tanuh) additionally binds each chunk to the authenticated session, so a chunk captured from one upload cannot be replayed into another.

### 4.3 `GET /enclave/upload/{upload_id}/status`

`{ "received_chunks": [0], "total_chunks": 2, "expires_at": "…" }` — lets the client resume after a network drop or reload instead of restarting the whole upload. See §9.

### 4.4 `POST /enclave/upload/{upload_id}/complete`

```jsonc
{ "plaintext_sha256": "<hex>" }
```

Where `plaintext_sha256 = SHA256( concat( sha256(chunk_0) ‖ … ‖ sha256(chunk_n-1) ) )` over the **raw digest bytes** in index order.

> Sending the root here rather than at `init` is deliberate: it lets the browser compute every chunk digest during the single encryption pass over the file, instead of requiring a separate full read up front just to hash.

Response `200`:
```jsonc
{ "dataset_ref": "enclave://upload/9f3c…", "bytes": 104857600, "sha256_verified": true }
```

Enclave then zeroises the AES key.

### 4.5 `DELETE /enclave/upload/{upload_id}` — abort/cleanup on user cancel.

### 4.6 Handing off to the existing pipeline — the minimal-diff trick

**The bundle contract does not change at all.** `dataset_ref` is substituted for the input blob URL and travels through the existing Fernet-encrypted `encryptedUrls.blobUrl` field:

```jsonc
POST /enclave/bundle/upload      // shape unchanged
{ "payload": { "encryptedUrls": { "blobUrl": Fernet("enclave://upload/9f3c…"), … } } }
```

The enclave branches on the scheme after decrypting:
- `https://…` → download from Azure Blob, exactly as today.
- `enclave://upload/<id>` → use the reassembled scratch file.

This keeps `encryptionWorker.ts`, `encryptFilesThunk`, `sendBundleToTeeThunk`, and the whole bundle format untouched.

### 4.7 Why AES-256-GCM for the data and not Fernet

We keep Fernet for the config bundle (unchanged, working) but use AES-256-GCM for the bulk data:

1. **No base64.** Fernet base64url-encodes its output — a flat **+33% on the wire** (33 MB of pure overhead on a 100 MB upload) and, more seriously, it breaks the §3.3 memory budget outright: base64 of a 64 MiB chunk is an ~89.5 M-character JS string ≈ 179 MB as UTF-16, on top of the plaintext and ciphertext already live. Fernet is simply not viable for bulk data under a 128 MiB peak.
2. **AAD.** Fernet has no additional-authenticated-data field, so it cannot bind a chunk to its index. Chunk reordering would decrypt cleanly and silently corrupt the dataset.
3. **Stock library on the enclave side.** `AESGCM` from Python's `cryptography` is one import with no compatibility shim.
4. **Blast radius.** `encryptWithFernet` in `cryptoUtils.ts` is a hand-rolled implementation whose key halves are ordered opposite to the Fernet spec (spec: first 16 B = HMAC signing key, last 16 B = AES key; ours is reversed). It works today only because the enclave mirrors the same ordering. **Do not "fix" it — that would break the working config path.** But it is a good reason not to extend it to a second, much larger payload. AES-GCM sidesteps the question entirely.

---

## 5. Frontend changes

### 5.1 Timing constraint — this is the key design point

The TEE public key comes from the MAA attestation token, which only exists once attestation verifies. Current step order (K-anon flow, from `SwitchComponent.tsx`):

```
3–4 LocalDataSelector → 5 BlobUrlsStep → 6 KAnonymization
  → 7 AttestationStatus  ← TEE public key first available here
  → 8 LocalFileSelector  ← encryption + bundle send happens here
  → 9 OutputPage
```
(DP flow is the same with everything after step 5 shifted by one.)

**So the upload cannot happen at the Data step.** At steps 3–4 we only capture the `File` handle and a preview. The actual encrypt-and-upload runs at **step 8 (`LocalFileSelector`)**, alongside the existing bundle encryption.

This is also the correct trust ordering, not just a workaround: we should only ever encrypt to a key we have already attested.

### 5.2 `src/environments/environments.ts`

```ts
const MB = 1024 * 1024;
export const direct_upload = {
  chunkSize: 64 * 1024 * 1024,   // 64 MiB — see §3.3, peak memory is 2× this
  memoryBudgetBytes: 128 * 1024 * 1024,
  maxChunks: 16,
  concurrency: 1,                // do not raise: this is the memory bound, not a perf knob
  retries: 3,
  chunkTimeoutMs: 300_000,
  maxBytesByFormat: { csv: 100 * MB, json: 100 * MB, excel: 25 * MB, dicom: 100 * MB },
  sessionTtlMs: 30 * 60 * 1000,
} as const;
```

### 5.3 `src/utils/cryptoUtils.ts` — additive only

Add, without touching `encryptWithFernet`:
- `generateAesKey(): Uint8Array` — 32 random bytes
- `importAesGcmKey(raw: Uint8Array): Promise<CryptoKey>`
- `deriveChunkNonce(baseIv: Uint8Array, index: number): Uint8Array` — big-endian add with carry
- `encryptChunkAesGcm(key, nonce, aad, plaintext): Promise<Uint8Array>`
- `sha256Hex(buf: BufferSource): Promise<string>`

### 5.4 `src/components/pages/LocalDataSelector/LocalDataSelector.tsx`

- Add third radio option `direct` — "Upload full dataset securely to the enclave", with a one-line explanation that the file is encrypted in the browser and Azure Blob is not used.
- **Preview from a head slice only.** For `direct` mode, parse `file.slice(0, 1 * MB)` — `Papa.parse` with `preview: PREVIEW_ROWS_COUNT`, and drop the last (likely truncated) row. Do **not** run the existing full-file parse path (§3.1 item 2). Row count becomes an estimate (`total_bytes / avg_row_bytes`) or is shown as "—".
  - Excel in direct mode: `XLSX.read` needs the whole workbook, so within the 25 MB cap the existing path is fine — but it must be capped, not left open-ended.
- Enforce `maxBytesByFormat` at selection time with a clear, specific error message.
- Set `inputMode = "direct_upload"` in Redux; clear `inputBlobUrl` / `keyVaultUrl` / `outputContainerUrl` (the existing mode-switch effect already does this).

### 5.5 New: `src/components/ReusableComponents/DatasetUploadWorker/datasetUploadWorker.ts`

**All encryption happens here, never on the main thread** — both so the UI stays responsive during a multi-minute upload and so the plaintext never touches the main-thread heap. The worker owns slicing, hashing, encrypting, and the HTTP PUTs, and posts `{ type: 'progress', sentBytes, totalBytes, chunkIndex }` back.

The JWT is passed in the worker's init message (workers have no access to the Redux store). The `File` handle is passed the same way — structured-cloning a `File` clones a reference, not the bytes.

#### Memory discipline — mandatory rules

These are what hold the §3.3 budget. Each one is individually load-bearing:

1. **Slice inside the worker.** `file.slice(off, off + CHUNK_SIZE)` returns a lazy `Blob`; only `.arrayBuffer()` materialises bytes, and it happens exactly once per chunk, in the worker.
2. **Concurrency 1.** `await` the PUT for chunk *i* before slicing chunk *i+1*. No `Promise.all` over chunks, no prefetch/pipelining.
3. **Zero and release the plaintext the moment encryption is done**, before the upload starts — the network round-trip is by far the longest phase of the cycle and the plaintext must not be alive for it:
   ```ts
   const digest = await sha256Hex(plaintext);          // 32 B, while plaintext is alive
   const ct = await encryptChunkAesGcm(key, nonce, aad, plaintext);
   zeroArrayBuffer(plaintext.buffer);                   // reuse the existing helper
   plaintext = null;                                    // drop the reference so GC can reclaim
   await putChunk(index, ct, digest);                   // only ciphertext is live here
   zeroArrayBuffer(ct.buffer);
   ct = null;
   ```
   `zeroArrayBuffer` already exists in `cryptoUtils.ts` — reuse it rather than adding another.
4. **Zero the AES key and the wrapped-key buffer** in a `finally` block when the upload finishes, fails, or is cancelled. `encryptionWorker.ts` already does exactly this for the Fernet key; mirror the pattern.
5. **Pass the ciphertext to the request directly** as a `Uint8Array` body. No `new Blob([ct])` (copies), no `FormData` (copies), and above all no base64 (§3.3).
   - Use **`XMLHttpRequest`, not `fetch`**, for the chunk PUT. `fetch` has no upload-progress event, and at 64 MiB a fetch-based progress bar would advance in ~50% jumps on a 100 MB file (2 chunks). `xhr.upload.onprogress` gives byte-level progress *within* a chunk, which is what makes a multi-minute upload feel responsive. It also gives a clean `xhr.abort()` for cancel.
6. **Retry re-derives, it does not cache.** On a failed PUT, re-slice and re-encrypt that chunk from the `File`. Holding a spare copy for retry would defeat rule 3. Costs CPU only on the failure path.
7. **No accumulators.** Chunk digests are 32 B each and are kept for the §4.4 root hash — that is the only thing that grows with file size (16 chunks × 32 B = 512 B). Never retain plaintext or ciphertext chunks.
8. **Terminate the worker on completion, error, or cancel** so its heap is reclaimed wholesale rather than relying on GC.

> Note: the existing `encryptionUtils.ts` wraps its worker in a single 30 s job timeout. That is wrong for this workload — the new worker needs a **per-chunk** timeout (300 s at 64 MiB) plus an overall cancel signal, not a whole-job deadline.

#### Verifying the budget

Peak memory is a stated requirement, so it gets measured, not assumed: run a 100 MB upload with DevTools → Memory → *Allocation sampling* on the worker thread, and assert `performance.measureUserAgentSpecificMemory()` (or heap snapshots taken at chunk boundaries) stays at or under 128 MiB. Worth adding as a manual test-plan item in Phase 3, since a regression here — someone adding `Promise.all` for throughput, or a base64 step for debugging — is silent, easy to introduce, and at 64 MiB chunks costs 64 MiB per mistake.

### 5.6 New: `src/store/directUpload/`

`directUploadSlice.ts` + `thunks/uploadDatasetThunk.ts`, holding `{ status, uploadId, datasetRef, sentBytes, totalBytes, error }`.

### 5.7 `src/components/pages/BlobUrlsStep/BlobUrlsStep.tsx` — skipped entirely

All three fields are currently `required` and gate `canProceed`. In direct mode **none of them apply**: the input comes from the chunked upload, and (per §8) the output is downloaded straight to the browser rather than written to a container. So when `inputMode === "direct_upload"`, **skip step 5 altogether** — `LocalDataSelector` jumps straight to step 6.

The bundle still carries all three fields (the worker validates their presence), so send sentinels rather than changing the bundle shape:

```ts
blobUrl:            `enclave://upload/${uploadId}`
keyVaultUrl:        "enclave://none"
outputContainerUrl: "enclave://download"
```

`enclave://download` is what tells the enclave to keep the result in tmpfs for direct download instead of writing to Azure.

### 5.8 `src/components/pages/LocalFileSelector/LocalFileSelector.tsx`

- New "Encrypt & Upload Dataset" action for direct mode, gated on the same `isAttestationVerified && teePublicKey` condition the existing encrypt button uses.
- Progress UI: `LinearProgress` with bytes/percent, throughput, ETA, cancel, and per-chunk retry indication.
- On `complete`, pass `blobUrl: dataset_ref` into the existing `encryptFilesThunk` — everything downstream is unchanged.
- Update `allInputsReady` so it no longer demands a user-entered blob URL in this mode.

### 5.9 New: `src/components/ReusableComponents/DatasetUploadProgress/`

Small presentational progress component.

---

## 6. Middleware changes

The middleware stays a **pass-through proxy** — it must never be able to read the plaintext, in either direction.

Since we own this layer, here is the concrete nginx block:

```nginx
# Chunked dataset upload — 64 MiB bodies, streamed, never buffered to disk.
location ~ ^/enclave/upload/ {
    client_max_body_size        80m;      # default 1m rejects every chunk
    client_body_buffer_size     128k;     # stream; do not spool the body
    proxy_request_buffering     off;      # critical: pass through as it arrives
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

`proxy_request_buffering off` is the one that matters most: with the default (`on`), nginx writes the entire 64 MiB body to a temp file before forwarding a single byte — which both doubles latency per chunk and **puts ciphertext on the proxy's disk**, exactly what this design is meant to avoid.

Beyond the config:

1. **Route the new endpoints** to the enclave over the existing RA-TLS/mTLS channel used for `/enclave/*`.
2. **If anything sits in front of nginx** — a WAF or CDN — check its body cap too. Cloudflare's free/pro tiers cap request bodies at 100 MB: a 64 MiB chunk fits, but there is no room to grow the chunk further.
3. **In the app layer** (Flask/gunicorn), stream via `request.stream`; never `request.get_data()`, which materialises the whole 64 MiB body.
4. **Auth:** validate the Bearer JWT on every route, same as `/enclave/dicom-output`. Propagate the caller's `sub` to the enclave — it needs it for the ownership check in §7.5.
5. **Fail fast on limits** at `init` (reject oversized `total_bytes` before the upload starts) — belt and braces with the enclave check.
6. **Abuse controls:** this accepts arbitrary bulk data, so it needs max 1 concurrent upload session per user, a per-user bytes/hour quota, and rate limiting on the chunk route.
7. **CORS:** allow method `PUT` and headers `Authorization`, `X-Chunk-SHA256`, `Content-Type`.
8. **Never persist** chunk bodies, `wrapped_key`, `base_iv`, or output chunks to disk or logs.

---

## 7. TEE / enclave changes

1. **Upload session manager.** Keyed by `upload_id` (uuid4), holding `{ user_sub, filename, format, total_bytes, chunk_size, total_chunks, aes_key, base_iv, received: set[int], scratch_path, created_at, last_activity }`.

2. **On `init`:** validate limits; RSA-OAEP-SHA256 unwrap `wrapped_key` with the enclave private key (the one whose public half is published in the MAA `x-ms-runtime.client-payload["public key"]` claim); assert the result is exactly 32 bytes; hold it **in memory only, never on disk**; preallocate the scratch file.

3. **On chunk PUT:**
   ```python
   nonce = add_be(base_iv, index)
   aad   = f"{upload_id}:{index}:{total_chunks}".encode()
   pt    = AESGCM(key).decrypt(nonce, body, aad)
   assert sha256(pt).hexdigest() == request.headers["X-Chunk-SHA256"]
   write_at(scratch_path, offset=index * chunk_size, data=pt)   # not an in-RAM accumulator
   ```
   Reject `index >= total_chunks`, and bodies larger than `chunk_size + 64`.

4. **On `complete`:** verify all indices present and total byte count matches; recompute `SHA256(concat(chunk digests))` and compare to `plaintext_sha256`; zeroise the AES key; mark the session ready.

5. **Input resolver:** when the bundle's decrypted `blobUrl` starts with `enclave://upload/`, resolve to the scratch path instead of downloading from Azure — **and verify the session's `user_sub` matches the authenticated caller of the bundle request.** Without this check, user A could reference user B's `upload_id`.

6. **Scratch storage** on a size-capped tmpfs (§3.4) — `Standard_DC2as_v5` has no local temp disk, so tmpfs is both the only sensible option and the secure one (RAM sits inside the SEV-SNP boundary). Unlink the file as soon as the pipeline has loaded it.

7. **Server-side limits:** `MAX_TOTAL_BYTES` per format, `MAX_CHUNKS = 16`, `MAX_CHUNK_BYTES = 64 MiB + 64`, `MAX_CONCURRENT_SESSIONS_PER_USER = 1`.

8. **TTL sweeper:** delete sessions idle > 30 min and their scratch files.

9. **Enclave-side memory has the same 2× floor.** During `AESGCM.decrypt` the enclave holds one 64 MiB ciphertext plus its 64 MiB plaintext — ~128 MiB per in-flight chunk, on top of the pipeline's own footprint. Already counted in the §3.2 budget. Reading the body into a single preallocated buffer rather than `request.get_data()` keeps it at 2× instead of 3×.

10. **Output handling** — see §8.

---

## 8. Output: encrypted to blob, downloaded and decrypted in the browser

**Decision: the enclave writes the result to blob storage — but encrypted under a key only this browser holds.** The UI pulls it back through the middleware's authenticated proxy, decrypts it with the session key, and hands the user a file.

This is better than keeping the output in enclave tmpfs: tmpfs is RAM on a 8 GiB box, so holding a 100 MB result for a two-hour download window competes directly with the pipeline. Blob storage costs nothing and holds ciphertext it cannot read. The confidentiality property is identical — what protects the output is the encryption, not where the bytes sit.

### 8.1 Key handling

TLS alone is not sufficient: the middleware terminates TLS, so a plaintext output stream would be readable there — which would undo the whole point of encrypting the input. So the **browser generates a second 32-byte AES-256-GCM key** (`output_key`), independent of the upload key, and sends it RSA-wrapped to the enclave in the `init` call (§4.1: `output_wrapped_key`, `output_base_iv`).

The enclave encrypts output chunks with it. The middleware carries ciphertext it cannot read, in both directions.

**Storing `output_key` in the browser.** The run may take many minutes, and the key must survive that (and a reload — §9). Generate it, wrap it for the enclave, then **re-import it as a non-extractable `CryptoKey` and store *that* in IndexedDB**, zeroing the raw bytes:

```ts
const raw = crypto.getRandomValues(new Uint8Array(32));
const outputWrappedKey = await encryptWithRSA(raw, teePublicKey);   // existing helper
const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", false /* non-extractable */, ["decrypt"]);
raw.fill(0);
await idbPut("outputKeys", { runId, key });   // CryptoKey is structured-cloneable
```

A non-extractable `CryptoKey` can be stored in IndexedDB and used to decrypt, but its raw bytes can never be read back by JavaScript — so even an XSS on the page cannot exfiltrate it.

### 8.2 The output container

The enclave writes a single self-describing blob. All integers big-endian:

```
magic       8 bytes   "SPIDROU1"
header_len  4 bytes   uint32
header      header_len bytes, UTF-8 JSON
per chunk:  4 bytes   uint32 ciphertext length
            N bytes   ciphertext || 16-byte GCM tag
```

Header JSON:
```jsonc
{
  "filename": "patients_anonymised.csv",
  "content_type": "text/csv",
  "total_bytes": 91234567,
  "chunk_size": 67108864,
  "total_chunks": 2,
  "base_iv": "<base64, 12 bytes>",
  "chunk_digests": ["<hex sha256 of plaintext chunk 0>", "…"],
  "plaintext_sha256": "<hex root>",
  "run_id": "<= the upload_id>"
}
```

Nonce = `base_iv + index`; AAD = `` `${run_id}:${index}:${total_chunks}` `` — the same scheme as the upload, so there is one set of crypto rules to get right rather than two.

**`run_id` is the `upload_id`.** No new identifier: the enclave already has it, it is unique per session, and the browser already knows it. One less thing to plumb through.

Chunked rather than one big AES-GCM blob because the browser has to decrypt within the 128 MiB budget — a single 100 MB blob would need 100 MB ciphertext plus 100 MB plaintext live at once.

### 8.3 Download path

**`GET /enclave/output/download?url=<url-encoded output blob URL>`**, `Authorization: Bearer <jwt>` → streams the container back as `application/octet-stream`.

This generalises the endpoint already built for DICOM (`/enclave/dicom-output`). It exists because the blob has no public access: the middleware holds the storage credential, adds a short-lived SAS or reads server-side, and streams the bytes. The browser never sees a SAS token, and a plain `<a href download>` could not send the Bearer header anyway.

The enclave reports the location in `/enclave/status`:
```jsonc
{ "status": "success",
  "outputs": { "direct": {
    "outputBlobUrl": "https://…/output-data/<run_id>.enc",
    "filename": "patients_anonymised.csv",
    "bytes": 91234567,
    "expires_at": "2026-08-06T15:05:00Z" } } }
```

### 8.4 Browser side — decrypting without blowing the budget

Decryption runs in `outputDownloadWorker.ts` under the same 2× rule. The response is consumed via `response.body.getReader()` and each chunk is decrypted as it arrives, so the ciphertext is never held whole.

Each decrypted chunk is wrapped in **its own Blob and released immediately**; the final file is `new Blob(parts)`. Blob data is browser-managed and typically disk-backed, so the JS heap stays at ~2× chunk regardless of output size. (The File System Access API would let us stream to a user-chosen file with the same guarantee and no Blob layer — worth adding for Chrome/Edge later, but it is not needed to hold the budget.)

Every chunk is checked against `chunk_digests[i]` and the whole against `plaintext_sha256` **before** the save is reported as successful.

### 8.5 Consequences — surfaced in the UI

1. **The output is still ephemeral**, just for a different reason: it is encrypted to a key held only in this browser's IndexedDB. Clearing site data, or opening the run on another machine, loses it permanently. The Output page carries an explicit warning and a countdown to `expires_at`.
2. **Output TTL: 2 hours.** Blob storage makes this cheap, so the window can be generous. A sweeper deletes expired blobs.
3. **No run-history re-download for direct-mode runs** — confirmed acceptable. The blob survives, but without the key it is undecryptable, so history entries should be marked "output encrypted to the originating browser".
4. **This supersedes the DICOM download proxy.** [DicomOutput.tsx](src/components/pages/OutputPage/DicomOutput.tsx) hands the user a Fernet-encrypted file to decrypt with an external script. On this path the file arrives already decrypted — strictly better. Worth folding in rather than maintaining two output mechanisms.

---

## 9. Resume after reload

A 100 MB upload over a slow link is minutes long, and a reload mid-flight currently means starting over. Everything needed to resume already exists in the protocol — chunk PUTs are idempotent by index, `/status` reports what arrived, and per-chunk crypto is deterministic from `(key, base_iv, index)`. What's missing is client-side persistence.

### 9.1 What to persist, and where

**IndexedDB, not localStorage** — we need to store `CryptoKey` objects and a growing digest list, neither of which fits localStorage's string-only API.

```ts
// store: "pendingUploads", keyed by uploadId
{
  uploadId, runId,
  fileName, fileSize, fileLastModified, format,
  headDigest,                 // sha256 of the first 1 MiB — identity check, see 9.3
  chunkSize, totalChunks,
  baseIv, outputBaseIv,
  aesKey:    CryptoKey,       // non-extractable, structured-cloned
  outputKey: CryptoKey,       // non-extractable
  chunkDigests: string[],     // appended as each chunk is encrypted
  sentIndices: number[],
  teeKeyFingerprint,          // sha256 of the attested TEE public key — see 9.4
  fileHandle?: FileSystemFileHandle,   // Chrome/Edge only, see 9.3
  createdAt
}
```

`chunkDigests` must be written **incrementally**, as each chunk is encrypted — the §4.4 root hash covers every chunk, including ones sent before the reload, so recomputing it later would require re-reading the whole file.

### 9.2 Resume flow

1. On mounting the Data or Encryption step, look for a `pendingUploads` record newer than `SESSION_TTL`.
2. `GET /enclave/upload/{id}/status`. A `404`/`410` means the enclave session expired — discard the record and start clean.
3. Re-acquire the file (§9.3) and re-verify the TEE key (§9.4).
4. Encrypt and PUT only the indices missing from `received_chunks`. Deterministic crypto means resumed chunks are byte-compatible with the originals.
5. `POST /complete` with the persisted digest root.
6. Delete the IndexedDB record on completion, abort, or TTL.

Show this with a **"Resume upload?" banner** — the codebase already has this exact UX pattern in [SKALD.tsx](src/components/pages/KAnonymization/SKALD/SKALD.tsx#L166) for saved Pass-2 results (Resume / Dismiss actions, age display). Reuse the shape so it feels native.

### 9.3 Re-acquiring the file — the hard part

A `File` handle cannot survive a reload; browsers deliberately forbid it. Two paths:

- **Chrome/Edge — `FileSystemFileHandle`.** If the user originally picked the file via `showOpenFilePicker()`, the resulting handle **is** storable in IndexedDB and does survive reload. On resume, `handle.requestPermission({mode:'read'})` → one click, and the file is back with no re-picking. This is a strong reason to prefer `showOpenFilePicker()` over `<input type=file>` in direct mode where available.
- **Firefox/Safari — re-select.** Prompt the user to pick the same file again.

**Either way, verify identity before resuming:** `name` + `size` + `lastModified` **and** the stored `headDigest` (SHA-256 of the first 1 MiB). All four must match.

> This check is not paranoia. Each chunk is authenticated *individually*, so splicing chunks 0–1 of file A with chunks 2–3 of file B produces a dataset where **every chunk passes AES-GCM verification** and only the §4.4 root hash catches it — at `complete`, after the entire upload has been paid for. The head digest fails it in milliseconds instead.

### 9.4 Re-verifying the TEE key

After a reload, attestation runs again. If the enclave was redeployed in the meantime it has a **new** RSA keypair, and the `wrapped_key` from the original `init` is undecryptable by it — the upload is dead no matter how many chunks arrived.

So store a fingerprint (SHA-256 of the attested public key) at `init`, and on resume compare it against the freshly attested key. On mismatch, discard the record and restart with a clear message. Cheap check; without it the failure surfaces as a confusing error at `complete`.

### 9.5 Output-download resume

Simpler, because the enclave holds the output and chunks are addressable: re-fetch whatever is missing. Persist `runId` + `outputKey` + the manifest. With the File System Access API the write handle also persists, so a partial download can continue; on the Blob fallback, restart the download (bounded by the output TTL).

---

## 10. Execution phases

| Phase | Work | Status |
|---|---|---|
| **1. FE crypto** | `cryptoUtils` AES-GCM additions + upload worker, verified against the Python enclave reference | **Done** |
| **2. FE UI** | Third data-source option, head-slice preview, size gates, progress, `BlobUrlsStep` skipped | **Done** |
| **3. Local verification** | Python reference + mock + interop and end-to-end tests | **Done** |
| **5. Output download** | Output key, container format, streaming decrypt, integrity checks, ephemerality warnings | **Done** |
| **6. Resume** | IndexedDB persistence, resume banner, file re-acquisition, TEE key fingerprint check | **Done** |
| **4. Real backend** | nginx/middleware config (§6); enclave session manager, tmpfs spooling, `enclave://` resolver, output writer | **Outstanding** — see `backend-changes-direct-upload.md` |
| **7. Hardening** | Quotas, TTL sweepers, ownership authz, and **timing a full run at the size cap on the real DC2as_v5** to set the final limit | **Outstanding** |

The frontend was deliberately built before the backend existed, with the crypto proven byte-for-byte against the Python reference first. That ordering means any failure during backend integration is on the backend side — the browser half is already known-good, which removes the usual "which end is wrong?" ambiguity from a two-codebase crypto bring-up.

Verification commands are in `local-testing.md` §"Automated checks".

---

## 11. Resolved decisions

| # | Question | Answer |
|---|---|---|
| 1 | Enclave sizing | **`Standard_DC2as_v5`** — 2 vCPU / 8 GiB / no local temp disk. Drove §3.2 (limits cut to 100 MB, CPU-bound not RAM-bound) and §3.4 (tmpfs scratch). |
| 2 | Upload timing UX (file picked at step 3, uploaded at step 8) | **Accepted as-is.** |
| 3 | Output destination | **Downloaded in the browser, stored nowhere** → §8. `BlobUrlsStep` is now skipped entirely in direct mode (§5.7). |
| 4 | Fernet key-half ordering | Explained in §11.1 below. **Leave it alone.** |
| 5 | Proxy config ownership | Owned by us → concrete nginx block in §6. |
| 6 | Resume after reload | **Required** → §9. |

### 11.1 The Fernet key-half issue, explained

A Fernet key is 32 bytes, split into two 16-byte halves. **Per the Fernet spec the first 16 bytes are the HMAC signing key and the last 16 are the AES-128-CBC encryption key.** Our [cryptoUtils.ts](src/utils/cryptoUtils.ts#L36-L37) does the opposite:

```ts
const encryptionKey = fernetKeyBytes.slice(0, 16);   // spec says this half is for HMAC
const signingKey    = fernetKeyBytes.slice(16, 32);  // spec says this half is for AES
```

Verified against Python's stock `cryptography.fernet.Fernet`: taking a real Fernet token and trying both orderings, spec order (`signing=first16`, `encryption=last16`) verifies the HMAC and recovers the plaintext; our order fails the HMAC and yields garbage.

**So the tokens our UI produces are not valid Fernet.** A standard `Fernet(key).decrypt(token)` on the enclave side would reject them outright.

**But the config path works in production.** The only way that can be true is that the enclave is *also* using the swapped ordering — i.e. hand-rolled code mirroring ours, not the stock library. Both ends are consistently non-standard, so they interoperate.

What this means practically:

- **Do not "correct" the frontend to match the spec.** It would immediately break config decryption in the enclave. This is why it's flagged rather than fixed.
- **Do not build anything new on `encryptWithFernet`.** Anyone who later reaches for a stock Fernet library on either end will get an HMAC failure with no obvious cause.
- The new data path uses **stock AES-256-GCM on both ends**, so the question never arises there. That is a real argument for the choice in §4.7, beyond the memory and bandwidth ones.
- If you want it confirmed independently: ask the TEE side to run `Fernet(key).decrypt(token)` on a token produced by the UI. If it raises `InvalidToken`, that's the swap.

*(A tidy long-term fix is to change both ends to spec order in the same release — but that's a coordinated breaking change with no functional payoff, so it isn't proposed here.)*
