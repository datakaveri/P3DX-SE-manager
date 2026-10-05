// Runs the UI's own output download worker (outputDownloadWorker.ts, bundled
// by esbuild) under Node against a container file, exactly as the browser
// would after fetching it through the middleware proxy.
//
//   node harness.mjs <bundled-worker.mjs> <container-file> <key-hex> <out-file | sha256>
//
// Prints {"filename", "bytes"[, "sha256"]} on success; exits 1 with the
// worker's error. `sha256` hashes the decrypted output instead of writing it.
import fs from "node:fs";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { createHash } from "node:crypto";

const [workerPath, containerPath, keyHex, outPath] = process.argv.slice(2);

globalThis.fetch = async () =>
  new Response(Readable.toWeb(fs.createReadStream(containerPath)), {
    status: 200,
    headers: { "Content-Length": String(fs.statSync(containerPath).size) },
  });

const done = new Promise((resolve) => {
  globalThis.self = {
    postMessage: (msg) => { if (msg.type !== "progress") resolve(msg); },
    close: () => {},
  };
});

await import(workerPath);
const outputKey = await crypto.subtle.importKey(
  "raw", Buffer.from(keyHex, "hex"), "AES-GCM", false, ["decrypt"]);
globalThis.self.onmessage({ data: { type: "download", downloadUrl: "file", accessToken: "t", outputKey } });

const msg = await done;
if (msg.type !== "success") {
  console.error(msg.error);
  process.exit(1);
}
if (outPath === "sha256") {
  const hash = createHash("sha256");
  for await (const part of Readable.fromWeb(msg.blob.stream())) hash.update(part);
  console.log(JSON.stringify({ filename: msg.filename, bytes: msg.bytes, sha256: hash.digest("hex") }));
} else {
  await pipeline(Readable.fromWeb(msg.blob.stream()), fs.createWriteStream(outPath));
  console.log(JSON.stringify({ filename: msg.filename, bytes: msg.bytes }));
}
