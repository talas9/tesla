#!/usr/bin/env node

/**
 * Generic Request Logger + Signature Lookup + Resumable Local File Serving
 *
 * - Put your files next to server.js:
 *     ./signature.json
 *     ./2025.20.8.ice
 *     ./2022.8.10.5.mcu1
 *     ...
 *
 * - Files are served from ROOT path:
 *     GET /2025.20.8.ice
 *     GET /2022.8.10.5.mcu1
 *
 * - Resume supported via HTTP Range (206 Partial Content)
 *
 * - Signature lookup:
 *     GET /packages/signature?signature=...
 */

const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = Number(process.env.PORT || 8080);

// ---------- Body parsing ----------
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));
app.use(express.raw({ type: "*/*", limit: "200mb" }));

// ---------- Signature handling (signature.json next to server.js) ----------
const SIG_PATH = path.join(__dirname, "signature.json");
let signatures = [];

function normalizeSig(s) {
  return String(s || "").trim();
}

function loadSignatures() {
  try {
    const raw = fs.readFileSync(SIG_PATH, "utf8");
    const parsed = JSON.parse(raw);
    const list = Array.isArray(parsed) ? parsed : parsed?.signatures;

    if (!Array.isArray(list)) {
      throw new Error(
        "signature.json must be an array or { signatures: [...] }"
      );
    }

    signatures = list;
    console.log(`[sig] Loaded ${signatures.length} records from ${SIG_PATH}`);
  } catch (e) {
    console.error(`[sig] Failed to load ${SIG_PATH}: ${e.message}`);
    signatures = [];
  }
}

loadSignatures();

try {
  fs.watch(SIG_PATH, { persistent: true }, () => {
    console.log("[sig] signature.json changed; reloading");
    loadSignatures();
  });
} catch (e) {
  console.warn(`[sig] fs.watch disabled: ${e.message}`);
}

// ---------- Global request logger ----------
app.use((req, res, next) => {
  const ip =
    (req.headers["x-forwarded-for"]
      ? String(req.headers["x-forwarded-for"]).split(",")[0].trim()
      : "") ||
    req.socket?.remoteAddress ||
    "unknown";

  let bodyForLog = req.body;
  if (Buffer.isBuffer(req.body)) {
    const buf = req.body;
    bodyForLog = {
      _type: "buffer",
      length: buf.length,
      preview_utf8: buf.subarray(0, Math.min(buf.length, 512)).toString("utf8"),
      preview_hex: buf.subarray(0, Math.min(buf.length, 128)).toString("hex"),
    };
  }

  console.log("=".repeat(100));
  console.log(`[REQ] ${new Date().toISOString()}`);
  console.log(`[IP ] ${ip}`);
  console.log(`[URL] ${req.method} ${req.originalUrl}`);
  console.log(`[HDR] ${JSON.stringify(req.headers, null, 2)}`);
  console.log(`[QRY] ${JSON.stringify(req.query, null, 2)}`);
  console.log(`[BDY] ${JSON.stringify(bodyForLog, null, 2)}`);
  console.log("=".repeat(100));

  next();
});

// ---------- API: signature lookup ----------
// GET /packages/signature?signature=<value>
app.get("/packages/signature", (req, res) => {
  const sig = normalizeSig(req.query.signature);
  if (!sig) return res.status(400).json({ error: "missing ?signature=" });

  const found =
    signatures.find((x) => normalizeSig(x?.signature) === sig) ||
    signatures.find((x) => normalizeSig(x?.sig) === sig) ||
    null;

  if (!found) return res.status(404).json({ error: "signature not found" });
  return res.json(found);
});

// POST /vehicles/:vin/handshake
// Content-Type: application/x-www-form-urlencoded
app.post("/vehicles/:vin/handshake", (req, res) => {
  const vin = req.params.vin;

  const sig = req.body?.vehicle?.package_signature
    ? String(req.body.vehicle.package_signature).trim()
    : null;

  console.log("VIN:", vin);
  console.log("package_signature:", sig);

  const found =
    signatures.find((x) => normalizeSig(x?.signature) === sig) ||
    signatures.find((x) => normalizeSig(x?.sig) === sig) ||
    null;

  if (!found) return res.status(404).json({ error: "signature not found" });
  return res.json(found);
});

// ---------- API: status sink ----------
app.all("/status", (req, res) => res.json({ ok: true }));

// ---------- API: health ----------
app.get("/health", (req, res) => res.json({ ok: true }));

// ---------- Resumable local file serving from ROOT ----------
// Matches: *.ice, *.mcu, *.mcu1, *.mcu2, *.mcu25, *.mcu3
const ALLOWED_EXT_RE = /\.(ice|mcu|mcu1|mcu2|mcu25|mcu3)$/i;

function serveResumableFile(req, res, filePath, filename) {
  const stat = fs.statSync(filePath);
  const total = stat.size;

  // ETag based on filename+size+mtime
  const etag = crypto
    .createHash("sha1")
    .update(`${filename}:${total}:${stat.mtimeMs}`)
    .digest("hex");

  res.setHeader("Accept-Ranges", "bytes");
  res.setHeader("ETag", `"${etag}"`);
  res.setHeader("Content-Type", "application/octet-stream");
  res.setHeader("Content-Disposition", `inline; filename="${filename}"`);

  // If-None-Match (only when not doing range)
  if (!req.headers.range && req.headers["if-none-match"] === `"${etag}"`) {
    return res.status(304).end();
  }

  // --- progress logger (prints every 10% of FULL FILE) ---
  const progressState = { lastBucket: -10 };
  let sentBytes = 0;

  function logProgress(delta) {
    sentBytes += delta;
    const pct = Math.floor((sentBytes / total) * 100);
    const bucket = Math.floor(pct / 10) * 10;
    if (bucket > progressState.lastBucket) {
      progressState.lastBucket = bucket;
      console.log(`[DL] ${filename} → ${bucket}% (sent=${sentBytes}/${total})`);
    }
  }

  const range = req.headers.range;

  // No range: full file
  if (!range) {
    res.setHeader("Content-Length", total);

    console.log(`[DL] ${filename} starting full download`);
    const stream = fs.createReadStream(filePath, {
      highWaterMark: 1024 * 1024,
    });

    stream.on("data", (chunk) => logProgress(chunk.length));
    stream.on("end", () => console.log(`[DL] ${filename} completed (100%)`));
    stream.on("error", (e) =>
      console.log(`[DL] ${filename} stream error: ${e.message}`)
    );

    return stream.pipe(res);
  }

  // Range: bytes=start-end
  const match = /^bytes=(\d*)-(\d*)$/.exec(range);
  if (!match) {
    res.setHeader("Content-Range", `bytes */${total}`);
    return res.status(416).end();
  }

  let start = match[1] ? parseInt(match[1], 10) : 0;
  let end = match[2] ? parseInt(match[2], 10) : total - 1;

  if (Number.isNaN(start) || Number.isNaN(end) || start > end) {
    res.setHeader("Content-Range", `bytes */${total}`);
    return res.status(416).end();
  }
  if (start >= total) {
    res.setHeader("Content-Range", `bytes */${total}`);
    return res.status(416).end();
  }

  end = Math.min(end, total - 1);
  const chunkSize = end - start + 1;

  res.status(206);
  res.setHeader("Content-Range", `bytes ${start}-${end}/${total}`);
  res.setHeader("Content-Length", chunkSize);

  console.log(
    `[DL] ${filename} starting range download bytes=${start}-${end}/${total}`
  );
  const stream = fs.createReadStream(filePath, {
    start,
    end,
    highWaterMark: 1024 * 1024,
  });

  // For Range, count progress relative to full file:
  // start offset means we "already have" start bytes.
  sentBytes = start;
  stream.on("data", (chunk) => logProgress(chunk.length));
  stream.on("end", () =>
    console.log(`[DL] ${filename} range completed bytes=${start}-${end}`)
  );
  stream.on("error", (e) =>
    console.log(`[DL] ${filename} stream error: ${e.message}`)
  );

  return stream.pipe(res);
}

// Serve allowed extensions from root
app.get("/:name", (req, res, next) => {
  const name = String(req.params.name || "");

  // Only handle allowed extensions here
  if (!ALLOWED_EXT_RE.test(name)) return next();

  // Block path traversal / subpaths
  if (name.includes("/") || name.includes("\\") || name.includes("..")) {
    return res.status(400).json({ error: "invalid filename" });
  }

  const filePath = path.join(__dirname, name);

  if (!fs.existsSync(filePath))
    return res.status(404).json({ error: "file not found" });
  const st = fs.statSync(filePath);
  if (!st.isFile()) return res.status(404).json({ error: "not a file" });

  return serveResumableFile(req, res, filePath, name);
});

// Catch-all (so you can see 404s clearly)
app.use((req, res) => res.status(404).json({ error: "not found" }));

app.listen(PORT, "0.0.0.0", () => {
  console.log(`[srv] Listening on http://0.0.0.0:${PORT}`);
  console.log(`[srv] signature file: ${SIG_PATH}`);
  console.log(`[srv] serving local files from: ${__dirname}`);
  console.log(`[srv] allowed extensions: .ice .mcu .mcu1 .mcu2 .mcu25 .mcu3`);
});
