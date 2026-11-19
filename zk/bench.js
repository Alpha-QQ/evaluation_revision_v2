// Groth16 selective-disclosure benchmark (snarkjs + circomlibjs).
// Usage: node bench.js '<json settings>'   ->  prints one JSON object on stdout.
"use strict";
const path = require("path");
const crypto = require("crypto");
const snarkjs = require("snarkjs");
const { buildEddsa, buildPoseidon } = require("circomlibjs");

const BUILD = path.join(__dirname, "build");
const WASM = path.join(BUILD, "disclose_js", "disclose.wasm");
const ZKEY = path.join(BUILD, "disclose.zkey");
const VKEY = require(path.join(BUILD, "vkey.json"));
const P = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");

function toField(v) {
  if (typeof v === "boolean") return v ? 1n : 0n;
  if (typeof v === "number") return BigInt(v);
  const h = crypto.createHash("sha256").update(String(v)).digest("hex");
  return BigInt("0x" + h) % P;
}

function shuffle(a, rnd) {
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(rnd() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function mulberry32(seed) {
  return function () {
    seed |= 0; seed = (seed + 0x6D2B79F5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function pkgVersion(name) {
  const fs = require("fs");
  return JSON.parse(fs.readFileSync(path.join(__dirname, "node_modules", name, "package.json"))).version;
}

const ms = (t0) => Number(process.hrtime.bigint() - t0) / 1e6;

async function main() {
  const cfg = JSON.parse(process.argv[2]);
  const rnd = mulberry32(cfg.seed);
  const eddsa = await buildEddsa();
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const attrs = cfg.attributes.map(toField);
  const N = attrs.length;
  const sk = crypto.randomBytes(32);
  const pub = eddsa.prv2pub(sk);

  function issue() {
    const h1 = poseidon(attrs.slice(0, 16));
    const msg = poseidon([h1, ...attrs.slice(16)]);
    return eddsa.signPoseidon(sk, msg);
  }

  async function present(d, nonce, sig) {
    const mask = attrs.map((_, i) => (i < d ? 1 : 0));
    const input = {
      attr: attrs.map(String), R8x: F.toObject(sig.R8[0]).toString(),
      R8y: F.toObject(sig.R8[1]).toString(), S: sig.S.toString(),
      Ax: F.toObject(pub[0]).toString(), Ay: F.toObject(pub[1]).toString(),
      mask: mask.map(String), nonce: nonce.toString(),
    };
    return snarkjs.groth16.fullProve(input, WASM, ZKEY);
  }

  async function verify(pres, d, nonce) {
    // public signals: disclosed[N], Ax, Ay, mask[N], nonce
    const ps = pres.publicSignals;
    if (ps[N] !== F.toObject(pub[0]).toString() || ps[N + 1] !== F.toObject(pub[1]).toString()) return false;
    for (let i = 0; i < N; i++) if (ps[N + 2 + i] !== (i < d ? "1" : "0")) return false;
    if (ps[2 * N + 2] !== nonce.toString()) return false;
    return snarkjs.groth16.verify(VKEY, ps, pres.proof);
  }

  const lat = { issue: [] };
  const sizes = {};
  for (const d of cfg.attribute_counts) { lat["present_" + d] = []; lat["verify_" + d] = []; sizes[d] = []; }

  // warm-up
  const sig0 = issue();
  const n0 = BigInt("0x" + crypto.randomBytes(31).toString("hex"));
  const w = await present(cfg.attribute_counts[0], n0, sig0);
  if (!(await verify(w, cfg.attribute_counts[0], n0))) throw new Error("warm-up verification failed");

  for (let r = 0; r < cfg.latency_reps; r++) {
    let t0 = process.hrtime.bigint();
    const sig = issue();
    lat.issue.push(ms(t0));
    const order = shuffle(cfg.attribute_counts.flatMap((d) => [[d, "present"], [d, "verify"]]), rnd);
    for (const [d, wf] of order) {
      const nonce = BigInt("0x" + crypto.randomBytes(31).toString("hex"));
      if (wf === "present") {
        t0 = process.hrtime.bigint();
        const pres = await present(d, nonce, sig);
        lat["present_" + d].push(ms(t0));
        sizes[d].push(Buffer.byteLength(JSON.stringify(pres)) / 1024);
      } else {
        const pres = await present(d, nonce, sig);
        t0 = process.hrtime.bigint();
        const ok = await verify(pres, d, nonce);
        lat["verify_" + d].push(ms(t0));
        if (!ok) throw new Error("verification failed");
      }
    }
    if (cfg.progress) process.stderr.write(`\r  zk-SNARK round ${r + 1}/${cfg.latency_reps}`);
  }
  if (cfg.progress) process.stderr.write("\n");
  // negative check: wrong nonce must fail
  const bad = await present(cfg.attribute_counts[0], 5n, sig0);
  const negative_ok = !(await verify(bad, cfg.attribute_counts[0], 6n));
  process.stdout.write(JSON.stringify({ latency_ms: lat, artifact_kib: sizes, negative_check: negative_ok,
    node: process.version, snarkjs: pkgVersion("snarkjs"), circomlibjs: pkgVersion("circomlibjs") }));
  process.exit(0);
}

main().catch((e) => { console.error(e); process.exit(1); });
