"""Running-time comparison with existing selective-disclosure credentials.

Schemes (same 20-attribute credential as benchmark.USER):
  sd_jwt : IETF SD-JWT with key binding (ES256), reference implementation
           sd-jwt (openwallet-foundation-labs/sd-jwt-python).
  bbs    : BBS signatures and proofs, BLS12-381-SHA-256 ciphersuite of the
           IRTF CFRG draft (bbs.py, checked against the draft fixtures).
  zksnark: Groth16 proof that the disclosed values come from an
           EdDSA-Poseidon signed attribute vector (circom circuit, snarkjs).

Workflows per scheme: issue (once per credential), present (holder output
for d disclosed attributes, bound to a fresh verifier nonce) and verify.
Latency and traced memory are measured in separate passes as in
benchmark.py.  The zk-SNARK part runs in Node.js; its memory is not traced.
"""
from __future__ import annotations

import gc
import json
import os
import random
import secrets
import shutil
import subprocess
import time
import tracemalloc
from typing import Dict, List

import bbs
from benchmark import USER, _summary

HERE = os.path.dirname(os.path.abspath(__file__))
ZK_DIR = os.path.join(HERE, "zk")
AUD = "https://verifier.example"


# ------------------------------------------------------------------ SD-JWT
class SDJWTScheme:
    name = "sd_jwt"

    def __init__(self):
        from jwcrypto.jwk import JWK
        self.issuer_key = JWK.generate(kty="EC", crv="P-256")
        self.holder_key = JWK.generate(kty="EC", crv="P-256")
        self.issuer_pub = JWK.from_json(self.issuer_key.export_public())
        self.cred = self.issue()

    def issue(self):
        from sd_jwt.common import SDObj
        from sd_jwt.issuer import SDJWTIssuer
        claims = {"iss": "https://issuer.example", "iat": 1763510400}
        claims.update({SDObj(k): v for k, v in USER.items()})
        return SDJWTIssuer(claims, self.issuer_key, self.holder_key).sd_jwt_issuance

    def present(self, d: int, nonce: str) -> str:
        from sd_jwt.holder import SDJWTHolder
        holder = SDJWTHolder(self.cred)
        holder.create_presentation({k: True for k in list(USER)[:d]}, nonce, AUD,
                                   self.holder_key, "ES256")
        return holder.sd_jwt_presentation

    def verify(self, pres: str, d: int, nonce: str) -> bool:
        from sd_jwt.verifier import SDJWTVerifier
        v = SDJWTVerifier(pres, lambda iss, hdr: self.issuer_pub, AUD, nonce)
        payload = v.get_verified_payload()
        return all(k in payload for k in list(USER)[:d])

    @staticmethod
    def size(pres: str) -> float:
        return len(pres.encode()) / 1024


# --------------------------------------------------------------------- BBS
def _bbs_msg(k, v) -> bytes:
    return json.dumps([k, v], separators=(",", ":")).encode()


class BBSScheme:
    name = "bbs"

    def __init__(self):
        self.sk, self.pk = bbs.keygen()
        self.header = b"credential-schema-v1"
        self.msgs = [_bbs_msg(k, v) for k, v in USER.items()]
        self.sig = self.issue()

    def issue(self) -> bytes:
        return bbs.sign(self.sk, self.pk, self.header, self.msgs)

    def present(self, d: int, nonce: str) -> bytes:
        return bbs.proof_gen(self.pk, self.sig, self.header, nonce.encode(), self.msgs,
                             list(range(d)))

    def verify(self, proof: bytes, d: int, nonce: str) -> bool:
        return bbs.proof_verify(self.pk, proof, self.header, nonce.encode(), self.msgs[:d],
                                list(range(d)))

    def size(self, proof: bytes) -> float:
        # proof plus the disclosed messages and their indexes (8 bytes each)
        d = (len(self.msgs) - (len(proof) - 3 * 48 - 4 * 32) // 32)
        return (len(proof) + sum(len(m) + 8 for m in self.msgs[:d])) / 1024


# ------------------------------------------------- proposed (issuance only)
class ProposedIssue:
    """Schnorr issuance of the proposed scheme.  Its presentation and
    verification are measured in benchmark.py (candidate sets, caching)."""
    name = "proposed"
    issue_only = True

    def __init__(self):
        import proposed as P
        from coincurve import PrivateKey
        self.P = P
        self.issuer = PrivateKey()
        self.cred = P.make_credential(self.issuer, PrivateKey().public_key, USER, 1234)

    def issue(self):
        return self.P.issue_credential(self.issuer, self.cred)


# ------------------------------------------------------------------ runner
def _measure(call, mode: str):
    gc.collect()
    if mode == "memory":
        tracemalloc.start()
        out = call()
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        return peak / 1024, out
    t0 = time.perf_counter()
    out = call()
    return (time.perf_counter() - t0) * 1000, out


def _run_python(schemes, attribute_counts: List[int], latency_reps: int, memory_reps: int,
                progress: bool) -> List[Dict]:
    data, sizes = {}, {}
    full = [s for s in schemes if not getattr(s, "issue_only", False)]
    for s in schemes:
        s.issue()
    for s in full:  # warm-up and correctness check
        n = secrets.token_hex(16)
        p = s.present(attribute_counts[0], n)
        assert s.verify(p, attribute_counts[0], n), s.name
        try:
            rejected = not s.verify(p, attribute_counts[0], n + "x")
        except Exception:
            rejected = True
        assert rejected, s.name + " accepted a wrong nonce"
    for mode, reps in (("latency", latency_reps), ("memory", memory_reps)):
        for r in range(reps):
            order = [(s, "issue", None) for s in schemes]
            order += [(s, w, d) for s in full for d in attribute_counts
                      for w in ("present", "verify")]
            random.shuffle(order)
            for s, w, d in order:
                nonce = secrets.token_hex(16)
                if w == "issue":
                    v, _ = _measure(s.issue, mode)
                elif w == "present":
                    v, pres = _measure(lambda: s.present(d, nonce), mode)
                    if mode == "latency":
                        sizes.setdefault((s.name, d), []).append(s.size(pres))
                else:
                    pres = s.present(d, nonce)
                    v, ok = _measure(lambda: s.verify(pres, d, nonce), mode)
                    assert ok, (s.name, d)
                data.setdefault((s.name, w, d, mode), []).append(v)
            if progress:
                print("\r  SD-JWT/BBS %s round %d/%d" % (mode, r + 1, reps), end="", flush=True)
    if progress:
        print()
    rows = []
    for s in schemes:
        row = {"scheme": s.name, "workflow": "issue", "disclosed": None,
               "latency_ms": _summary(data[(s.name, "issue", None, "latency")])}
        if memory_reps:
            row["peak_traced_memory_kib"] = _summary(data[(s.name, "issue", None, "memory")])
        rows.append(row)
        if getattr(s, "issue_only", False):
            continue
        for d in attribute_counts:
            for w in ("present", "verify"):
                row = {"scheme": s.name, "workflow": w, "disclosed": d,
                       "latency_ms": _summary(data[(s.name, w, d, "latency")])}
                if memory_reps:
                    row["peak_traced_memory_kib"] = _summary(data[(s.name, w, d, "memory")])
                if w == "present":
                    row["artifact_kib"] = _summary(sizes[(s.name, d)])
                rows.append(row)
    return rows


def _run_zk(attribute_counts: List[int], reps: int, seed: int, progress: bool):
    node = shutil.which("node")
    if node is None:
        raise SystemExit("Node.js not found. Install Node.js 20 or 22 and run 'npm ci' in zk/.")
    if not os.path.isdir(os.path.join(ZK_DIR, "node_modules", "snarkjs")):
        raise SystemExit("snarkjs not installed. Run 'npm ci' inside the zk folder.")
    cfg = {"seed": seed, "attributes": list(USER.values()), "attribute_counts": attribute_counts,
           "latency_reps": reps, "progress": progress}
    proc = subprocess.run([node, os.path.join(ZK_DIR, "bench.js"), json.dumps(cfg)],
                          stdout=subprocess.PIPE, cwd=ZK_DIR, check=True)
    raw = json.loads(proc.stdout)
    if not raw["negative_check"]:
        raise SystemExit("zk-SNARK negative check failed")
    rows = [{"scheme": "zksnark", "workflow": "issue", "disclosed": None,
             "latency_ms": _summary(raw["latency_ms"]["issue"])}]
    for d in attribute_counts:
        rows.append({"scheme": "zksnark", "workflow": "present", "disclosed": d,
                     "latency_ms": _summary(raw["latency_ms"]["present_%d" % d]),
                     "artifact_kib": _summary(raw["artifact_kib"][str(d)])})
        rows.append({"scheme": "zksnark", "workflow": "verify", "disclosed": d,
                     "latency_ms": _summary(raw["latency_ms"]["verify_%d" % d])})
    versions = {"node": raw["node"], "snarkjs": raw["snarkjs"], "circomlibjs": raw["circomlibjs"]}
    return rows, versions


def run_comparison(attribute_counts: List[int], latency_reps: int, memory_reps: int,
                   zk_reps: int, seed: int, progress: bool = True) -> Dict:
    random.seed(seed)
    rows = _run_python([ProposedIssue(), SDJWTScheme(), BBSScheme()], attribute_counts, latency_reps,
                       memory_reps, progress)
    zk_rows, zk_versions = _run_zk(attribute_counts, zk_reps, seed, progress)
    return {"parameters": {"attribute_counts": attribute_counts, "latency_reps": latency_reps,
                           "memory_reps": memory_reps, "zk_reps": zk_reps, "seed": seed,
                           "total_attributes": len(USER),
                           "zk_circuit": "Groth16/BN254, EdDSA-Poseidon, 20 attributes"},
            "versions": zk_versions, "summary": rows + zk_rows}
