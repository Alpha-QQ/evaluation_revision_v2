#!/usr/bin/env python3
"""End-to-end network evaluation of one presentation.

Everything runs on the local machine.  A verifier service and a verifiable
data registry (VDR) are HTTP/1.1 servers on 127.0.0.1; the holder and the
verifier reach them through clients whose traffic is shaped in software:

* each new TCP connection costs ``handshake_rtts`` round-trip times
  (2 = TCP plus a TLS 1.3 handshake, without the TLS cryptography);
* each request is delayed by RTT/2 before it is sent and each response by
  RTT/2 before it is read;
* request and response bodies are paced to the link bandwidth.  All
  connections of one host share one uplink and one downlink, so parallel
  downloads divide the bandwidth.

The VDR serves did:web documents of the issuers and one Bitstring Status
List per issuer.  A presentation consists of

  1. GET  /request        holder <- verifier   policy and session context
  2. POST /presentation   holder -> verifier   transcript T, verification result

Before step 2 the holder resolves the issuer DIDs named in its candidate list
and checks their status entries; when the verifier receives T it checks the
status entries of all candidates.  In the "cold" scenario nothing is cached
and every DID document and status list is fetched; in the "warm" scenario
both parties use cached copies (e.g. refreshed periodically).
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import http.client
import http.server
import json
import math
import os
import random
import secrets
import socketserver
import statistics
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import protocol_adapter as proto

CHUNK = 16 * 1024
STATUS_LIST_BITS = 131072          # minimum length in the W3C Bitstring Status List spec


# ---------------------------------------------------------------- shaping
class Link:
    """One host's access link: shared uplink and downlink pacing."""

    def __init__(self, mbps: float, rtt_ms: float):
        self.rate = mbps * 1e6 / 8.0           # bytes per second
        self.one_way = rtt_ms / 2000.0
        self.rtt = rtt_ms / 1000.0
        self._lock = threading.Lock()
        self._free = {"up": 0.0, "down": 0.0}

    def _reserve(self, direction: str, nbytes: int) -> float:
        with self._lock:
            start = max(time.perf_counter(), self._free[direction])
            end = start + nbytes / self.rate
            self._free[direction] = end
            return end

    def pace(self, direction: str, nbytes: int) -> None:
        _sleep_until(self._reserve(direction, nbytes))


def _sleep_until(deadline: float) -> None:
    while True:
        left = deadline - time.perf_counter()
        if left <= 0:
            return
        time.sleep(left if left > 0.002 else 0)


class ShapedConnection(http.client.HTTPConnection):
    """HTTP/1.1 keep-alive connection whose traffic is shaped by a Link."""

    def __init__(self, host, port, link: Link, handshake_rtts: int):
        super().__init__(host, port, timeout=600)
        self.link = link
        self.handshake_rtts = handshake_rtts
        self.bytes_up = 0
        self.bytes_down = 0

    def connect(self):
        super().connect()
        time.sleep(self.handshake_rtts * self.link.rtt)

    def send(self, data):
        if self.sock is None:
            self.connect()
        if isinstance(data, str):
            data = data.encode("latin-1")
        for i in range(0, len(data), CHUNK):
            part = data[i:i + CHUNK]
            self.link.pace("up", len(part))
            self.sock.sendall(part)
        self.bytes_up += len(data)

    def request_shaped(self, method: str, path: str, body: bytes | None = None,
                       headers: dict | None = None) -> bytes:
        time.sleep(self.link.one_way)              # request propagation
        self.request(method, path, body=body, headers=headers or {})
        resp = self.getresponse()
        time.sleep(self.link.one_way)              # response propagation
        out = bytearray()
        while True:
            part = resp.read(CHUNK)
            if not part:
                break
            self.link.pace("down", len(part))
            out += part
        self.bytes_down += len(out)
        if resp.status != 200:
            raise RuntimeError("HTTP %d for %s" % (resp.status, path))
        return bytes(out)


# ---------------------------------------------------------------- servers
class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _handler(routes_get: dict, post_handler=None):
    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _reply(self, body: bytes, ctype="application/json"):
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            fn = routes_get.get(self.path)
            if fn is None:
                self.send_error(404)
                return
            self._reply(fn())

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            if post_handler is None:
                self.send_error(404)
                return
            self._reply(post_handler(self.path, body))
    return H


def _start(server):
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


# ---------------------------------------------------------------- VDR data
def did_web(port: int, idx: int) -> str:
    return "did:web:127.0.0.1%%3A%d:issuers:i%d" % (port, idx)


def did_web_path(idx: int) -> str:
    return "/issuers/i%d/did.json" % idx


def status_path(idx: int) -> str:
    return "/status/i%d" % idx


def did_document(did: str, pub_xy: tuple[bytes, bytes]) -> bytes:
    x, y = pub_xy
    b64 = lambda v: base64.urlsafe_b64encode(v).rstrip(b"=").decode()
    doc = {
        "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
        "id": did,
        "verificationMethod": [{
            "id": did + "#key-1", "type": "JsonWebKey2020", "controller": did,
            "publicKeyJwk": {"kty": "EC", "crv": "secp256k1", "x": b64(x), "y": b64(y)},
        }],
        "assertionMethod": [did + "#key-1"],
    }
    return json.dumps(doc, separators=(",", ":")).encode()


def status_list(did: str, rng: random.Random, revoked_fraction: float) -> tuple[bytes, int]:
    """Return a Bitstring Status List credential and one unrevoked index."""
    bits = bytearray(STATUS_LIST_BITS // 8)
    revoked = set(rng.sample(range(STATUS_LIST_BITS), int(STATUS_LIST_BITS * revoked_fraction)))
    for i in revoked:
        bits[i // 8] |= 0x80 >> (i % 8)
    free = next(i for i in range(rng.randrange(STATUS_LIST_BITS), STATUS_LIST_BITS * 2)
                if (i % STATUS_LIST_BITS) not in revoked) % STATUS_LIST_BITS
    encoded = base64.urlsafe_b64encode(gzip.compress(bytes(bits), mtime=0)).rstrip(b"=").decode()
    cred = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential", "BitstringStatusListCredential"],
        "issuer": did,
        "credentialSubject": {"type": "BitstringStatusList", "statusPurpose": "revocation",
                              "encodedList": "u" + encoded},
    }
    return json.dumps(cred, separators=(",", ":")).encode(), free


def check_status(list_bytes: bytes, index: int) -> bool:
    enc = json.loads(list_bytes)["credentialSubject"]["encodedList"][1:]
    raw = gzip.decompress(base64.urlsafe_b64decode(enc + "=" * (-len(enc) % 4)))
    return not (raw[index // 8] & (0x80 >> (index % 8)))


def resolve_ok(doc_bytes: bytes, did: str, pub_xy: tuple[bytes, bytes]) -> bool:
    doc = json.loads(doc_bytes)
    jwk = doc["verificationMethod"][0]["publicKeyJwk"]
    dec = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    return doc["id"] == did and (dec(jwk["x"]), dec(jwk["y"])) == pub_xy


# ---------------------------------------------------------------- wallet
def wallet_store(path: str, credential: dict, key: bytes) -> None:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    data = json.dumps(credential, separators=(",", ":")).encode()
    with open(path, "wb") as fh:
        fh.write(nonce + AESGCM(key).encrypt(nonce, data, b"wallet"))


def wallet_load(path: str, key: bytes) -> dict:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    with open(path, "rb") as fh:
        blob = fh.read()
    return json.loads(AESGCM(key).decrypt(blob[:12], blob[12:], b"wallet"))


# ---------------------------------------------------------------- one setup
class World:
    """Keys, VDR contents, servers and caches for one candidate-set size n."""

    def __init__(self, n: int, setup: dict, seed: int, revoked_fraction: float):
        self.n = n
        rng = random.Random(seed + n)
        self.setup = setup                    # from protocol_adapter.make_setup
        self.issuers = setup["issuer_pubs"][:n]          # index 0 = authentic issuer
        self.vdr = _start(_Server(("127.0.0.1", 0), _handler({})))
        self.vdr_port = self.vdr.server_address[1]
        self.dids, self.docs, self.lists, self.index = [], {}, {}, []
        routes = {}
        for i, pub in enumerate(self.issuers):
            did = did_web(self.vdr_port, i)
            xy = proto.pub_xy(pub)
            doc = did_document(did, xy)
            lst, free = status_list(did, rng, revoked_fraction)
            routes[did_web_path(i)] = (lambda d=doc: d)
            routes[status_path(i)] = (lambda l=lst: l)
            self.dids.append(did)
            self.index.append(free)
        self.vdr.RequestHandlerClass = _handler(routes)
        self.routes = routes
        self.doc_bytes = len(routes[did_web_path(0)]())
        self.list_bytes = statistics.fmean(len(routes[status_path(i)]()) for i in range(n))


def _fetch_all(paths: list[str], port: int, link: Link, handshake_rtts: int,
               conns: int) -> dict:
    """Fetch paths over `conns` new keep-alive connections sharing `link`."""
    out = {}
    lanes = [paths[i::conns] for i in range(min(conns, len(paths)))]

    def lane(ps):
        c = ShapedConnection("127.0.0.1", port, link, handshake_rtts)
        try:
            return [(p, c.request_shaped("GET", p)) for p in ps]
        finally:
            c.close()

    with ThreadPoolExecutor(max_workers=len(lanes)) as ex:
        for res in ex.map(lane, lanes):
            out.update(res)
    return out


def run_once(world: World, mbps: float, rtt_ms: float, cache: str, cfg: dict,
             wallet_path: str, wallet_key: bytes, disclosed: int) -> dict:
    n = world.n
    holder_link = Link(mbps, rtt_ms)
    verifier_link = Link(mbps, rtt_ms)
    hs, conns = cfg["handshake_rtts"], cfg["parallel_connections"]
    timings = {}

    # verifier service: holds its whitelist; status lists cached only when warm
    session = {"ctx": proto.new_context(disclosed)}
    vcache = world.routes if cache == "warm" else None

    def on_post(path, body):
        t0 = time.perf_counter()
        if vcache is None:
            fetched = _fetch_all([status_path(i) for i in range(n)], world.vdr_port,
                                 verifier_link, hs, conns)
        else:
            fetched = {status_path(i): vcache[status_path(i)]() for i in range(n)}
        t1 = time.perf_counter()
        ok_status = all(check_status(fetched[status_path(i)], world.index[i]) for i in range(n))
        t2 = time.perf_counter()
        ok = proto.verify(world.setup, body, session["ctx"], n)
        t3 = time.perf_counter()
        return json.dumps({"ok": bool(ok and ok_status), "fetch_ms": (t1 - t0) * 1e3,
                           "status_ms": (t2 - t1) * 1e3, "verify_ms": (t3 - t2) * 1e3}).encode()

    verifier = _start(_Server(("127.0.0.1", 0), _handler(
        {"/request": lambda: json.dumps(session["ctx"]).encode()}, on_post)))
    vport = verifier.server_address[1]
    try:
        start = time.perf_counter()
        # wallet access
        cred = wallet_load(wallet_path, wallet_key)
        t_wallet = time.perf_counter()
        # 1. request
        conn = ShapedConnection("127.0.0.1", vport, holder_link, hs)
        ctx = json.loads(conn.request_shaped("GET", "/request"))
        request_bytes = conn.bytes_down
        t_req = time.perf_counter()
        # holder-side resolution of the issuer DIDs and status checks
        if cache == "cold":
            paths = [did_web_path(i) for i in range(n)] + [status_path(i) for i in range(n)]
            fetched = _fetch_all(paths, world.vdr_port, holder_link, hs, conns)
        else:
            fetched = {p: world.routes[p]() for p in
                       [did_web_path(i) for i in range(n)] + [status_path(i) for i in range(n)]}
        t_fetch = time.perf_counter()
        ok_dids = all(resolve_ok(fetched[did_web_path(i)], world.dids[i],
                                 proto.pub_xy(world.issuers[i])) for i in range(n))
        ok_stat = all(check_status(fetched[status_path(i)], world.index[i]) for i in range(n))
        t_check = time.perf_counter()
        # generation
        transcript = proto.present(world.setup, cred, ctx, n)
        t_gen = time.perf_counter()
        # 2. presentation and result
        result = json.loads(conn.request_shaped(
            "POST", "/presentation", body=transcript,
            headers={"Content-Type": "application/json"}))
        end = time.perf_counter()
        conn.close()
        if not (ok_dids and ok_stat and result["ok"]):
            raise RuntimeError("presentation rejected (dids %s, status %s, verifier %s)"
                               % (ok_dids, ok_stat, result["ok"]))
        timings = {
            "end_to_end_ms": (end - start) * 1e3,
            "wallet_ms": (t_wallet - start) * 1e3,
            "request_ms": (t_req - t_wallet) * 1e3,
            "holder_fetch_ms": (t_fetch - t_req) * 1e3,
            "holder_checks_ms": (t_check - t_fetch) * 1e3,
            "generation_ms": (t_gen - t_check) * 1e3,
            "submit_and_verify_ms": (end - t_gen) * 1e3,
            "verifier_fetch_ms": result["fetch_ms"],
            "verifier_status_ms": result["status_ms"],
            "verification_ms": result["verify_ms"],
            "transcript_bytes": len(transcript),
            "request_bytes": request_bytes,
        }
        timings["network_ms"] = timings["end_to_end_ms"] - (
            timings["wallet_ms"] + timings["holder_checks_ms"] + timings["generation_ms"]
            + timings["verifier_status_ms"] + timings["verification_ms"])
    finally:
        verifier.shutdown()
        verifier.server_close()
    return timings


def _summary(values: list[float]) -> dict:
    mean = statistics.fmean(values)
    sd = statistics.stdev(values) if len(values) > 1 else 0.0
    half = 1.959964 * sd / math.sqrt(len(values))
    return {"mean": mean, "median": statistics.median(values), "std": sd,
            "ci95": [mean - half, mean + half], "runs": len(values)}


def run_network(cfg: dict, seed: int, log=print) -> dict:
    n_max = max(cfg["candidate_sizes"])
    setup = proto.make_setup(n_max, seed)
    tmp = tempfile.mkdtemp(prefix="wallet_")
    wallet_path = os.path.join(tmp, "credential.bin")
    wallet_key = secrets.token_bytes(32)
    wallet_store(wallet_path, setup["credential_record"], wallet_key)
    rows = []
    combos = [(n, b, r, c) for n in cfg["candidate_sizes"] for b in cfg["bandwidths_mbps"]
              for r in cfg["rtts_ms"] for c in cfg["cache"]]
    order = random.Random(seed).sample(range(cfg["reps"] * len(combos)),
                                       cfg["reps"] * len(combos))
    worlds = {n: World(n, setup, seed, cfg["revoked_fraction"]) for n in cfg["candidate_sizes"]}
    raw = {c: [] for c in combos}
    for k, idx in enumerate(order, 1):
        combo = combos[idx % len(combos)]
        n, b, r, c = combo
        raw[combo].append(run_once(worlds[n], b, r, c, cfg, wallet_path, wallet_key,
                                   cfg["disclosed_attributes"]))
        if k % 10 == 0 or k == len(order):
            log("   network run %d/%d" % (k, len(order)))
    for combo in combos:
        n, b, r, c = combo
        runs = raw[combo]
        row = {"n": n, "bandwidth_mbps": b, "rtt_ms": r, "cache": c}
        for key in runs[0]:
            row[key] = _summary([x[key] for x in runs])
        rows.append(row)
    w0 = worlds[cfg["candidate_sizes"][0]]
    for w in worlds.values():
        w.vdr.shutdown()
        w.vdr.server_close()
    return {
        "settings": cfg,
        "model": __doc__.strip(),
        "did_document_bytes": w0.doc_bytes,
        "status_list_bytes_mean": w0.list_bytes,
        "status_list_bits": STATUS_LIST_BITS,
        "rows": rows,
    }
