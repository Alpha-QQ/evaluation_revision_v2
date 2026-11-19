#!/usr/bin/env python3
"""Candidate-set credential presentation (revised protocol).

Components
- Issuer signature: Schnorr, challenge c = H0(m, R), response s = k - x*c.
- URS rows (Tso US(1,n) conversion): for every candidate i a pair (r_i, delta_i)
  with r_i = H0(m_i, pk_i^{r_i} * delta_i).  For the authentic row J,
  (r_J, delta_J) = (c, g^s); for every other row delta_i = alpha_i * pk_i^{-r_i}.
- Joint designated-verifier proof pi_pres (replaces the separate URS
  witness-hiding proof and the separate holder-key linkage proof):
      OR_{i=1..n} [ delta_i = g^{s} AND hk_i = g^{sk} AND pk_VP = h^{sk} ]
      OR  pk_V = g^{y}
  The URS witness and the holder-key witness are proved for the SAME index.
  The last branch lets the designated verifier simulate every proof.
- SDVS (Saeednia-Kremer-Markowitch (r, s, t) form, base h) over mu, where mu
  binds the session context, the candidate lists, the URS rows, and pi_pres.
- Holder-side candidate lists are cached per (credential, disclosure set) and
  reused, so repeated presentations under the same policy expose the same
  candidate list and the same URS rows.
"""
from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

from coincurve import PrivateKey, PublicKey

ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = PrivateKey((1).to_bytes(32, "big")).public_key
SYSTEM_RANDOM = secrets.SystemRandom()
METADATA_FIELDS = ("issuer_public_key", "holder_public_key", "credential_status")
STATUS_LIST_SIZE = 131072  # entries per issuer status list (bitstring list)


# ---------------------------------------------------------------- group helpers
def _random_scalar() -> int:
    return secrets.randbelow(ORDER - 1) + 1


def _to_pub(obj: Any) -> PublicKey:
    if isinstance(obj, PublicKey):
        return obj
    if isinstance(obj, PrivateKey):
        return obj.public_key
    raise TypeError("unsupported public-key type")


def _priv_int(sk: Any) -> int:
    if isinstance(sk, PrivateKey):
        return int.from_bytes(sk.secret, "big")
    raise TypeError("unsupported private-key type")


def _mul_g(k: int) -> PublicKey:
    k %= ORDER
    if k == 0:
        raise ValueError("zero scalar")
    return PrivateKey(k.to_bytes(32, "big")).public_key


def _mul(point: PublicKey, k: int) -> PublicKey:
    k %= ORDER
    if k == 0:
        raise ValueError("zero scalar")
    return point.multiply(k.to_bytes(32, "big"))


def _lin(*terms: Tuple[PublicKey, int]) -> PublicKey:
    points = [_mul(p, s) for p, s in terms if s % ORDER]
    if not points:
        raise ValueError("identity")
    return points[0] if len(points) == 1 else PublicKey.combine_keys(points)


def _pb(point: Any) -> bytes:
    return _to_pub(point).format(compressed=True)


def _pts(values: Sequence[str]) -> List[PublicKey]:
    return [PublicKey(bytes.fromhex(v)) for v in values]


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _hash_scalar(tag: bytes, *chunks: bytes) -> int:
    d = hashlib.sha256()
    d.update(len(tag).to_bytes(4, "big"))
    d.update(tag)
    for c in chunks:
        d.update(len(c).to_bytes(8, "big"))
        d.update(c)
    return int.from_bytes(d.digest(), "big") % ORDER or 1


def _message_bytes(message: Union[bytes, str, Dict[str, Any]]) -> bytes:
    if isinstance(message, bytes):
        return message
    if isinstance(message, str):
        return message.encode("utf-8")
    if isinstance(message, dict):
        return canonical_json(message)
    raise ValueError("message must be bytes, str, or dict")


# ------------------------------------------------------- issuer Schnorr signing
H0_TAG = b"DIDVC-Schnorr-v1"


def issue_credential(issuer_sk: PrivateKey, message: Any) -> Dict[str, str]:
    m = _message_bytes(message)
    x = _priv_int(issuer_sk)
    while True:
        k = _random_scalar()
        c = _hash_scalar(H0_TAG, m, _pb(_mul_g(k)))
        s = (k - x * c) % ORDER
        if s:
            return {"r": hex(c), "s": hex(s)}


def verify_credential(issuer_vk: Any, message: Any, sig: Dict[str, str]) -> bool:
    try:
        m = _message_bytes(message)
        c = int(sig["r"], 16) % ORDER
        s = int(sig["s"], 16) % ORDER
        if not c or not s:
            return False
        return c == _hash_scalar(H0_TAG, m, _pb(_lin((G, s), (_to_pub(issuer_vk), c))))
    except (KeyError, TypeError, ValueError):
        return False


# ----------------------------------------------------------------- URS rows
def urs_rows(messages: List[bytes], issuer_ring: List[PublicKey],
             authentic_index: int, issuer_signature: Dict[str, str]
             ) -> Tuple[List[int], List[PublicKey], int]:
    """Tso conversion without the ring proof.  Returns (r, delta, s_J)."""
    if not verify_credential(issuer_ring[authentic_index],
                             messages[authentic_index], issuer_signature):
        raise ValueError("issuer signature does not verify on the aligned row")
    c = int(issuer_signature["r"], 16) % ORDER
    s = int(issuer_signature["s"], 16) % ORDER
    r_vals: List[int] = []
    deltas: List[PublicKey] = []
    for i, (m, pk) in enumerate(zip(messages, issuer_ring)):
        if i == authentic_index:
            r_vals.append(c)
            deltas.append(_mul_g(s))
            continue
        while True:
            alpha = _mul_g(_random_scalar())
            r = _hash_scalar(H0_TAG, m, _pb(alpha))
            try:
                deltas.append(_lin((alpha, 1), (pk, -r)))
                r_vals.append(r)
                break
            except ValueError:
                continue
    return r_vals, deltas, s


def urs_rows_valid(messages: List[bytes], issuer_ring: List[PublicKey],
                   r_vals: List[int], deltas: List[PublicKey]) -> bool:
    try:
        for m, pk, r, d in zip(messages, issuer_ring, r_vals, deltas):
            if not r or r != _hash_scalar(H0_TAG, m, _pb(_lin((pk, r), (d, 1)))):
                return False
        return True
    except ValueError:
        return False


# ------------------------------------------------ joint designated-verifier proof
H1_TAG = b"DIDVC-Pres-v2"


def _pres_challenge(statement: bytes, commitments: List[PublicKey]) -> int:
    return _hash_scalar(H1_TAG, statement, b"".join(_pb(p) for p in commitments))


def _branch_commit(delta, hk, h, pkvp, e, zs, zk):
    return (_lin((G, zs), (delta, -e)),
            _lin((G, zk), (hk, -e)),
            _lin((h, zk), (pkvp, -e)))


def pres_prove(statement: bytes, deltas: List[PublicKey], hks: List[PublicKey],
               h: PublicKey, pkvp: PublicKey, pk_v: PublicKey,
               *, index: Optional[int] = None, s: int = 0, sk: int = 0,
               verifier_sk: Optional[int] = None) -> Dict[str, Any]:
    """Prove the joint relation.  The holder passes (index, s, sk); the
    designated verifier passes verifier_sk and simulates all candidate branches."""
    n = len(deltas)
    while True:
        try:
            e = [0] * (n + 1)
            zs = [0] * n
            zk = [0] * n
            commits: List[PublicKey] = []
            for i in range(n):
                if i == index:
                    u, v = _random_scalar(), _random_scalar()
                    commits += [_mul_g(u), _mul_g(v), _mul(h, v)]
                else:
                    e[i], zs[i], zk[i] = _random_scalar(), _random_scalar(), _random_scalar()
                    commits += list(_branch_commit(deltas[i], hks[i], h, pkvp,
                                                   e[i], zs[i], zk[i]))
            if verifier_sk is None:
                e[n], zy = _random_scalar(), _random_scalar()
                commits.append(_lin((G, zy), (pk_v, -e[n])))
            else:
                w = _random_scalar()
                commits.append(_mul_g(w))
            total = _pres_challenge(statement, commits)
            real = n if verifier_sk is not None else index
            e[real] = (total - sum(e[j] for j in range(n + 1) if j != real)) % ORDER
            if not e[real]:
                continue
            if verifier_sk is None:
                zs[index] = (u + e[index] * s) % ORDER
                zk[index] = (v + e[index] * sk) % ORDER
            else:
                zy = (w + e[n] * verifier_sk) % ORDER
            if 0 in zs or 0 in zk or not zy:
                continue
            return {"e": [hex(x) for x in e], "zs": [hex(x) for x in zs],
                    "zk": [hex(x) for x in zk], "zy": hex(zy)}
        except ValueError:
            continue


def pres_verify(statement: bytes, deltas: List[PublicKey], hks: List[PublicKey],
                h: PublicKey, pkvp: PublicKey, pk_v: PublicKey,
                proof: Dict[str, Any]) -> bool:
    try:
        n = len(deltas)
        e = [int(x, 16) % ORDER for x in proof["e"]]
        zs = [int(x, 16) % ORDER for x in proof["zs"]]
        zk = [int(x, 16) % ORDER for x in proof["zk"]]
        zy = int(proof["zy"], 16) % ORDER
        if len(e) != n + 1 or len(zs) != n or len(zk) != n or len(hks) != n:
            return False
        if 0 in e or 0 in zs or 0 in zk or not zy:
            return False
        commits: List[PublicKey] = []
        for i in range(n):
            commits += list(_branch_commit(deltas[i], hks[i], h, pkvp, e[i], zs[i], zk[i]))
        commits.append(_lin((G, zy), (pk_v, -e[n])))
        return sum(e) % ORDER == _pres_challenge(statement, commits)
    except (KeyError, TypeError, ValueError):
        return False


# ------------------------------------------------------------------- SDVS
SDVS_TAG = b"DIDVC-SDVS-v1"


def sdvs_sign(signer_sk: int, verifier_session_vk: PublicKey, message: bytes) -> Dict[str, str]:
    while True:
        k, t = _random_scalar(), _random_scalar()
        r = _hash_scalar(SDVS_TAG, message, _pb(_mul(verifier_session_vk, k)))
        s = (k * pow(t, -1, ORDER) - r * signer_sk) % ORDER
        if s:
            return {"r": hex(r), "s": hex(s), "t": hex(t)}


def sdvs_verify(sig: Dict[str, str], verifier_sk: int, signer_vk: PublicKey,
                base: PublicKey, message: bytes) -> bool:
    try:
        r, s, t = (int(sig[k], 16) % ORDER for k in ("r", "s", "t"))
        if not r or not s or not t:
            return False
        inner = _lin((base, s), (signer_vk, r))
        return r == _hash_scalar(SDVS_TAG, message, _pb(_mul(inner, t * verifier_sk)))
    except (KeyError, TypeError, ValueError):
        return False


def sdvs_simulate(verifier_sk: int, signer_vk: PublicKey, base: PublicKey,
                  message: bytes) -> Dict[str, str]:
    while True:
        s1, r1 = _random_scalar(), _random_scalar()
        try:
            r = _hash_scalar(SDVS_TAG, message, _pb(_lin((base, s1), (signer_vk, r1))))
        except ValueError:
            continue
        ell = r1 * pow(r, -1, ORDER) % ORDER
        s = s1 * pow(ell, -1, ORDER) % ORDER
        t = ell * pow(verifier_sk, -1, ORDER) % ORDER
        if s and t:
            return {"r": hex(r), "s": hex(s), "t": hex(t)}


# ------------------------------------------------------- holder-side DGen
@dataclass
class CoverSet:
    """Fixed public cover identities used for one credential.

    issuer_keys[i] and holder_keys[i] (i = 0..n-2) are public, resolvable
    whitelisted issuer keys and public holder keys taken from a public pool.
    Issuer keys may repeat; holder keys must be distinct."""
    issuer_keys: List[PublicKey]
    holder_keys: List[PublicKey]


Sampler = Callable[[str, Any], Any]


def default_sampler(field_name: str, genuine_value: Any) -> Any:
    """Type-preserving placeholder sampler.  Deployments should pass a sampler
    that draws from the public attribute distribution (see saliency study)."""
    if isinstance(genuine_value, bool):
        return bool(SYSTEM_RANDOM.getrandbits(1))
    if isinstance(genuine_value, int):
        return SYSTEM_RANDOM.randint(0, 100)
    pool = ["Alice", "Bob", "Carol", "David", "Erin", "Frank", "Grace", "Heidi",
            "Ivan", "Judy", "Taiwan", "Japan", "Korea", "France", "Brazil", "Kenya"]
    return SYSTEM_RANDOM.choice(pool)


@dataclass
class CandidateList:
    messages: List[bytes]
    issuer_ring: List[PublicKey]
    holder_ring: List[PublicKey]
    r_vals: List[int]
    deltas: List[PublicKey]
    authentic_index: int
    s_authentic: int


@dataclass
class Holder:
    sk: PrivateKey
    credential: Dict[str, Any]
    issuer_signature: Dict[str, str]
    issuer_vk: PublicKey
    cover: CoverSet
    sampler: Sampler = default_sampler
    cache: Dict[Tuple[str, ...], CandidateList] = field(default_factory=dict)
    # revoked status indices per issuer key (hex), from downloaded status lists;
    # decoy status indices are drawn outside these sets
    status_lists: Optional[Dict[str, set]] = None

    def candidate_list(self, disclosed: Sequence[str]) -> CandidateList:
        key = tuple(sorted(disclosed))
        if key not in self.cache:
            self.cache[key] = build_candidate_list(self, key)
        return self.cache[key]


def build_candidate_list(holder: Holder, disclosed: Sequence[str]) -> CandidateList:
    authentic = holder.credential
    for f in METADATA_FIELDS:
        if f not in authentic:
            raise ValueError("credential lacks metadata field " + f)
    if authentic["issuer_public_key"] != _pb(holder.issuer_vk).hex():
        raise ValueError("credential issuer key does not match issuer_vk")
    if authentic["holder_public_key"] != _pb(holder.sk).hex():
        raise ValueError("credential holder key does not match holder secret")
    attrs = {k: v for k, v in authentic.items() if k not in METADATA_FIELDS}
    if not set(disclosed) <= set(attrs):
        raise ValueError("disclosed fields must be credential attributes")
    n = len(holder.cover.holder_keys) + 1
    if len(holder.cover.issuer_keys) != n - 1:
        raise ValueError("cover set lengths differ")
    rows = [(authentic, holder.issuer_vk, _to_pub(holder.sk))]
    for ik, hk in zip(holder.cover.issuer_keys, holder.cover.holder_keys):
        decoy = {k: (v if k in disclosed else holder.sampler(k, v)) for k, v in attrs.items()}
        decoy["issuer_public_key"] = _pb(ik).hex()
        decoy["holder_public_key"] = _pb(hk).hex()
        revoked = (holder.status_lists or {}).get(decoy["issuer_public_key"], set())
        while True:
            idx = SYSTEM_RANDOM.randrange(STATUS_LIST_SIZE)
            if idx not in revoked:
                break
        decoy["credential_status"] = {"index": idx}
        rows.append((decoy, ik, hk))
    SYSTEM_RANDOM.shuffle(rows)
    j = next(i for i, row in enumerate(rows) if row[0] is authentic)
    messages = [canonical_json(row[0]) for row in rows]
    issuer_ring = [row[1] for row in rows]
    holder_ring = [row[2] for row in rows]
    if len({_pb(k) for k in holder_ring}) != n:
        raise ValueError("holder-key candidates must be distinct")
    r_vals, deltas, s = urs_rows(messages, issuer_ring, j, holder.issuer_signature)
    return CandidateList(messages, issuer_ring, holder_ring, r_vals, deltas, j, s)


# ------------------------------------------------------------- presentation
def _statement(context: Dict[str, Any], pk_v: PublicKey, cl_messages: List[bytes],
               issuer_ring: List[PublicKey], r_vals: List[int],
               deltas: List[PublicKey], h: PublicKey, pkvp: PublicKey) -> bytes:
    return canonical_json({
        "ctx": context,
        "pkV": _pb(pk_v).hex(),
        "M": [m.hex() for m in cl_messages],
        "PK": [_pb(k).hex() for k in issuer_ring],
        "r": [hex(x) for x in r_vals],
        "delta": [_pb(d).hex() for d in deltas],
        "h": _pb(h).hex(),
        "pkVP": _pb(pkvp).hex(),
    })


def _mu_bytes(statement: bytes, proof: Dict[str, Any]) -> bytes:
    return canonical_json({"statement": statement.hex(), "pi": proof})


def present(holder: Holder, verifier_vk: PublicKey, context: Dict[str, Any]) -> Dict[str, Any]:
    policy = context.get("policy")
    if not isinstance(policy, list):
        raise ValueError("context must carry the policy list")
    cl = holder.candidate_list(policy)
    sk = _priv_int(holder.sk)
    rho = _random_scalar()
    h = _mul_g(rho)
    pkvp = _mul(h, sk)
    pk_v = _to_pub(verifier_vk)
    stmt = _statement(context, pk_v, cl.messages, cl.issuer_ring, cl.r_vals, cl.deltas, h, pkvp)
    proof = pres_prove(stmt, cl.deltas, cl.holder_ring, h, pkvp, pk_v,
                       index=cl.authentic_index, s=cl.s_authentic, sk=sk)
    sdvs = sdvs_sign(sk, _mul(pk_v, rho), _mu_bytes(stmt, proof))
    return {
        "context": context,
        "M": [m.hex() for m in cl.messages],
        "PK": [_pb(k).hex() for k in cl.issuer_ring],
        "r": [hex(x) for x in cl.r_vals],
        "delta": [_pb(d).hex() for d in cl.deltas],
        "h": _pb(h).hex(),
        "pkVP": _pb(pkvp).hex(),
        "pi": proof,
        "sdvs": sdvs,
    }


def verify_presentation(t: Dict[str, Any], verifier_sk: PrivateKey,
                        issuer_whitelist: Sequence[Any], *,
                        expected_context: Dict[str, Any],
                        expected_schema: Sequence[str],
                        revoked: Optional[Dict[str, set]] = None) -> bool:
    """Returns True only if every check passes.  `revoked` maps an issuer key
    (hex) to the set of revoked status indices taken from that issuer's
    downloaded status list (None skips the status check)."""
    try:
        y = _priv_int(verifier_sk)
        pk_v = verifier_sk.public_key
        if canonical_json(t["context"]) != canonical_json(expected_context):
            return False
        policy = t["context"]["policy"]
        messages = [bytes.fromhex(m) for m in t["M"]]
        issuer_ring = _pts(t["PK"])
        r_vals = [int(x, 16) % ORDER for x in t["r"]]
        deltas = _pts(t["delta"])
        h = PublicKey(bytes.fromhex(t["h"]))
        pkvp = PublicKey(bytes.fromhex(t["pkVP"]))
        n = len(messages)
        if n < 2 or not (len(issuer_ring) == len(r_vals) == len(deltas) == n):
            return False
        wl = {_pb(_to_pub(k)) for k in issuer_whitelist}
        if any(_pb(k) not in wl for k in issuer_ring):
            return False
        parsed = [json.loads(m) for m in messages]
        schema = set(expected_schema)
        if any(set(p) != schema for p in parsed):
            return False
        if not isinstance(policy, list) or any(f not in schema or f in METADATA_FIELDS for f in policy):
            return False
        if any(p[f] != parsed[0][f] for p in parsed[1:] for f in policy):
            return False
        if any(p["issuer_public_key"] != t["PK"][i] for i, p in enumerate(parsed)):
            return False
        holder_ring = [PublicKey(bytes.fromhex(p["holder_public_key"])) for p in parsed]
        if len({_pb(k) for k in holder_ring}) != n:
            return False
        if revoked is not None:
            for p in parsed:
                idx = p["credential_status"]["index"]
                if idx in revoked.get(p["issuer_public_key"], set()):
                    return False
        if not urs_rows_valid(messages, issuer_ring, r_vals, deltas):
            return False
        stmt = _statement(t["context"], pk_v, messages, issuer_ring, r_vals, deltas, h, pkvp)
        if not pres_verify(stmt, deltas, holder_ring, h, pkvp, pk_v, t["pi"]):
            return False
        return sdvs_verify(t["sdvs"], y, pkvp, h, _mu_bytes(stmt, t["pi"]))
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return False


def verifier_simulate(verifier_sk: PrivateKey, context: Dict[str, Any],
                      messages: List[bytes], issuer_ring: List[PublicKey]) -> Dict[str, Any]:
    """The designated verifier produces, from public data and its own key, a
    transcript that passes verify_presentation (non-transferability)."""
    y = _priv_int(verifier_sk)
    pk_v = verifier_sk.public_key
    r_vals, deltas = [], []
    for m, pk in zip(messages, issuer_ring):
        while True:
            alpha = _mul_g(_random_scalar())
            r = _hash_scalar(H0_TAG, m, _pb(alpha))
            try:
                deltas.append(_lin((alpha, 1), (pk, -r)))
                r_vals.append(r)
                break
            except ValueError:
                continue
    holder_ring = [PublicKey(bytes.fromhex(json.loads(m)["holder_public_key"])) for m in messages]
    h = _mul_g(_random_scalar())
    pkvp = _mul_g(_random_scalar())
    stmt = _statement(context, pk_v, messages, issuer_ring, r_vals, deltas, h, pkvp)
    proof = pres_prove(stmt, deltas, holder_ring, h, pkvp, pk_v, verifier_sk=y)
    sdvs = sdvs_simulate(y, pkvp, h, _mu_bytes(stmt, proof))
    return {"context": context, "M": [m.hex() for m in messages],
            "PK": [_pb(k).hex() for k in issuer_ring], "r": [hex(x) for x in r_vals],
            "delta": [_pb(d).hex() for d in deltas], "h": _pb(h).hex(),
            "pkVP": _pb(pkvp).hex(), "pi": proof, "sdvs": sdvs}


# ------------------------------------------------------------- convenience
def make_credential(issuer_sk: PrivateKey, holder_vk: PublicKey,
                    attrs: Dict[str, Any], status_index: int) -> Dict[str, Any]:
    return {**attrs,
            "issuer_public_key": _pb(issuer_sk).hex(),
            "holder_public_key": _pb(holder_vk).hex(),
            "credential_status": {"index": status_index}}


def random_cover(n: int, issuer_pool: Sequence[PublicKey], holder_pool: Sequence[PublicKey]) -> CoverSet:
    if len(holder_pool) < n - 1:
        raise ValueError("holder pool too small")
    holders = SYSTEM_RANDOM.sample(list(holder_pool), n - 1)
    issuers = [SYSTEM_RANDOM.choice(list(issuer_pool)) for _ in range(n - 1)]
    return CoverSet(issuers, holders)
