"""BBS signatures and proofs, ciphersuite BLS12-381-SHA-256.

Follows the IRTF CFRG draft "The BBS Signature Scheme"
(https://github.com/decentralized-identity/bbs-signature, interface
H2G_HM2S_).  Group arithmetic and pairings use py_arkworks_bls12381.
Correctness is checked against the draft's fixture files
(see test_bbs.py and fixtures/bbs).
"""
from __future__ import annotations

import hashlib
import secrets
from typing import List, Sequence, Tuple

from py_arkworks_bls12381 import G1Point, G2Point, GT, Scalar

R = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
CIPHERSUITE_ID = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_"
API_ID = CIPHERSUITE_ID + b"H2G_HM2S_"
EXPAND_LEN = 48
P1 = G1Point.from_compressed_bytes(bytes.fromhex(
    "a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9"))
BP2 = G2Point()
_cache: List[G1Point] = []


# ------------------------------------------------------------------ helpers
def _sc(x: int) -> Scalar:
    return Scalar(x % R)


def _i2osp(x: int, n: int) -> bytes:
    return x.to_bytes(n, "big")


def expand_message_xmd(msg: bytes, dst: bytes, length: int) -> bytes:
    """RFC 9380, Section 5.3.1, with SHA-256."""
    b_in, r_in = 32, 64
    ell = -(-length // b_in)
    if ell > 255 or len(dst) > 255:
        raise ValueError("expand_message_xmd: bad lengths")
    dst_prime = dst + _i2osp(len(dst), 1)
    b0 = hashlib.sha256(bytes(r_in) + msg + _i2osp(length, 2) + b"\x00" + dst_prime).digest()
    b = [hashlib.sha256(b0 + b"\x01" + dst_prime).digest()]
    for i in range(2, ell + 1):
        prev = bytes(x ^ y for x, y in zip(b0, b[-1]))
        b.append(hashlib.sha256(prev + _i2osp(i, 1) + dst_prime).digest())
    return b"".join(b)[:length]


def hash_to_scalar(msg: bytes, dst: bytes) -> int:
    return int.from_bytes(expand_message_xmd(msg, dst, EXPAND_LEN), "big") % R


def create_generators(count: int, api_id: bytes = API_ID) -> List[G1Point]:
    if api_id == API_ID and len(_cache) >= count:
        return _cache[:count]
    seed_dst = api_id + b"SIG_GENERATOR_SEED_"
    gen_dst = api_id + b"SIG_GENERATOR_DST_"
    v = expand_message_xmd(api_id + b"MESSAGE_GENERATOR_SEED", seed_dst, EXPAND_LEN)
    out = []
    for i in range(1, count + 1):
        v = expand_message_xmd(v + _i2osp(i, 8), seed_dst, EXPAND_LEN)
        out.append(G1Point.hash_to_curve(v, gen_dst))
    if api_id == API_ID:
        _cache[:] = out
    return out


def messages_to_scalars(messages: Sequence[bytes], api_id: bytes = API_ID) -> List[int]:
    dst = api_id + b"MAP_MSG_TO_SCALAR_AS_HASH_"
    return [hash_to_scalar(m, dst) for m in messages]


def _ser(items) -> bytes:
    out = b""
    for el in items:
        if isinstance(el, G1Point):
            out += el.to_compressed_bytes()
        elif isinstance(el, G2Point):
            out += el.to_compressed_bytes()
        elif isinstance(el, tuple) and el[0] == "s":
            out += _i2osp(el[1] % R, 32)
        elif isinstance(el, int):
            out += _i2osp(el, 8)
        else:
            raise TypeError("cannot serialize")
    return out


def _s(x: int):
    return ("s", x)


def _msm(points: Sequence[G1Point], scalars: Sequence[int]) -> G1Point:
    return G1Point.multiexp_unchecked(list(points), [_sc(s) for s in scalars])


def _domain(pk: bytes, gens: Sequence[G1Point], header: bytes, api_id: bytes) -> int:
    dom_octs = _ser([len(gens) - 1] + list(gens)) + api_id
    dom_input = pk + dom_octs + _i2osp(len(header), 8) + header
    return hash_to_scalar(dom_input, api_id + b"H2S_")


def _pairing_check(pairs) -> bool:
    """True iff prod e(P_i, Q_i) == 1."""
    g1 = [p for p, _ in pairs]
    g2 = [q for _, q in pairs]
    return GT.multi_pairing(g1, g2) == GT.one()


# -------------------------------------------------------------- key handling
def keygen() -> Tuple[int, bytes]:
    sk = secrets.randbelow(R - 1) + 1
    return sk, sk_to_pk(sk)


def sk_to_pk(sk: int) -> bytes:
    return (BP2 * _sc(sk)).to_compressed_bytes()


# ------------------------------------------------------------------- sign
def sign(sk: int, pk: bytes, header: bytes, messages: Sequence[bytes]) -> bytes:
    msgs = messages_to_scalars(messages)
    gens = create_generators(len(msgs) + 1)
    domain = _domain(pk, gens, header, API_ID)
    e = hash_to_scalar(_ser([_s(sk)] + [_s(m) for m in msgs] + [_s(domain)]), API_ID + b"H2S_")
    b = _msm([P1] + gens, [1, domain] + msgs)
    a = b * _sc(pow((sk + e) % R, -1, R))
    return _ser([a, _s(e)])


def _octets_to_sig(sig: bytes):
    if len(sig) != 80:
        raise ValueError("bad signature length")
    a = G1Point.from_compressed_bytes(sig[:48])
    e = int.from_bytes(sig[48:], "big")
    if a == G1Point.identity() or not 0 < e < R:
        raise ValueError("bad signature")
    return a, e


def verify(pk: bytes, sig: bytes, header: bytes, messages: Sequence[bytes]) -> bool:
    try:
        a, e = _octets_to_sig(sig)
        w = G2Point.from_compressed_bytes(pk)
    except Exception:
        return False
    msgs = messages_to_scalars(messages)
    gens = create_generators(len(msgs) + 1)
    domain = _domain(pk, gens, header, API_ID)
    b = _msm([P1] + gens, [1, domain] + msgs)
    return _pairing_check([(a, w), (a * _sc(e) + b * _sc(R - 1), BP2)])


# ------------------------------------------------------------------ proofs
def _challenge(abar, bbar, d, t1, t2, domain, disclosed: Sequence[Tuple[int, int]], ph: bytes) -> int:
    arr = [len(disclosed)]
    for i, m in disclosed:
        arr += [i, _s(m)]
    arr += [abar, bbar, d, t1, t2, _s(domain)]
    octs = _ser(arr) + _i2osp(len(ph), 8) + ph
    return hash_to_scalar(octs, API_ID + b"H2S_")


def proof_gen(pk: bytes, sig: bytes, header: bytes, ph: bytes, messages: Sequence[bytes],
              disclosed_indexes: Sequence[int], random_scalars: Sequence[int] = None) -> bytes:
    a, e = _octets_to_sig(sig)
    msgs = messages_to_scalars(messages)
    gens = create_generators(len(msgs) + 1)
    L = len(msgs)
    disc = sorted(disclosed_indexes)
    undisc = [j for j in range(L) if j not in set(disc)]
    U = len(undisc)
    if random_scalars is None:
        random_scalars = [secrets.randbelow(R - 1) + 1 for _ in range(5 + U)]
    r1, r2, et, r1t, r3t = random_scalars[:5]
    mt = random_scalars[5:]
    domain = _domain(pk, gens, header, API_ID)
    b = _msm([P1] + gens, [1, domain] + msgs)
    d = b * _sc(r2)
    abar = a * _sc(r1 * r2)
    bbar = _msm([d, abar], [r1, R - e])
    t1 = _msm([abar, d], [et, r1t])
    t2 = _msm([d] + [gens[j + 1] for j in undisc], [r3t] + list(mt))
    c = _challenge(abar, bbar, d, t1, t2, domain, [(i, msgs[i]) for i in disc], ph)
    r3 = pow(r2, -1, R)
    eh = (et + e * c) % R
    r1h = (r1t - r1 * c) % R
    r3h = (r3t - r3 * c) % R
    mh = [(mt[k] + msgs[j] * c) % R for k, j in enumerate(undisc)]
    return _ser([abar, bbar, d, _s(eh), _s(r1h), _s(r3h)] + [_s(x) for x in mh] + [_s(c)])


def proof_verify(pk: bytes, proof: bytes, header: bytes, ph: bytes,
                 disclosed_messages: Sequence[bytes], disclosed_indexes: Sequence[int]) -> bool:
    try:
        if len(proof) < 3 * 48 + 4 * 32 or (len(proof) - 144) % 32:
            return False
        pts = [G1Point.from_compressed_bytes(proof[48 * i:48 * i + 48]) for i in range(3)]
        if any(p == G1Point.identity() for p in pts):
            return False
        scal = [int.from_bytes(proof[144 + 32 * k:176 + 32 * k], "big")
                for k in range((len(proof) - 144) // 32)]
        if any(not 0 < s < R for s in scal):
            return False
        w = G2Point.from_compressed_bytes(pk)
    except Exception:
        return False
    abar, bbar, d = pts
    eh, r1h, r3h = scal[:3]
    commits, c = scal[3:-1], scal[-1]
    U, Rn = len(commits), len(disclosed_indexes)
    L = U + Rn
    disc = list(disclosed_indexes)
    if disc != sorted(disc) or any(not 0 <= i < L for i in disc):
        return False
    undisc = [j for j in range(L) if j not in set(disc)]
    msgs = messages_to_scalars(disclosed_messages)
    gens = create_generators(L + 1)
    domain = _domain(pk, gens, header, API_ID)
    t1 = _msm([bbar, abar, d], [c, eh, r1h])
    bv = _msm([P1, gens[0]] + [gens[i + 1] for i in disc], [1, domain] + msgs)
    t2 = _msm([bv, d] + [gens[j + 1] for j in undisc], [c, r3h] + commits)
    if c != _challenge(abar, bbar, d, t1, t2, domain, list(zip(disc, msgs)), ph):
        return False
    return _pairing_check([(abar, w), (bbar * _sc(R - 1), BP2)])
