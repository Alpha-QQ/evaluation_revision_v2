#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import secrets
from typing import Any, Dict, List, Optional, Tuple, Union

from coincurve import PrivateKey, PublicKey

try:
    from ecdsa import SigningKey, VerifyingKey
    from ecdsa.ellipticcurve import Point
except ImportError:
    SigningKey = VerifyingKey = Point = object


ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = PrivateKey((1).to_bytes(32, "big")).public_key
RING_SIZE = 100
SYSTEM_RANDOM = secrets.SystemRandom()
METADATA_FIELDS = {
    "issuer_public_key",
    "holder_public_key",
    "credential_status",
}


def _to_pub(obj: Any) -> PublicKey:
    if isinstance(obj, PublicKey):
        return obj
    if isinstance(obj, PrivateKey):
        return obj.public_key
    if isinstance(obj, VerifyingKey):
        point = obj.pubkey.point
        return PublicKey.from_point(point.x(), point.y())
    if isinstance(obj, SigningKey):
        point = obj.verifying_key.pubkey.point
        return PublicKey.from_point(point.x(), point.y())
    if isinstance(obj, Point):
        return PublicKey.from_point(obj.x(), obj.y())
    raise TypeError("unsupported public-key type")


def _priv_int(sk: Any) -> int:
    if isinstance(sk, PrivateKey):
        return int.from_bytes(sk.secret, "big")
    if isinstance(sk, SigningKey):
        return sk.privkey.secret_multiplier
    raise TypeError("unsupported private-key type")


def _random_scalar() -> int:
    return secrets.randbelow(ORDER - 1) + 1


def _scalar_mul_g(k: int) -> PublicKey:
    k %= ORDER
    if k == 0:
        raise ValueError("zero scalar has no encodable public point")
    return PrivateKey(k.to_bytes(32, "big")).public_key


def _scalar_mul(point: Any, k: int) -> PublicKey:
    k %= ORDER
    if k == 0:
        raise ValueError("zero scalar produces the identity")
    return _to_pub(point).multiply(k.to_bytes(32, "big"))


def _linear_combination(*terms: Tuple[Any, int]) -> PublicKey:
    points = [
        _scalar_mul(point, scalar)
        for point, scalar in terms
        if scalar % ORDER != 0
    ]
    if not points:
        raise ValueError("identity result")
    if len(points) == 1:
        return points[0]
    return PublicKey.combine_keys(points)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _hash_scalar(tag: bytes, *chunks: bytes) -> int:
    digest = hashlib.sha256()
    digest.update(len(tag).to_bytes(4, "big"))
    digest.update(tag)
    for chunk in chunks:
        digest.update(len(chunk).to_bytes(8, "big"))
        digest.update(chunk)
    return int.from_bytes(digest.digest(), "big") % ORDER or 1


def _point_bytes(point: Any) -> bytes:
    return _to_pub(point).format(compressed=True)


def _decode_points(values: List[str]) -> List[PublicKey]:
    return [PublicKey(bytes.fromhex(value)) for value in values]


def issue_credential(issuer_sk: Any, message: Union[bytes, str, Dict[str, Any]]) -> Dict[str, str]:
    message_bytes = _message_bytes(message)
    x = _priv_int(issuer_sk)
    while True:
        k = _random_scalar()
        commitment = _scalar_mul_g(k)
        challenge = _hash_scalar(
            b"DIDVC-Schnorr-v1", message_bytes, _point_bytes(commitment)
        )
        response = (k - x * challenge) % ORDER
        if response:
            return {"r": hex(challenge), "s": hex(response)}


def verify_credential(
    issuer_vk: Any,
    message: Union[bytes, str, Dict[str, Any]],
    signature: Dict[str, str],
) -> bool:
    try:
        message_bytes = _message_bytes(message)
        challenge = int(signature["r"], 16) % ORDER
        response = int(signature["s"], 16) % ORDER
        if not challenge or not response:
            return False
        commitment = _linear_combination(
            (G, response), (_to_pub(issuer_vk), challenge)
        )
        return challenge == _hash_scalar(
            b"DIDVC-Schnorr-v1", message_bytes, _point_bytes(commitment)
        )
    except (KeyError, TypeError, ValueError):
        return False


def _urs_wh_prove(
    witness: int,
    authentic_index: int,
    deltas: List[PublicKey],
) -> Dict[str, Any]:
    n = len(deltas)
    delta_list = _canonical_json(
        [_point_bytes(delta).hex() for delta in deltas]
    )
    while True:
        challenges = [0] * n
        omega = [0] * n
        beta = _random_scalar()
        next_index = (authentic_index + 1) % n
        challenges[next_index] = _hash_scalar(
            b"DIDVC-URS-WH-v1",
            next_index.to_bytes(8, "big"),
            delta_list,
            _point_bytes(_scalar_mul_g(beta)),
        )
        index = next_index
        try:
            while index != authentic_index:
                omega[index] = _random_scalar()
                commitment = _linear_combination(
                    (G, omega[index]), (deltas[index], challenges[index])
                )
                following = (index + 1) % n
                challenges[following] = _hash_scalar(
                    b"DIDVC-URS-WH-v1",
                    following.to_bytes(8, "big"),
                    delta_list,
                    _point_bytes(commitment),
                )
                index = following
            omega[authentic_index] = (
                beta - witness * challenges[authentic_index]
            ) % ORDER
            if challenges[0] and all(value != 0 for value in omega):
                return {
                    "c1": hex(challenges[0]),
                    "omega": [hex(value) for value in omega],
                }
        except ValueError:
            continue


def _urs_wh_verify(
    deltas: List[PublicKey],
    proof: Dict[str, Any],
) -> bool:
    try:
        initial = int(proof["c1"], 16) % ORDER
        omega = [int(value, 16) % ORDER for value in proof["omega"]]
        n = len(deltas)
        if not initial or len(omega) != n or any(value == 0 for value in omega):
            return False
        delta_list = _canonical_json(
            [_point_bytes(delta).hex() for delta in deltas]
        )
        challenge = initial
        for index in range(n):
            commitment = _linear_combination(
                (G, omega[index]), (deltas[index], challenge)
            )
            following = (index + 1) % n
            challenge = _hash_scalar(
                b"DIDVC-URS-WH-v1",
                following.to_bytes(8, "big"),
                delta_list,
                _point_bytes(commitment),
            )
        return challenge == initial
    except (KeyError, TypeError, ValueError):
        return False


def _urs_convert(
    authentic_message: bytes,
    issuer_signature: Dict[str, str],
    messages: List[bytes],
    issuer_ring: List[PublicKey],
    authentic_index: int,
) -> Dict[str, Any]:
    if messages[authentic_index] != authentic_message:
        raise ValueError("authentic message is not aligned with its issuer key")
    if not verify_credential(
        issuer_ring[authentic_index], authentic_message, issuer_signature
    ):
        raise ValueError("issuer signature is invalid")

    genuine_r = int(issuer_signature["r"], 16) % ORDER
    genuine_s = int(issuer_signature["s"], 16) % ORDER
    r_values: List[int] = []
    deltas: List[PublicKey] = []
    for index, (message, issuer_key) in enumerate(zip(messages, issuer_ring)):
        if index == authentic_index:
            r_values.append(genuine_r)
            deltas.append(_scalar_mul_g(genuine_s))
            continue
        while True:
            alpha = _scalar_mul_g(_random_scalar())
            challenge = _hash_scalar(
                b"DIDVC-Schnorr-v1", message, _point_bytes(alpha)
            )
            try:
                delta = _linear_combination(
                    (alpha, 1), (issuer_key, -challenge)
                )
                r_values.append(challenge)
                deltas.append(delta)
                break
            except ValueError:
                continue

    wh_proof = _urs_wh_prove(
        genuine_s,
        authentic_index,
        deltas,
    )
    return {
        "PK": [_point_bytes(key).hex() for key in issuer_ring],
        "M": [message.hex() for message in messages],
        "r": [hex(value) for value in r_values],
        "delta": [_point_bytes(delta).hex() for delta in deltas],
        "WH": wh_proof,
    }


def _urs_verify(urs: Dict[str, Any]) -> bool:
    try:
        issuer_ring = _decode_points(urs["PK"])
        messages = [bytes.fromhex(value) for value in urs["M"]]
        r_values = [int(value, 16) % ORDER for value in urs["r"]]
        deltas = _decode_points(urs["delta"])
        n = len(issuer_ring)
        if not (len(messages) == len(r_values) == len(deltas) == n and n >= 2):
            return False
        if len(set(urs["PK"])) != n or any(value == 0 for value in r_values):
            return False
        for message, issuer_key, challenge, delta in zip(
            messages, issuer_ring, r_values, deltas
        ):
            commitment = _linear_combination(
                (issuer_key, challenge), (delta, 1)
            )
            expected = _hash_scalar(
                b"DIDVC-Schnorr-v1", message, _point_bytes(commitment)
            )
            if challenge != expected:
                return False
        return _urs_wh_verify(deltas, urs["WH"])
    except (KeyError, TypeError, ValueError):
        return False


def _sdvs_sign(
    signer_sk: Any,
    verifier_session_vk: PublicKey,
    base: PublicKey,
    message: bytes,
) -> Dict[str, str]:
    x_a = _priv_int(signer_sk)
    while True:
        k = _random_scalar()
        t = _random_scalar()
        commitment = _scalar_mul(verifier_session_vk, k)
        r = _hash_scalar(b"DIDVC-SDVS-v1", message, _point_bytes(commitment))
        s = (k * pow(t, -1, ORDER) - r * x_a) % ORDER
        if s:
            return {"r": hex(r), "s": hex(s), "t": hex(t)}


def _sdvs_verify(
    signature: Dict[str, str],
    verifier_sk: Any,
    signer_vk: PublicKey,
    base: PublicKey,
    message: bytes,
) -> bool:
    try:
        x_b = _priv_int(verifier_sk)
        r = int(signature["r"], 16) % ORDER
        s = int(signature["s"], 16) % ORDER
        t = int(signature["t"], 16) % ORDER
        if not r or not s or not t:
            return False
        inner = _linear_combination((base, s), (signer_vk, r))
        commitment = _scalar_mul(inner, t * x_b)
        return r == _hash_scalar(
            b"DIDVC-SDVS-v1", message, _point_bytes(commitment)
        )
    except (KeyError, TypeError, ValueError):
        return False


def _sdvs_simulate(
    verifier_sk: Any,
    signer_vk: PublicKey,
    base: PublicKey,
    message: bytes,
) -> Dict[str, str]:
    x_b = _priv_int(verifier_sk)
    while True:
        s_prime = _random_scalar()
        r_prime = _random_scalar()
        commitment = _linear_combination(
            (base, s_prime), (signer_vk, r_prime)
        )
        r = _hash_scalar(b"DIDVC-SDVS-v1", message, _point_bytes(commitment))
        ell = r_prime * pow(r, -1, ORDER) % ORDER
        s = s_prime * pow(ell, -1, ORDER) % ORDER
        t = ell * pow(x_b, -1, ORDER) % ORDER
        if s and t:
            return {"r": hex(r), "s": hex(s), "t": hex(t)}


def _link_challenge(
    context: bytes,
    verifier_vk: PublicKey,
    messages: List[bytes],
    issuer_ring: List[PublicKey],
    base: PublicKey,
    session_vk: PublicKey,
    commitments_1: List[PublicKey],
    commitments_2: List[PublicKey],
) -> int:
    return _hash_scalar(
        b"DIDVC-Link-v1",
        context,
        _point_bytes(verifier_vk),
        _canonical_json([message.hex() for message in messages]),
        _canonical_json([_point_bytes(key).hex() for key in issuer_ring]),
        _point_bytes(base),
        _point_bytes(session_vk),
        b"".join(
            _point_bytes(first) + _point_bytes(second)
            for first, second in zip(commitments_1, commitments_2)
        ),
    )


def _link_prove(
    holder_sk: Any,
    holder_ring: List[PublicKey],
    base: PublicKey,
    context: bytes,
    verifier_vk: PublicKey,
    messages: List[bytes],
    issuer_ring: List[PublicKey],
) -> Dict[str, Any]:
    x = _priv_int(holder_sk)
    holder_vk = _to_pub(holder_sk)
    encodings = [_point_bytes(key) for key in holder_ring]
    authentic_index = encodings.index(_point_bytes(holder_vk))
    session_vk = _scalar_mul(base, x)
    n = len(holder_ring)

    while True:
        challenges = [0] * n
        responses = [0] * n
        first: List[Optional[PublicKey]] = [None] * n
        second: List[Optional[PublicKey]] = [None] * n
        nonce = _random_scalar()
        first[authentic_index] = _scalar_mul_g(nonce)
        second[authentic_index] = _scalar_mul(base, nonce)
        for index in range(n):
            if index == authentic_index:
                continue
            challenges[index] = _random_scalar()
            responses[index] = _random_scalar()
            first[index] = _linear_combination(
                (G, responses[index]),
                (holder_ring[index], -challenges[index]),
            )
            second[index] = _linear_combination(
                (base, responses[index]),
                (session_vk, -challenges[index]),
            )
        first_points = [point for point in first if point is not None]
        second_points = [point for point in second if point is not None]
        overall = _link_challenge(
            context,
            verifier_vk,
            messages,
            issuer_ring,
            base,
            session_vk,
            first_points,
            second_points,
        )
        real_challenge = (
            overall
            - sum(challenges[index] for index in range(n) if index != authentic_index)
        ) % ORDER
        real_response = (nonce + real_challenge * x) % ORDER
        if real_challenge and real_response:
            challenges[authentic_index] = real_challenge
            responses[authentic_index] = real_response
            return {
                "c": [hex(value) for value in challenges],
                "z": [hex(value) for value in responses],
            }


def _link_verify(
    proof: Dict[str, Any],
    holder_ring: List[PublicKey],
    base: PublicKey,
    session_vk: PublicKey,
    context: bytes,
    verifier_vk: PublicKey,
    messages: List[bytes],
    issuer_ring: List[PublicKey],
) -> bool:
    try:
        challenges = [int(value, 16) % ORDER for value in proof["c"]]
        responses = [int(value, 16) % ORDER for value in proof["z"]]
        n = len(holder_ring)
        if not (len(challenges) == len(responses) == n):
            return False
        if any(value == 0 for value in challenges + responses):
            return False
        first = [
            _linear_combination(
                (G, responses[index]),
                (holder_ring[index], -challenges[index]),
            )
            for index in range(n)
        ]
        second = [
            _linear_combination(
                (base, responses[index]),
                (session_vk, -challenges[index]),
            )
            for index in range(n)
        ]
        overall = _link_challenge(
            context,
            verifier_vk,
            messages,
            issuer_ring,
            base,
            session_vk,
            first,
            second,
        )
        return sum(challenges) % ORDER == overall
    except (KeyError, TypeError, ValueError):
        return False


def _message_bytes(message: Union[bytes, str, Dict[str, Any]]) -> bytes:
    if isinstance(message, bytes):
        return message
    if isinstance(message, str):
        return message.encode("utf-8")
    if isinstance(message, dict):
        return _canonical_json(message)
    raise ValueError("message must be bytes, str, or dict")


def _credential(message: Union[bytes, str, Dict[str, Any]]) -> Dict[str, Any]:
    value = json.loads(_message_bytes(message))
    if not isinstance(value, dict):
        raise ValueError("message must encode a JSON object")
    return value


def _decoy_value(value: Any, candidate_index: int, field: str) -> Any:
    if isinstance(value, bool):
        return bool(SYSTEM_RANDOM.getrandbits(1))
    if isinstance(value, int):
        return SYSTEM_RANDOM.randint(0, 100)
    return f"decoy-{candidate_index}-{field}"


def _holder_ring_from_messages(messages: List[bytes]) -> List[PublicKey]:
    keys = []
    for message in messages:
        value = json.loads(message)
        keys.append(PublicKey(bytes.fromhex(value["holder_public_key"])))
    if len(set(_point_bytes(key) for key in keys)) != len(keys):
        raise ValueError("holder-key candidates must be distinct")
    return keys


def sign_urs_dvs(
    holder_sk: Any,
    issuer_ring_keys: List[Any],
    message: Union[bytes, str, Dict[str, Any]],
    issuer_signature: Dict[str, str],
    verifier_vk: Any,
    *,
    issuer_vk: Any,
    reveal_keys: Optional[List[str]] = None,
    ring_size: int = RING_SIZE,
    context: Dict[str, Any],
) -> Dict[str, Any]:
    if ring_size < 2:
        raise ValueError("ring_size must be at least 2")

    authentic_issuer = _to_pub(issuer_vk)
    issuer_ring = [authentic_issuer]
    seen_issuers = {_point_bytes(authentic_issuer)}
    for key in issuer_ring_keys:
        public_key = _to_pub(key)
        encoded = _point_bytes(public_key)
        if encoded not in seen_issuers:
            issuer_ring.append(public_key)
            seen_issuers.add(encoded)
        if len(issuer_ring) == ring_size:
            break
    while len(issuer_ring) < ring_size:
        public_key = PrivateKey().public_key
        encoded = _point_bytes(public_key)
        if encoded not in seen_issuers:
            issuer_ring.append(public_key)
            seen_issuers.add(encoded)

    authentic = _credential(message)
    if not METADATA_FIELDS.issubset(authentic):
        raise ValueError(
            "the issuer-signed credential must contain issuer, holder, and status metadata"
        )
    holder_vk = _to_pub(holder_sk)
    if authentic["issuer_public_key"] != _point_bytes(authentic_issuer).hex():
        raise ValueError("credential issuer key does not match issuer_vk")
    if authentic["holder_public_key"] != _point_bytes(holder_vk).hex():
        raise ValueError("credential holder key does not match holder_sk")
    if not isinstance(authentic["credential_status"], dict):
        raise ValueError("credential_status must be an object")
    attrs = {
        field: value
        for field, value in authentic.items()
        if field not in METADATA_FIELDS
    }
    disclosed = set(reveal_keys or [])
    if not disclosed.issubset(attrs):
        raise ValueError("reveal_keys must be fields in the genuine credential")
    candidates = [authentic]
    for candidate_index in range(1, ring_size):
        decoy_holder = PrivateKey().public_key
        candidates.append(
            {
                **{
                    field: value
                    if field in disclosed
                    else _decoy_value(value, candidate_index, field)
                    for field, value in attrs.items()
                },
                "issuer_public_key": _point_bytes(
                    issuer_ring[candidate_index]
                ).hex(),
                "holder_public_key": _point_bytes(decoy_holder).hex(),
                "credential_status": {
                    "entry": f"decoy-{candidate_index}",
                    "state": "ok",
                    "source": "holder-mask",
                },
            }
        )

    permutation = list(range(ring_size))
    SYSTEM_RANDOM.shuffle(permutation)
    issuer_ring = [issuer_ring[index] for index in permutation]
    candidates = [candidates[index] for index in permutation]
    authentic_index = permutation.index(0)
    messages = [_canonical_json(candidate) for candidate in candidates]
    authentic_message = messages[authentic_index]

    if _canonical_json(authentic) != authentic_message:
        raise ValueError("authentic credential encoding changed during DGen")
    if not verify_credential(authentic_issuer, authentic_message, issuer_signature):
        raise ValueError(
            "issuer_signature must authenticate the complete genuine credential"
        )

    urs = _urs_convert(
        authentic_message,
        issuer_signature,
        messages,
        issuer_ring,
        authentic_index,
    )
    context_bytes = _canonical_json(context)

    base_scalar = _random_scalar()
    base = _scalar_mul_g(base_scalar)
    session_vk = _scalar_mul(base, _priv_int(holder_sk))
    verifier_public = _to_pub(verifier_vk)
    verifier_session_vk = _scalar_mul(verifier_public, base_scalar)
    holder_ring = _holder_ring_from_messages(messages)

    link_proof = _link_prove(
        holder_sk,
        holder_ring,
        base,
        context_bytes,
        verifier_public,
        messages,
        issuer_ring,
    )
    mu = urs
    mu_bytes = _canonical_json(mu)
    sdvs = _sdvs_sign(
        holder_sk, verifier_session_vk, base, mu_bytes
    )

    return {
        "context": context,
        "vp": {
            "mu": mu,
            "sdvs": sdvs,
            "pkVP": _point_bytes(session_vk).hex(),
        },
        "h": _point_bytes(base).hex(),
        "pkVP": _point_bytes(session_vk).hex(),
        "link_proof": link_proof,
    }


def verify_urs_dvs(
    bundle: Dict[str, Any],
    verifier_sk: Any,
    issuer_whitelist: List[Any],
    *,
    expected_context: Dict[str, Any],
    expected_schema: List[str],
) -> Tuple[bool, bool]:
    try:
        verifier_vk = _to_pub(verifier_sk)
        base = PublicKey(bytes.fromhex(bundle["h"]))
        session_vk = PublicKey(bytes.fromhex(bundle["pkVP"]))
        if bundle["vp"]["pkVP"] != bundle["pkVP"]:
            return False, False

        mu = bundle["vp"]["mu"]
        if not _urs_verify(mu):
            return False, False
        messages = [bytes.fromhex(value) for value in mu["M"]]
        issuer_ring = _decode_points(mu["PK"])
        holder_ring = _holder_ring_from_messages(messages)
        context_bytes = _canonical_json(bundle["context"])
        if _canonical_json(expected_context) != context_bytes:
            return False, False

        whitelist = {_point_bytes(_to_pub(key)) for key in issuer_whitelist}
        if not whitelist or any(
            _point_bytes(key) not in whitelist for key in issuer_ring
        ):
            return False, False

        parsed_messages = [json.loads(message) for message in messages]
        if any(
            parsed["issuer_public_key"] != mu["PK"][index]
            for index, parsed in enumerate(parsed_messages)
        ):
            return False, False
        schema = set(parsed_messages[0])
        if schema != set(expected_schema) or any(
            set(parsed) != schema for parsed in parsed_messages[1:]
        ):
            return False, False
        policy = bundle["context"].get("policy")
        if not isinstance(policy, list) or any(
            field not in schema for field in policy
        ):
            return False, False
        if any(
            parsed[field] != parsed_messages[0][field]
            for parsed in parsed_messages[1:]
            for field in policy
        ):
            return False, False

        status_ok = all(
            parsed["credential_status"]["state"] == "ok"
            for parsed in parsed_messages
        )
        if not status_ok:
            return False, False

        sdvs_ok = _sdvs_verify(
            bundle["vp"]["sdvs"],
            verifier_sk,
            session_vk,
            base,
            _canonical_json(mu),
        )
        link_ok = _link_verify(
            bundle["link_proof"],
            holder_ring,
            base,
            session_vk,
            context_bytes,
            verifier_vk,
            messages,
            issuer_ring,
        )
        return sdvs_ok and link_ok, link_ok
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return False, False


def simulate_sdvs(
    bundle: Dict[str, Any], verifier_sk: Any
) -> Dict[str, str]:
    base = PublicKey(bytes.fromhex(bundle["h"]))
    session_vk = PublicKey(bytes.fromhex(bundle["pkVP"]))
    return _sdvs_simulate(
        verifier_sk,
        session_vk,
        base,
        _canonical_json(bundle["vp"]["mu"]),
    )


if __name__ == "__main__":
    holder_sk = PrivateKey()
    issuer_sk = PrivateKey()
    verifier_sk = PrivateKey()
    attrs = {
        "name": "Alice",
        "age": 25,
        "score": 88,
        "nationality": "Taiwan",
        "level": 4,
        "experience": 6,
        "gender": 0,
        "login_days": 62,
        "purchase_count": 13,
        "review_score": 74,
        "contribution": 32,
        "training_hours": 7,
        "active": True,
        "member": False,
        "passed_kyc": False,
        "admin": True,
        "certified": True,
        "has_photo": True,
        "verified": True,
        "student": False,
    }
    genuine = {
        **attrs,
        "issuer_public_key": _point_bytes(issuer_sk).hex(),
        "holder_public_key": _point_bytes(holder_sk).hex(),
        "credential_status": {
            "entry": "authentic",
            "state": "ok",
            "source": "issuer",
        },
    }
    issuer_signature = issue_credential(issuer_sk, genuine)
    bundle = sign_urs_dvs(
        holder_sk,
        [],
        genuine,
        issuer_signature,
        verifier_sk.public_key,
        issuer_vk=issuer_sk.public_key,
        reveal_keys=["name"],
        ring_size=10,
        context={"session_id": "demo-session", "policy": ["name"]},
    )
    issuer_whitelist = [
        PublicKey(bytes.fromhex(value)) for value in bundle["vp"]["mu"]["PK"]
    ]
    assert verify_urs_dvs(
        bundle,
        verifier_sk,
        issuer_whitelist,
        expected_context={"session_id": "demo-session", "policy": ["name"]},
        expected_schema=list(genuine),
    )[0]
    simulated = simulate_sdvs(bundle, verifier_sk)
    assert _sdvs_verify(
        simulated,
        verifier_sk,
        PublicKey(bytes.fromhex(bundle["pkVP"])),
        PublicKey(bytes.fromhex(bundle["h"])),
        _canonical_json(bundle["vp"]["mu"]),
    )
    assert not verify_urs_dvs(
        bundle,
        PrivateKey(),
        issuer_whitelist,
        expected_context={"session_id": "demo-session", "policy": ["name"]},
        expected_schema=list(genuine),
    )[0]
    print("protocol self-test passed")
