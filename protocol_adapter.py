"""Connects the network evaluation (netbench.py) to the protocol in proposed.py.

The credential, attribute set and serialization are those of
benchmark_candidate_sizes.py, so the transcript sent over the network is the
artifact measured in the performance benchmark.
"""
from __future__ import annotations

import json
import secrets

from coincurve import PrivateKey, PublicKey

from benchmark_candidate_sizes import USER, serialize_artifact
from proposed import issue_credential, sign_urs_dvs, verify_urs_dvs

ATTRIBUTES = list(USER)


def pub_xy(pub: PublicKey) -> tuple[bytes, bytes]:
    raw = pub.format(compressed=False)
    return raw[1:33], raw[33:65]


def make_setup(n_max: int, seed: int) -> dict:
    """Keys and the holder's credential for candidate sets of up to n_max."""
    holder = PrivateKey()
    issuer = PrivateKey()
    verifier = PrivateKey()
    ring = [PrivateKey().public_key for _ in range(n_max - 1)]
    credential = {
        **USER,
        "issuer_public_key": issuer.public_key.format(compressed=True).hex(),
        "holder_public_key": holder.public_key.format(compressed=True).hex(),
        "credential_status": {"entry": "authentic", "state": "ok", "source": "issuer"},
    }
    signature = issue_credential(issuer, credential)
    return {
        "issuer_pubs": [issuer.public_key] + ring,     # index 0 = authentic issuer
        "issuer": issuer.public_key,
        "ring": ring,
        "verifier_sk": verifier,
        "verifier_pk": verifier.public_key,
        "schema": list(credential),
        # what the holder keeps in its wallet
        "credential_record": {"credential": credential, "signature": signature,
                              "holder_sk": holder.secret.hex()},
    }


def new_context(disclosed: int) -> dict:
    return {"session_id": secrets.token_hex(16), "policy": sorted(ATTRIBUTES[:disclosed])}


def present(setup: dict, record: dict, ctx: dict, n: int) -> bytes:
    bundle = sign_urs_dvs(
        PrivateKey(bytes.fromhex(record["holder_sk"])),
        setup["ring"][:n - 1],
        record["credential"],
        record["signature"],
        setup["verifier_pk"],
        issuer_vk=setup["issuer"],
        reveal_keys=list(ctx["policy"]),
        ring_size=n,
        context=ctx,
    )
    return serialize_artifact(bundle)


def verify(setup: dict, body: bytes, ctx: dict, n: int) -> bool:
    ok, _ = verify_urs_dvs(json.loads(body), setup["verifier_sk"], setup["issuer_pubs"][:n],
                           expected_context=ctx, expected_schema=setup["schema"])
    return bool(ok)
