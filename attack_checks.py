"""Regression checks for the attacks found on the previous prototype.

A1  label leakage: no row carries a field that marks it as genuine or decoy.
A2  repeated presentations, same policy: the candidate lists are identical,
    so intersecting them leaves all n candidates.
A3  repeated presentations, different policies: count of URS r-values shared
    by the two transcripts (documented limitation; 1 means the authentic row
    is exposed when lists for different policies are compared).
A4  lent credential: a holder who has another holder's signed credential but
    not that holder's secret key is rejected.
A5  designated verifier can produce an accepted transcript on its own.
"""
from __future__ import annotations

import json
from typing import Dict

from coincurve import PrivateKey

import proposed as P

ATTRS = {"name": "Bob", "age": 26, "gender": "male", "nationality": "Taiwan"}


def run(n: int = 10) -> Dict[str, object]:
    issuer, verifier = PrivateKey(), PrivateKey()
    wl = [issuer.public_key] + [PrivateKey().public_key for _ in range(5)]
    pool = [PrivateKey().public_key for _ in range(3 * n)]
    hsk = PrivateKey()
    cred = P.make_credential(issuer, hsk.public_key, ATTRS, 42)
    sig = P.issue_credential(issuer, cred)
    holder = P.Holder(hsk, cred, sig, issuer.public_key, P.random_cover(n, wl, pool))
    schema = list(cred)

    c1 = {"session_id": "a", "policy": ["age"]}
    c2 = {"session_id": "b", "policy": ["age"]}
    c3 = {"session_id": "c", "policy": ["gender"]}
    t1 = P.present(holder, verifier.public_key, c1)
    t2 = P.present(holder, verifier.public_key, c2)
    t3 = P.present(holder, verifier.public_key, c3)
    ok = all(P.verify_presentation(t, verifier, wl, expected_context=c, expected_schema=schema)
             for t, c in ((t1, c1), (t2, c2), (t3, c3)))

    rows = [json.loads(bytes.fromhex(m)) for m in t1["M"]]
    shapes = {json.dumps(sorted(r["credential_status"])) for r in rows}
    hk = lambda t: {json.loads(bytes.fromhex(m))["holder_public_key"] for m in t["M"]}

    # A4: Alice holds Bob's signed credential, puts her key in a cover row.
    bob, alice = PrivateKey(), PrivateKey()
    cb = P.make_credential(issuer, bob.public_key, ATTRS, 7)
    sb = P.issue_credential(issuer, cb)
    cover = P.random_cover(n, wl, pool)
    cover.holder_keys[0] = alice.public_key
    cl = P.Holder(bob, cb, sb, issuer.public_key, cover).candidate_list(["age"])
    a_idx = [P._pb(k) for k in cl.holder_ring].index(P._pb(alice.public_key))
    lent_accepted = False
    for idx in (cl.authentic_index, a_idx):
        sk = P._priv_int(alice)
        rho = P._random_scalar()
        h = P._mul_g(rho)
        pkvp = P._mul(h, sk)
        stmt = P._statement(c1, verifier.public_key, cl.messages, cl.issuer_ring,
                            cl.r_vals, cl.deltas, h, pkvp)
        pi = P.pres_prove(stmt, cl.deltas, cl.holder_ring, h, pkvp, verifier.public_key,
                          index=idx, s=cl.s_authentic, sk=sk)
        sd = P.sdvs_sign(sk, P._mul(verifier.public_key, rho), P._mu_bytes(stmt, pi))
        forged = {"context": c1, "M": [m.hex() for m in cl.messages],
                  "PK": [P._pb(k).hex() for k in cl.issuer_ring],
                  "r": [hex(x) for x in cl.r_vals], "delta": [P._pb(d).hex() for d in cl.deltas],
                  "h": P._pb(h).hex(), "pkVP": P._pb(pkvp).hex(), "pi": pi, "sdvs": sd}
        lent_accepted |= P.verify_presentation(forged, verifier, wl, expected_context=c1,
                                               expected_schema=schema)

    sim = P.verifier_simulate(verifier, c1, [bytes.fromhex(m) for m in t1["M"]], P._pts(t1["PK"]))
    return {
        "n": n,
        "honest_transcripts_accepted": ok,
        "A1_status_field_shapes": len(shapes),
        "A1_rows_containing_decoy_label": sum("decoy" in json.dumps(r) for r in rows),
        "A2_same_policy_common_holder_keys": len(hk(t1) & hk(t2)),
        "A2_same_policy_rows_identical": t1["M"] == t2["M"] and t1["r"] == t2["r"],
        "A3_cross_policy_common_r_values": len(set(t1["r"]) & set(t3["r"])),
        "A4_lent_credential_accepted": lent_accepted,
        "A5_verifier_simulation_accepted": P.verify_presentation(
            sim, verifier, wl, expected_context=c1, expected_schema=schema),
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
