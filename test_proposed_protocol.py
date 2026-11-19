import copy
import json
import unittest

from coincurve import PrivateKey

import proposed as P

ATTRS = {"name": "Alice", "age": 25, "nationality": "Taiwan", "level": 4,
         "member": False, "verified": True}


def _setup(n=8):
    issuer = PrivateKey()
    verifier = PrivateKey()
    issuer_pool = [issuer.public_key] + [PrivateKey().public_key for _ in range(5)]
    holder_pool = [PrivateKey().public_key for _ in range(3 * n)]
    holder_sk = PrivateKey()
    cred = P.make_credential(issuer, holder_sk.public_key, ATTRS, 17)
    sig = P.issue_credential(issuer, cred)
    holder = P.Holder(holder_sk, cred, sig, issuer.public_key,
                      P.random_cover(n, issuer_pool, holder_pool))
    return issuer, verifier, issuer_pool, holder_pool, holder, cred


class RevisedProtocolTests(unittest.TestCase):
    def setUp(self):
        (self.issuer, self.verifier, self.wl, self.pool,
         self.holder, self.cred) = _setup()
        self.ctx = {"session_id": "s-1", "policy": ["age", "nationality"]}
        self.schema = list(self.cred)
        self.t = P.present(self.holder, self.verifier.public_key, self.ctx)

    def verify(self, t=None, verifier=None, wl=None, ctx=None, revoked=None):
        return P.verify_presentation(
            t or self.t, verifier or self.verifier, wl or self.wl,
            expected_context=ctx or self.ctx, expected_schema=self.schema,
            revoked=revoked)

    def test_valid(self):
        self.assertTrue(self.verify())

    def test_wrong_verifier(self):
        self.assertFalse(self.verify(verifier=PrivateKey()))

    def test_message_tampering(self):
        t = copy.deepcopy(self.t)
        m = json.loads(bytes.fromhex(t["M"][0]))
        m["level"] = 99
        t["M"][0] = P.canonical_json(m).hex()
        self.assertFalse(self.verify(t))

    def test_reordering(self):
        t = copy.deepcopy(self.t)
        for k in ("M", "PK", "r", "delta"):
            t[k][0], t[k][1] = t[k][1], t[k][0]
        self.assertFalse(self.verify(t))

    def test_context_substitution(self):
        t = copy.deepcopy(self.t)
        t["context"] = {"session_id": "s-2", "policy": self.ctx["policy"]}
        self.assertFalse(self.verify(t, ctx=t["context"]))

    def test_non_whitelisted(self):
        used = set(self.t["PK"])
        wl = [k for k in self.wl if k.format(compressed=True).hex() != sorted(used)[0]]
        self.assertFalse(self.verify(wl=wl))

    def test_disclosed_mismatch(self):
        t = copy.deepcopy(self.t)
        m = json.loads(bytes.fromhex(t["M"][0]))
        m["age"] = 30
        t["M"][0] = P.canonical_json(m).hex()
        self.assertFalse(self.verify(t))

    def test_revoked_authentic(self):
        revoked = {self.cred["issuer_public_key"]: {17}}
        self.assertFalse(self.verify(revoked=revoked))

    def test_unrevoked_passes_status_check(self):
        self.assertTrue(self.verify(revoked={}))

    def test_decoy_status_avoids_revoked_entries(self):
        # half of every cover issuer's list is revoked; the holder must avoid it
        revoked = {P._pb(k).hex(): set(range(0, P.STATUS_LIST_SIZE, 2)) for k in self.wl}
        for key in revoked:
            revoked[key].discard(17)
        self.holder.status_lists = revoked
        self.holder.cache.clear()
        t = P.present(self.holder, self.verifier.public_key, self.ctx)
        self.assertTrue(self.verify(t=t, revoked=revoked))

    def test_rows_have_uniform_shape(self):
        rows = [json.loads(bytes.fromhex(m)) for m in self.t["M"]]
        self.assertEqual({tuple(sorted(r["credential_status"])) for r in rows}, {("index",)})
        self.assertFalse(any("decoy" in json.dumps(r) for r in rows))

    def test_same_policy_reuses_rows(self):
        t2 = P.present(self.holder, self.verifier.public_key,
                       {"session_id": "s-9", "policy": ["nationality", "age"]})
        for k in ("M", "PK", "r", "delta"):
            self.assertEqual(self.t[k], t2[k])
        self.assertNotEqual(self.t["pkVP"], t2["pkVP"])

    def test_verifier_can_simulate(self):
        msgs = [bytes.fromhex(m) for m in self.t["M"]]
        sim = P.verifier_simulate(self.verifier, self.ctx, msgs, P._pts(self.t["PK"]))
        self.assertTrue(self.verify(sim))

    def test_lent_credential_rejected(self):
        bob = PrivateKey()
        alice = PrivateKey()
        cb = P.make_credential(self.issuer, bob.public_key, ATTRS, 5)
        sb = P.issue_credential(self.issuer, cb)
        cover = P.random_cover(8, self.wl, self.pool)
        cover.holder_keys[0] = alice.public_key
        lent = P.Holder(alice, cb, sb, self.issuer.public_key, cover)
        with self.assertRaises(ValueError):
            P.present(lent, self.verifier.public_key, self.ctx)
        # Manual forgery attempts: prove with Bob's row (Alice's sk) or Alice's row (Bob's s).
        bob_holder = P.Holder(bob, cb, sb, self.issuer.public_key, cover)
        cl = bob_holder.candidate_list(self.ctx["policy"])
        a_idx = [P._pb(k) for k in cl.holder_ring].index(P._pb(alice.public_key))
        for idx in (cl.authentic_index, a_idx):
            sk = P._priv_int(alice)
            rho = P._random_scalar()
            h = P._mul_g(rho)
            pkvp = P._mul(h, sk)
            stmt = P._statement(self.ctx, self.verifier.public_key, cl.messages,
                                cl.issuer_ring, cl.r_vals, cl.deltas, h, pkvp)
            proof = P.pres_prove(stmt, cl.deltas, cl.holder_ring, h, pkvp,
                                 self.verifier.public_key, index=idx,
                                 s=cl.s_authentic, sk=sk)
            sd = P.sdvs_sign(sk, P._mul(self.verifier.public_key, rho), P._mu_bytes(stmt, proof))
            t = {"context": self.ctx, "M": [m.hex() for m in cl.messages],
                 "PK": [P._pb(k).hex() for k in cl.issuer_ring],
                 "r": [hex(x) for x in cl.r_vals], "delta": [P._pb(d).hex() for d in cl.deltas],
                 "h": P._pb(h).hex(), "pkVP": P._pb(pkvp).hex(), "pi": proof, "sdvs": sd}
            self.assertFalse(self.verify(t))


if __name__ == "__main__":
    unittest.main()
