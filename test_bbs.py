"""Check bbs.py against the IRTF CFRG draft fixtures (BLS12-381-SHA-256)."""
import json
import os
import unittest

import bbs

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "bbs")


def _load(name):
    with open(os.path.join(FIX, name)) as f:
        return json.load(f)


def _files(prefix):
    return sorted(f for f in os.listdir(FIX) if f.startswith(prefix))


class TestBBS(unittest.TestCase):
    def test_generators(self):
        g = _load("generators.json")
        gens = bbs.create_generators(len(g["MsgGenerators"]) + 1)
        self.assertEqual(bbs.P1.to_compressed_bytes().hex(), g["P1"])
        self.assertEqual(gens[0].to_compressed_bytes().hex(), g["Q1"])
        for pt, h in zip(gens[1:], g["MsgGenerators"]):
            self.assertEqual(pt.to_compressed_bytes().hex(), h)

    def test_keypair(self):
        k = _load("keypair.json")
        self.assertEqual(bbs.sk_to_pk(int(k["keyPair"]["secretKey"], 16)).hex(), k["keyPair"]["publicKey"])

    def test_signatures(self):
        for name in _files("signature"):
            f = _load(name)
            pk = bytes.fromhex(f["signerKeyPair"]["publicKey"])
            sig = bytes.fromhex(f["signature"])
            hdr = bytes.fromhex(f["header"])
            msgs = [bytes.fromhex(m) for m in f["messages"]]
            with self.subTest(name):
                self.assertEqual(bbs.verify(pk, sig, hdr, msgs), f["result"]["valid"])
                if f["result"]["valid"]:
                    sk = int(f["signerKeyPair"]["secretKey"], 16)
                    self.assertEqual(bbs.sign(sk, pk, hdr, msgs).hex(), f["signature"])

    def test_proofs(self):
        for name in _files("proof"):
            f = _load(name)
            pk = bytes.fromhex(f["signerPublicKey"])
            hdr = bytes.fromhex(f["header"])
            ph = bytes.fromhex(f["presentationHeader"])
            msgs = [bytes.fromhex(m) for m in f["messages"]]
            idx = f["disclosedIndexes"]
            disc = [msgs[i] for i in idx]
            proof = bytes.fromhex(f["proof"])
            with self.subTest(name):
                self.assertEqual(bbs.proof_verify(pk, proof, hdr, ph, disc, idx), f["result"]["valid"])
                tr = f.get("trace", {}).get("random_scalars")
                if f["result"]["valid"] and tr:
                    rs = [int(tr[k], 16) for k in ("r1", "r2", "e_tilde", "r1_tilde", "r3_tilde")]
                    rs += [int(x, 16) for x in tr["m_tilde_scalars"]]
                    sig = bytes.fromhex(f["signature"])
                    self.assertEqual(bbs.proof_gen(pk, sig, hdr, ph, msgs, idx, rs).hex(), f["proof"])


if __name__ == "__main__":
    unittest.main()
