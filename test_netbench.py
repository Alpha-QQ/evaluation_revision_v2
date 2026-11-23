import json
import random
import time
import unittest

from coincurve import PrivateKey

import netbench
import protocol_adapter as proto


class NetbenchTests(unittest.TestCase):
    def test_status_list(self):
        lst, free = netbench.status_list("did:web:x", random.Random(1), 0.01)
        self.assertTrue(netbench.check_status(lst, free))
        enc = json.loads(lst)["credentialSubject"]["encodedList"]
        self.assertTrue(enc.startswith("u"))

    def test_revoked_entry_detected(self):
        lst, _ = netbench.status_list("did:web:x", random.Random(2), 0.5)
        flags = [netbench.check_status(lst, i) for i in range(2000)]
        self.assertIn(False, flags)
        self.assertIn(True, flags)

    def test_did_document_resolves_to_key(self):
        pub = PrivateKey().public_key
        did = netbench.did_web(8080, 3)
        doc = netbench.did_document(did, proto.pub_xy(pub))
        self.assertTrue(netbench.resolve_ok(doc, did, proto.pub_xy(pub)))
        other = PrivateKey().public_key
        self.assertFalse(netbench.resolve_ok(doc, did, proto.pub_xy(other)))

    def test_link_pacing(self):
        link = netbench.Link(10, 0)            # 10 Mbit/s
        t = time.perf_counter()
        for _ in range(8):
            link.pace("up", 16384)             # 128 KiB in total
        elapsed = time.perf_counter() - t
        self.assertAlmostEqual(elapsed, 131072 * 8 / 10e6, delta=0.03)

    def test_present_and_verify(self):
        setup = proto.make_setup(10, 1)
        ctx = proto.new_context(5)
        body = proto.present(setup, setup["credential_record"], ctx, 10)
        self.assertTrue(proto.verify(setup, body, ctx, 10))
        other = proto.new_context(5)
        self.assertFalse(proto.verify(setup, body, other, 10))


if __name__ == "__main__":
    unittest.main()
