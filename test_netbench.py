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


    def test_status_entries_checked_from_transcript(self):
        setup = proto.make_setup(6, 2)
        world = netbench.World(6, setup, 2, 0.5)
        try:
            lists = {i: world.routes[netbench.status_path(i)]() for i in range(6)}
            rng = random.Random(3)
            ctx = proto.new_context(5)
            body = proto.present(setup, setup["credential_record"], ctx, 6,
                                 decoy_status_index=lambda k: netbench.pick_unrevoked(
                                     lists[world.by_key[k]], rng))
            check = lambda k, idx: netbench.check_status(lists[world.by_key[k]], idx)
            self.assertTrue(proto.verify(setup, body, ctx, 6, status_check=check))
            # with uniform indexes, half of the list revoked, some decoy fails
            results = [proto.verify(setup, proto.present(setup, setup["credential_record"], ctx, 6),
                                    ctx, 6, status_check=check) for _ in range(5)]
            self.assertIn(False, results)
        finally:
            world.vdr.shutdown()
            world.vdr.server_close()


    def test_fetch_time_follows_link_model(self):
        # 32 small objects over 8 connections at RTT 20 ms: two handshake RTTs
        # plus four request RTTs per connection, about 120 ms in total
        routes = {"/o%d" % i: (lambda: b"x" * 500) for i in range(32)}
        srv = netbench._start(netbench._Server(("127.0.0.1", 0), netbench._handler(routes)))
        try:
            link = netbench.Link(100, 20)
            t = time.perf_counter()
            out = netbench._fetch_all(list(routes), srv.server_address[1], link, 2, 8)
            elapsed = time.perf_counter() - t
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual(len(out), 32)
        self.assertGreater(elapsed, 0.115)
        self.assertLess(elapsed, 0.260)


if __name__ == "__main__":
    unittest.main()
