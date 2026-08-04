import copy
import json
import unittest

from coincurve import PrivateKey

from proposed import (
    issue_credential,
    sign_urs_dvs,
    simulate_sdvs,
    verify_urs_dvs,
)


class ProposedProtocolTests(unittest.TestCase):
    def setUp(self):
        self.holder_sk = PrivateKey()
        self.issuer_sk = PrivateKey()
        self.verifier_sk = PrivateKey()
        self.attributes = {
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
        self.authentic = {
            **self.attributes,
            "issuer_public_key": self.issuer_sk.public_key.format(
                compressed=True
            ).hex(),
            "holder_public_key": self.holder_sk.public_key.format(
                compressed=True
            ).hex(),
            "credential_status": {
                "entry": "issuer-status-17",
                "state": "ok",
                "source": "issuer",
            },
        }
        issuer_signature = issue_credential(self.issuer_sk, self.authentic)
        self.issuer_ring = [
            self.issuer_sk.public_key,
            *[PrivateKey().public_key for _ in range(7)],
        ]
        self.context = {
            "session_id": "test-session",
            "policy": ["age", "name"],
        }
        self.schema = list(self.authentic)
        self.bundle = sign_urs_dvs(
            self.holder_sk,
            self.issuer_ring[1:],
            self.authentic,
            issuer_signature,
            self.verifier_sk.public_key,
            issuer_vk=self.issuer_sk.public_key,
            reveal_keys=["name", "age"],
            ring_size=8,
            context=self.context,
        )

    def verify(self, bundle=None, verifier_sk=None, whitelist=None, schema=None):
        return verify_urs_dvs(
            bundle or self.bundle,
            verifier_sk or self.verifier_sk,
            whitelist or self.issuer_ring,
            expected_context=self.context,
            expected_schema=schema or self.schema,
        )

    def test_valid_transcript(self):
        self.assertEqual(self.verify(), (True, True))

    def test_wrong_designated_verifier_rejected(self):
        self.assertEqual(
            self.verify(verifier_sk=PrivateKey()),
            (False, False),
        )

    def test_message_tampering_rejected(self):
        tampered = copy.deepcopy(self.bundle)
        message = json.loads(bytes.fromhex(tampered["vp"]["mu"]["M"][0]))
        message["age"] = 99
        tampered["vp"]["mu"]["M"][0] = json.dumps(
            message, sort_keys=True, separators=(",", ":")
        ).encode().hex()
        self.assertFalse(self.verify(tampered)[0])

    def test_candidate_reordering_rejected(self):
        tampered = copy.deepcopy(self.bundle)
        tampered["vp"]["mu"]["M"][0], tampered["vp"]["mu"]["M"][1] = (
            tampered["vp"]["mu"]["M"][1],
            tampered["vp"]["mu"]["M"][0],
        )
        self.assertFalse(self.verify(tampered)[0])

    def test_context_substitution_rejected(self):
        tampered = copy.deepcopy(self.bundle)
        tampered["context"]["session_id"] = "other-session"
        self.assertFalse(self.verify(tampered)[0])

    def test_non_whitelisted_issuer_rejected(self):
        incomplete_whitelist = self.issuer_ring[:-1]
        self.assertFalse(self.verify(whitelist=incomplete_whitelist)[0])

    def test_disclosed_field_mismatch_rejected(self):
        tampered = copy.deepcopy(self.bundle)
        message = json.loads(bytes.fromhex(tampered["vp"]["mu"]["M"][0]))
        message["name"] = "Mallory"
        tampered["vp"]["mu"]["M"][0] = json.dumps(
            message, sort_keys=True, separators=(",", ":")
        ).encode().hex()
        self.assertFalse(self.verify(tampered)[0])

    def test_verifier_simulation_is_accepted(self):
        simulated = copy.deepcopy(self.bundle)
        simulated["vp"]["sdvs"] = simulate_sdvs(
            simulated, self.verifier_sk
        )
        self.assertEqual(self.verify(simulated), (True, True))

    def test_issuer_status_is_preserved(self):
        messages = [
            json.loads(bytes.fromhex(value))
            for value in self.bundle["vp"]["mu"]["M"]
        ]
        genuine = next(
            message
            for message in messages
            if message["issuer_public_key"]
            == self.authentic["issuer_public_key"]
        )
        self.assertEqual(
            genuine["credential_status"],
            self.authentic["credential_status"],
        )

    def test_unexpected_schema_rejected(self):
        self.assertFalse(self.verify(schema=self.schema[:-1])[0])

    def test_transcript_has_no_redundant_verifier_keys(self):
        self.assertNotIn("verifier_pub", self.bundle)
        self.assertNotIn("verifier_session_pub", self.bundle)


if __name__ == "__main__":
    unittest.main()
