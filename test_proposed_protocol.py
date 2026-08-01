import copy
import json
import unittest

from coincurve import PrivateKey

from proposed import (
    ORDER,
    _binding_prove,
    _canonical_json,
    _decode_points,
    _holder_ring_from_messages,
    _point_bytes,
    _to_pub,
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
            "valid_until": "2030-01-01T00:00:00Z",
        }
        self.issuer_signature = issue_credential(self.issuer_sk, self.authentic)
        self.issuer_ring = [
            self.issuer_sk.public_key,
            *[PrivateKey().public_key for _ in range(7)],
        ]
        self.context = {
            "session_id": "test-session",
            "schema_id": "urn:example:credential:v1",
            "policy": ["age", "name"],
            "validity_epoch": self.authentic["valid_until"],
        }
        self.schema = list(self.authentic)
        self.bundle = sign_urs_dvs(
            self.holder_sk,
            self.issuer_ring[1:],
            self.authentic,
            self.issuer_signature,
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
        message = json.loads(
            bytes.fromhex(tampered["vp"]["mu"]["urs"]["M"][0])
        )
        message["age"] = 99
        tampered["vp"]["mu"]["urs"]["M"][0] = json.dumps(
            message, sort_keys=True, separators=(",", ":")
        ).encode().hex()
        self.assertFalse(self.verify(tampered)[0])

    def test_candidate_reordering_rejected(self):
        tampered = copy.deepcopy(self.bundle)
        urs = tampered["vp"]["mu"]["urs"]
        urs["M"][0], urs["M"][1] = (
            urs["M"][1],
            urs["M"][0],
        )
        self.assertFalse(self.verify(tampered)[0])

    def test_context_substitution_rejected(self):
        tampered = copy.deepcopy(self.bundle)
        tampered["vp"]["mu"]["context"]["session_id"] = "other-session"
        self.assertFalse(self.verify(tampered)[0])

    def test_non_whitelisted_issuer_rejected(self):
        incomplete_whitelist = self.issuer_ring[:-1]
        self.assertFalse(self.verify(whitelist=incomplete_whitelist)[0])

    def test_insufficient_authorized_issuer_set_rejected(self):
        with self.assertRaisesRegex(ValueError, "smaller than ring_size"):
            sign_urs_dvs(
                self.holder_sk,
                self.issuer_ring[1:3],
                self.authentic,
                self.issuer_signature,
                self.verifier_sk.public_key,
                issuer_vk=self.issuer_sk.public_key,
                reveal_keys=["name", "age"],
                ring_size=8,
                context=self.context,
            )

    def test_disclosed_field_mismatch_rejected(self):
        tampered = copy.deepcopy(self.bundle)
        message = json.loads(
            bytes.fromhex(tampered["vp"]["mu"]["urs"]["M"][0])
        )
        message["name"] = "Mallory"
        tampered["vp"]["mu"]["urs"]["M"][0] = json.dumps(
            message, sort_keys=True, separators=(",", ":")
        ).encode().hex()
        self.assertFalse(self.verify(tampered)[0])

    def test_verifier_simulation_is_accepted(self):
        simulated = copy.deepcopy(self.bundle)
        simulated["vp"]["sdvs"] = simulate_sdvs(
            simulated, self.verifier_sk
        )
        self.assertEqual(self.verify(simulated), (True, True))

    def test_issuer_signed_validity_epoch_is_preserved(self):
        messages = [
            json.loads(bytes.fromhex(value))
            for value in self.bundle["vp"]["mu"]["urs"]["M"]
        ]
        genuine = next(
            message
            for message in messages
            if message["issuer_public_key"]
            == self.authentic["issuer_public_key"]
        )
        self.assertEqual(
            genuine["valid_until"],
            self.authentic["valid_until"],
        )

    def test_validity_epoch_substitution_rejected(self):
        tampered = copy.deepcopy(self.bundle)
        tampered["vp"]["mu"]["context"]["validity_epoch"] = (
            "2031-01-01T00:00:00Z"
        )
        self.assertEqual(self.verify(tampered), (False, False))

    def test_unexpected_schema_rejected(self):
        self.assertFalse(self.verify(schema=self.schema[:-1])[0])

    def test_transcript_has_no_redundant_verifier_keys(self):
        self.assertNotIn("verifier_pub", self.bundle)
        self.assertNotIn("verifier_session_pub", self.bundle)

    def test_stolen_credential_cannot_be_bound_to_attacker_key(self):
        attacker_sk = PrivateKey()
        signature = issue_credential(self.issuer_sk, self.authentic)
        with self.assertRaisesRegex(ValueError, "holder key"):
            sign_urs_dvs(
                attacker_sk,
                self.issuer_ring[1:],
                self.authentic,
                signature,
                self.verifier_sk.public_key,
                issuer_vk=self.issuer_sk.public_key,
                reveal_keys=["name", "age"],
                ring_size=8,
                context=self.context,
            )

    def test_binding_proof_tampering_rejected(self):
        tampered = copy.deepcopy(self.bundle)
        proof = tampered["vp"]["mu"]["binding_proof"]
        proof["z_holder"][0] = hex(int(proof["z_holder"][0], 16) + 1)
        self.assertEqual(self.verify(tampered), (False, False))

    def test_conversion_challenge_tampering_rejected(self):
        tampered = copy.deepcopy(self.bundle)
        urs = tampered["vp"]["mu"]["urs"]
        urs["r"][0] = hex((int(urs["r"][0], 16) + 1) % ORDER)
        self.assertEqual(self.verify(tampered), (False, False))

    def test_joint_relation_rejects_both_cross_index_choices(self):
        attacker_sk = PrivateKey()
        mu = self.bundle["vp"]["mu"]
        urs = mu["urs"]
        messages = [bytes.fromhex(value) for value in urs["M"]]
        issuer_ring = _decode_points(urs["PK"])
        deltas = _decode_points(urs["delta"])
        challenges = [int(value, 16) % ORDER for value in urs["r"]]
        holder_ring = _holder_ring_from_messages(messages)
        genuine_issuer = _point_bytes(self.issuer_sk.public_key)
        genuine_index = [
            _point_bytes(key) for key in issuer_ring
        ].index(genuine_issuer)
        attacker_index = (genuine_index + 1) % len(holder_ring)
        holder_ring[attacker_index] = _to_pub(attacker_sk)
        common = (
            deltas,
            holder_ring,
            _decode_points([mu["h"]])[0],
            _canonical_json(mu["context"]),
            self.verifier_sk.public_key,
            messages,
            issuer_ring,
        )
        with self.assertRaisesRegex(ValueError, "same index"):
            _binding_prove(
                int(self.issuer_signature["s"], 16),
                attacker_sk,
                genuine_index,
                challenges,
                *common,
            )
        with self.assertRaisesRegex(ValueError, "issuer response"):
            _binding_prove(
                int(self.issuer_signature["s"], 16),
                attacker_sk,
                attacker_index,
                challenges,
                *common,
            )


if __name__ == "__main__":
    unittest.main()
