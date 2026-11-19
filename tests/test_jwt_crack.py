
import base64
import hashlib
import hmac
import json
import sys
import unittest

from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import jwt_crack


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def create_test_jwt(algorithm, secret):
    """Generate a JWT using a known HMAC secret."""

    header = {
        "alg": algorithm,
        "typ": "JWT"
    }

    payload = {
        "sub": "auditor-test-user",
        "role": "tester",
        "purpose": "automated regression testing"
    }

    header_part = b64url(
        json.dumps(header, separators=(",", ":")).encode()
    )

    payload_part = b64url(
        json.dumps(payload, separators=(",", ":")).encode()
    )

    signing_input = f"{header_part}.{payload_part}"

    signature = hmac.new(
        secret.encode(),
        signing_input.encode(),
        getattr(hashlib, algorithm.lower().replace("hs", "sha"))
    ).digest()

    return f"{signing_input}.{b64url(signature)}"


class TestJWTAlgorithms(unittest.TestCase):

    def test_hs256(self):
        self.verify_algorithm("HS256")

    def test_hs384(self):
        self.verify_algorithm("HS384")

    def test_hs512(self):
        self.verify_algorithm("HS512")

    def verify_algorithm(self, algorithm):

        secret = f"test-secret-{algorithm}"

        token = create_test_jwt(algorithm, secret)

        detected, signing_input, signature, payload = (
            jwt_crack.parse_token(token)
        )

        self.assertEqual(detected, algorithm)

        result = jwt_crack.verify_candidate((
            signing_input,
            signature,
            secret,
            jwt_crack.ALGORITHMS[algorithm]
        ))

        self.assertEqual(result, secret)


class TestJWTValidation(unittest.TestCase):

    def test_wrong_secret(self):

        token = create_test_jwt("HS256", "correct-secret")

        algorithm, signing_input, signature, _ = (
            jwt_crack.parse_token(token)
        )

        result = jwt_crack.verify_candidate((
            signing_input,
            signature,
            "wrong-secret",
            jwt_crack.ALGORITHMS[algorithm]
        ))

        self.assertIsNone(result)

    def test_invalid_jwt_format(self):

        with self.assertRaises(ValueError):
            jwt_crack.parse_token("invalid.jwt")

    def test_unsupported_algorithm(self):

        header = b64url(
            json.dumps({"alg": "RS256"}).encode()
        )

        token = f"{header}.e30.AAAA"

        with self.assertRaises(ValueError):
            jwt_crack.parse_token(token)

    def test_invalid_signature_length(self):

        token = create_test_jwt("HS256", "test-secret")

        parts = token.split(".")

        invalid_token = f"{parts[0]}.{parts[1]}.{b64url(b'bad')}"

        with self.assertRaises(ValueError):
            jwt_crack.parse_token(invalid_token)

    def test_payload_decoding(self):

        token = create_test_jwt("HS256", "test-secret")

        _, _, _, payload_segment = jwt_crack.parse_token(token)

        payload = json.loads(
            jwt_crack.decode_payload(payload_segment)
        )

        self.assertEqual(payload["sub"], "auditor-test-user")
        self.assertEqual(payload["role"], "tester")


class TestCheckpointValidation(unittest.TestCase):

    def setUp(self):

        self.expected = {
            "version": jwt_crack.VERSION,
            "token_fingerprint": "test-token-fingerprint",
            "wordlist_fingerprint": "test-wordlist-fingerprint",
            "algorithm": "HS256"
        }

        self.saved = {
            **self.expected,
            "next_index": 100
        }

    def test_valid_checkpoint(self):

        result = jwt_crack.validate_checkpoint(
            self.saved,
            self.expected,
            1000
        )

        self.assertEqual(result, 100)

    def test_token_fingerprint_mismatch(self):

        saved = self.saved.copy()
        saved["token_fingerprint"] = "different-token"

        with self.assertRaises(ValueError):
            jwt_crack.validate_checkpoint(
                saved, self.expected, 1000
            )

    def test_wordlist_fingerprint_mismatch(self):

        saved = self.saved.copy()
        saved["wordlist_fingerprint"] = "different-wordlist"

        with self.assertRaises(ValueError):
            jwt_crack.validate_checkpoint(
                saved, self.expected, 1000
            )

    def test_version_mismatch(self):

        saved = self.saved.copy()
        saved["version"] = "0.1"

        with self.assertRaises(ValueError):
            jwt_crack.validate_checkpoint(
                saved, self.expected, 1000
            )

    def test_invalid_checkpoint_index(self):

        saved = self.saved.copy()
        saved["next_index"] = 2000

        with self.assertRaises(ValueError):
            jwt_crack.validate_checkpoint(
                saved, self.expected, 1000
            )

    def test_missing_checkpoint_field(self):

        saved = self.saved.copy()
        del saved["algorithm"]

        with self.assertRaises(ValueError):
            jwt_crack.validate_checkpoint(
                saved, self.expected, 1000
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)

