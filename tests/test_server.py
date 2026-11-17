import os
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from fido2.cose import ES256
from fido2.server import Fido2Server
from fido2.utils import websafe_encode
from fido2.webauthn import (
    Aaguid,
    AttestedCredentialData,
    AuthenticationResponse,
    AuthenticatorAssertionResponse,
    AuthenticatorData,
    CollectedClientData,
    PublicKeyCredentialRpEntity,
    UserVerificationRequirement,
)

from .test_ctap2 import _ATT_CRED_DATA, _CRED_ID


class TestPublicKeyCredentialRpEntity(unittest.TestCase):
    def test_id_hash(self):
        rp = PublicKeyCredentialRpEntity(name="Example", id="example.com")
        rp_id_hash = (
            b"\xa3y\xa6\xf6\xee\xaf\xb9\xa5^7\x8c\x11\x804\xe2u\x1eh/"
            b"\xab\x9f-0\xab\x13\xd2\x12U\x86\xce\x19G"
        )
        self.assertEqual(rp.id_hash, rp_id_hash)


USER = {"id": b"user_id", "name": "A. User"}


class TestFido2Server(unittest.TestCase):
    def test_register_begin_rp(self):
        rp = PublicKeyCredentialRpEntity(name="Example", id="example.com")
        server = Fido2Server(rp)

        request, state = server.register_begin(USER)

        self.assertEqual(
            request["publicKey"]["rp"], {"id": "example.com", "name": "Example"}
        )

    def test_register_begin_custom_challenge(self):
        rp = PublicKeyCredentialRpEntity(name="Example", id="example.com")
        server = Fido2Server(rp)

        challenge = b"1234567890123456"
        request, state = server.register_begin(USER, challenge=challenge)

        self.assertEqual(request["publicKey"]["challenge"], websafe_encode(challenge))

    def test_register_begin_custom_challenge_too_short(self):
        rp = PublicKeyCredentialRpEntity(name="Example", id="example.com")
        server = Fido2Server(rp)

        challenge = b"123456789012345"
        with self.assertRaises(ValueError):
            request, state = server.register_begin(USER, challenge=challenge)

    def test_authenticate_complete_invalid_signature(self):
        rp = PublicKeyCredentialRpEntity(name="Example", id="example.com")
        server = Fido2Server(rp)

        state = {
            "challenge": "GAZPACHO!",
            "user_verification": UserVerificationRequirement.PREFERRED,
        }
        client_data = CollectedClientData.create(
            CollectedClientData.TYPE.GET,
            "GAZPACHO!",
            "https://example.com",
        )
        _AUTH_DATA = bytes.fromhex(
            "A379A6F6EEAFB9A55E378C118034E2751E682FAB9F2D30AB13D2125586CE1947010000001D"
        )
        response = AuthenticationResponse(
            raw_id=_CRED_ID,
            response=AuthenticatorAssertionResponse(
                client_data=client_data,
                authenticator_data=AuthenticatorData(_AUTH_DATA),
                signature=b"INVALID",
            ),
        )

        with self.assertRaisesRegex(ValueError, "Invalid signature."):
            server.authenticate_complete(
                state,
                [AttestedCredentialData(_ATT_CRED_DATA)],
                response,
            )


class TestAuthenticateCompleteResult(unittest.TestCase):
    """The assertion context (counter, backup flags, user handle) must be
    readable by the caller of authenticate_complete."""

    def setUp(self):
        rp = PublicKeyCredentialRpEntity(name="Example", id="example.com")
        self.server = Fido2Server(rp)
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential = AttestedCredentialData.create(
            Aaguid.NONE,
            os.urandom(32),
            ES256.from_cryptography_key(self.key.public_key()),
        )

    def _authenticate(self, *, counter, flags, user_handle=None):
        options, state = self.server.authenticate_begin([self.credential])
        client_data = CollectedClientData.create(
            CollectedClientData.TYPE.GET,
            options["publicKey"]["challenge"],
            "https://example.com",
        )
        auth_data = AuthenticatorData.create(self.server.rp.id_hash, flags, counter)
        signature = self.key.sign(
            auth_data + client_data.hash, ec.ECDSA(hashes.SHA256())
        )
        response = AuthenticationResponse(
            raw_id=self.credential.credential_id,
            response=AuthenticatorAssertionResponse(
                client_data=client_data,
                authenticator_data=auth_data,
                signature=signature,
                user_handle=user_handle,
            ),
        )
        return self.server.authenticate_complete(state, [self.credential], response)

    def test_result_exposes_assertion_context(self):
        flags = (
            AuthenticatorData.FLAG.UP
            | AuthenticatorData.FLAG.UV
            | AuthenticatorData.FLAG.BE
            | AuthenticatorData.FLAG.BS
        )
        result = self._authenticate(counter=41, flags=flags, user_handle=b"user_id")

        self.assertEqual(result.credential, self.credential)
        self.assertEqual(result.auth_data.counter, 41)
        self.assertTrue(result.auth_data.is_backup_eligible())
        self.assertTrue(result.auth_data.is_backed_up())
        self.assertEqual(result.user_handle, b"user_id")

    def test_counter_regression_is_trackable(self):
        flags = AuthenticatorData.FLAG.UP
        first = self._authenticate(counter=10, flags=flags)
        second = self._authenticate(counter=7, flags=flags)

        # The caller can persist first.auth_data.counter and detect the
        # regression on the next assertion.
        self.assertLess(second.auth_data.counter, first.auth_data.counter)

    def test_backup_flag_flip_is_trackable(self):
        flags = (
            AuthenticatorData.FLAG.UP
            | AuthenticatorData.FLAG.BE
            | AuthenticatorData.FLAG.BS
        )
        first = self._authenticate(counter=1, flags=flags)
        second = self._authenticate(
            counter=2, flags=AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.BE
        )

        self.assertTrue(first.auth_data.is_backed_up())
        self.assertFalse(second.auth_data.is_backed_up())

    def test_foreign_user_handle_is_visible(self):
        expected_user_handle = b"user-a"
        result = self._authenticate(
            counter=1,
            flags=AuthenticatorData.FLAG.UP,
            user_handle=b"user-b",
        )

        # The caller can compare the returned handle against the account being
        # authenticated and reject the assertion on mismatch.
        self.assertIsNotNone(result.user_handle)
        self.assertNotEqual(result.user_handle, expected_user_handle)
