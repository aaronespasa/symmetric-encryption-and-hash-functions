###################################
# Tests for the SymmetricEncryption class
#
# Authors:
#  - Aarón Espasandín Geselmann
#  - Alejandra Galán Arróspide
###################################
import unittest
from packages.SymmetricEncryption import SymmetricEncryption


class SymmetricEncryptionTests(unittest.TestCase):
    """
    SymmetricEncryption Class: Unit Testing
    """

    def setUp(self) -> None:
        """
        Set up the test
        """
        self.password = "Roberto123$"
        self.prescription = "1_bBRIAHdVunX1i7vAWTLPJYXdl9OaV3o"
        self.symmetricEncryption = SymmetricEncryption()

    def test_encrypt(self):
        """
        Encrypt a message
        """
        EXPECTED_CIPHERTEXT = "d8239839f03810e6142f5c8322c7f4819a4d935be0c4652f0e9deacf86be056a7b"

        # Encrypt the password
        (_, _, ciphertext) = self.symmetricEncryption.encrypt(self.prescription.encode())
        resultingCiphertext = ciphertext.hex()

        self.assertEqual(resultingCiphertext, EXPECTED_CIPHERTEXT)

    def test_decrypt(self):
        """
        Decrypt a password
        """
        # Encrypt the password
        (key, iv, ciphertext) = self.symmetricEncryption.encrypt()

        # Decrypt the password
        plaintext = self.symmetricEncryption.decrypt(key, iv, ciphertext)

        # Check the plaintext is not empty
        self.assertNotEqual(plaintext, b"")

    def test_decrypt_incorrect(self):
        """
        Decrypt an incorrect password
        """
        # Encrypt the password
        (key, iv, ciphertext) = self.symmetricEncryption.encrypt()

        # Decrypt the password
        plaintext = self.symmetricEncryption.decrypt(key, iv, ciphertext + b"1")

        # Check the plaintext is not empty
        self.assertNotEqual(plaintext, b"")

    def test_decrypt_empty(self):
        """
        Decrypt an empty password
        """
        # Encrypt the password
        (key, iv, ciphertext) = self.symmetricEncryption.encrypt()

        # Decrypt the password
        plaintext = self.symmetricEncryption.decrypt(key, iv, b"")

        # Check the plaintext is not empty
        self.assertNotEqual(plaintext, b"")

    def test_decrypt_none(self):
        """
        Decrypt a none password
        """
        # Encrypt the password
        (key, iv, ciphertext) = self.symmetricEncryption.encrypt()

        # Decrypt the password
        plaintext = self.symmetricEncryption.decrypt(key, iv, None)

        # Check the plaintext is not empty
        self.assertNotEqual(plaintext, b"")

if __name__ == '__main__':
    unittest.main()