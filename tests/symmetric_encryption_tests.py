###################################
# Tests for the SymmetricEncryption class
# 
# Authors:
#  - Aarón Espasandín Geselmann
#  - Alejandra Galán Arróspide
###################################
import unittest
from ..packages.SymmetricEncryption import SymmetricEncryption

class SymmetricEncryptionTests(unittest.TestCase):
    """
    SymmetricEncryption Class: Unit Testing
    """
    def setUp(self) -> None:
        """
        Set up the test
        """
        self.password = b"password"
        self.symmetricEncryption = SymmetricEncryption(self.password)
    
    def test_encrypt(self):
        """
        Encrypt a password
        """
        # Encrypt the password
        (key, iv, ciphertext) = self.symmetricEncryption.encrypt()

        # Check the ciphertext is not empty
        self.assertNotEqual(ciphertext, b"")
    
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