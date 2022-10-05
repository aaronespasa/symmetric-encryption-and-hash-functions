#########################################
# Symmetric Encryption Class
# 
# It allows us to:
# - Generate a new secure password and encrypt it using AES
# - Store the generated password in a password-protected file
# - Decrypt the password from the file
#
# Authors:
#  - Aarón Espasandín Geselmann
#  - Alejandra Galán Arróspide
#########################################
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class SymmetricEncryption:
    """
    Class to encrypt and decrypt a password using AES
    """
    def __init__(self, password):
        """
        Constructor
        """
        self.password = password

    def encrypt(self):
        """
        Encrypts the password using AES
        """
        # Generate a secure key
        key = get_random_bytes(32)

        # Generate a secure initialization vector
        iv = get_random_bytes(16)

        # Encrypt the password using AES
        cipher = AES.new(key, AES.MODE_CFB, iv)
        ciphertext = cipher.encrypt(self.password)

        # Return the encrypted password
        return (key, iv, ciphertext)

    def decrypt(self, key, iv, ciphertext):
        """
        Decrypts the password using AES
        """
        # Decrypt the password using AES
        cipher = AES.new(key, AES.MODE_CFB, iv)
        plaintext = cipher.decrypt(ciphertext)

        # Return the decrypted password
        return plaintext
