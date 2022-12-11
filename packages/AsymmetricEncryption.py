
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

class AsymmetricEncryption:
    """
    Class to encrypt and decrypt a password using RSA
    """
    @staticmethod
    def generate_key():
        """
        Generates a new RSA key
        and returns it
        """
        # Generate a secure key
        #! Hay que justificar el uso de 2048 bits
        keyPair = RSA.generate(2048)

        # Return the key
        return keyPair
    @staticmethod
    def encrypt(password, public_key):
        """
        Encrypts the password using RSA
        And returns the encrypted password
        """
       
        # Note that kayPair is a tuple with the private and public keys
        #pubkey = keyPair.publickey()
        cipher = PKCS1_OAEP.new(public_key)
        # Encrypt the password using RSA
        #! No se si es necesario el 32
        #ciphertext = keyPair.encrypt(password, 32)
        ciphertext = cipher.encrypt(password)
        # Return the encrypted password
        return (ciphertext)

    @staticmethod
    def decrypt(private_key, ciphertext):
        """
        Decrypts the password using RSA
        And returns the decrypted password
        """
        # Decrypt the password using RSA
        privkey = private_key
        #! Mirar que hace el PKCS1_OAEP
        cipher = PKCS1_OAEP.new(privkey)
        plaintext = cipher.decrypt(ciphertext)
        # Return the decrypted password
        return plaintext