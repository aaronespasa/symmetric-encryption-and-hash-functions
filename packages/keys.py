from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey.RSA import import_key
from OpenSSL.crypto import FILETYPE_PEM, load_privatekey
from os import path
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


class Sign:
    """
    This class is used to sign and verify the signature of a message.

    Main Functions:
        -> sign(prescription_raw: str) -> str:
            This function signs a message using the institution private key.
        
        -> check_signature(self, prescription_raw: str, signature: str) -> bool:
            This function verifies a message using the institution public key.
    """
    def __init__(self, A_path: str):
        # CONSTANTS
        PRIVATE_KEY_NAME = "Akey.pem"
        PUBLIC_KEY_NAME = "Acert.pem"

        # Keep in mind we're calling it from main.py
        self.A_PATH = self.get_A_path(A_path)
        self.PRIVATE_KEY = self.get_file_info(PRIVATE_KEY_NAME)
        self.PUBLIC_KEY = self.get_file_info(PUBLIC_KEY_NAME)

    @staticmethod
    def get_A_path(A_path):
        if A_path[-1] != "/":
            raise Exception("A Pathname has to end with a slash / symbol")

        if not path.exists(A_path):
            raise Exception("The path does not exist")
        
        return A_path
    
    def get_file_info(self, key_name):
        """Obtain the information of the given keys.
        These keys have been generated previously using OpenSSL and
        they belong to the Authority of Certification 'A'.
        """
        path = self.A_PATH + key_name
        
        file = open(path, "rb")
        info = file.read()
        file.close()

        return info
    
    def sign(self, prescription_raw: str) -> str:
        """
        The process of signing a message is as follows:
            1. The hash of the raw message is calculated using SHA256.
            2. The hash is signed using the institution private key.
            3. The signature is returned.
        """
        hash = SHA256.new(prescription_raw.encode())
        pkcs = self.get_pkcs(use_private_key=True)
        return pkcs.sign(hash)
    
    def check_signature(self, prescription_raw: str, signature: str) -> bool:
        """
        The process of verifying a signature is as follows:
            1. The hash of the raw message is calculated using SHA256.
            2. The hash is verified using the institution public key.
            3. The result of whether the signature is verify or not is returned.
        """
        hash = SHA256.new(prescription_raw.encode())
        pkcs = self.get_pkcs(use_private_key=False)
        return True if pkcs.verify(hash, signature) else False

    def get_pkcs(self, use_private_key) -> pkcs1_15:
        """
        Returns the pkcs1_15 object to sign or verify a message.
        
        If we want to sign the message, we need to use the private key. So
        use_private_key has to be set to True.

        In case we want to verify the message, we need to use the public key. So
        use_private_key has to be set to False.
        """
        if use_private_key:
            # passphrase= input("\nEnter the RSA private key password:\n>>> ")
            # print(self.PRIVATE_KEY)
            key = load_privatekey(FILETYPE_PEM, self.PRIVATE_KEY)
            # key = import_key(self.PRIVATE_KEY, passphrase=passphrase)
        else:
            key = import_key(self.PUBLIC_KEY)

        return pkcs1_15.new(key)
# we read the private key situated in the path C:\Users\ALEJANDRA\Desktop\uni\tercero\cripto\cripto2.2\crypto-delivery-2\packages\aut_certificacion\A\Akey.pem
# opening the file and printing the content
#Write key to file

#Read key from file
f = open(".\\aut_certificacion\\A\\Akey_de.pem", 'rb')
key = RSA.importKey(f.read())
cipher = PKCS1_OAEP.new(key)
print(cipher)