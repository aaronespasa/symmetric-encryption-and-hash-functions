#########################################
# Hash Functions Class
# 
# It allows us to:
# - Generate a hash of a password
# - Compare a password with a hash
#
#
# Authors:
#  - Aarón Espasandín Geselmann
#  - Alejandra Galán Arróspide
#########################################
from Crypto.Hash import SHA512
from time import time

class HashFunctions:
    """
    Class to generate a hash of a password and compare it with another one
    """
    def __init__(self, password, salt=None):
        """
        Constructor
        """
        self.password = password
        self.salt = self.generate_salt(salt)

    def generate_hash(self):
        """
        Generates a hash of the password
        """
        # Generate a hash of the password
        hash = SHA512.new((self.salt + self.password).encode())

        # Return the hash
        return hash
    
    def generate_salt(self, salt):
        if salt == None:
            return str(int(time()))
        else:
            return salt
    
    def get_salt(self):
        """
        Returns the salt
        """
        return self.salt

    def compare_hash(self, hash):
        """
        Compares the password with a hash
        """
        # Generate a hash of the password
        hash2 = SHA512.new((self.salt + self.password).encode())

        # Compare the hashes
        if hash.hexdigest() == hash2.hexdigest():
            return True
        else:
            return False
