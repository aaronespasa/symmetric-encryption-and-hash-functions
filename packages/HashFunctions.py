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

class HashFunctions:
    """
    Class to generate a hash of a password and compare it with another one
    """
    def __init__(self, password):
        """
        Constructor
        """
        self.password = password

    def generate_hash(self):
        """
        Generates a hash of the password
        """
        # Generate a hash of the password
        hash = SHA512.new(self.password)

        # Return the hash
        return hash

    def compare_hash(self, hash):
        """
        Compares the password with a hash
        """
        # Generate a hash of the password
        hash2 = SHA512.new(self.password)

        # Compare the hashes
        if hash == hash2:
            return True
        else:
            return False
