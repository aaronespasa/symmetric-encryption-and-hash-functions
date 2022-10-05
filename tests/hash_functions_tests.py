###################################
# Tests for the HashFunctions class
# 
# Authors:
#  - Aarón Espasandín Geselmann
#  - Alejandra Galán Arróspide
###################################
import unittest
from ..packages.HashFunctions import HashFunctions

class HashFunctionsTests(unittest.TestCase):
    """
    HashFunctions Class: Unit Testing
    """
    def setUp(self) -> None:
        """
        Set up the test
        """
        self.password = b"password"
        self.hashFunctions = HashFunctions(self.password)
    
    def test_generate_hash(self):
        """
        Generate a hash of a password
        """
        # Generate a hash of the password
        hash = self.hashFunctions.generate_hash()

        # Check the hash is not empty
        self.assertNotEqual(hash, b"")

    def test_compare_hash(self):
        """
        Compare a password with a hash
        """
        # Generate a hash of the password
        hash = self.hashFunctions.generate_hash()

        # Compare the hash with the password
        self.assertTrue(self.hashFunctions.compare_hash(hash))
    
    def test_compare_hash_incorrect(self):
        """
        Compare hash with incorrect password
        """
        # Generate a hash of the password
        hash = self.hashFunctions.generate_hash()

        # Compare the hash with the password
        self.assertFalse(self.hashFunctions.compare_hash(hash + b"1"))
    
    def test_compare_hash_empty(self):
        """
        Compare hash with empty password
        """
        # Compare the hash with the password
        self.assertFalse(self.hashFunctions.compare_hash(b""))
    
    def test_compare_hash_none(self):
        """
        Compare hash with None
        """
        # Compare the hash with the password
        self.assertFalse(self.hashFunctions.compare_hash(None))
    
    def test_compare_hash_incorrect_type(self):
        """
        Compare hash with incorrect type (integer)
        """
        # Compare the hash with the password
        self.assertFalse(self.hashFunctions.compare_hash(1))
    
    def test_compare_hash_incorrect_type2(self):
        """
        Compare hash with incorrect type (string)
        """
        # Compare the hash with the password
        self.assertFalse(self.hashFunctions.compare_hash("1"))
    
    def test_compare_hash_incorrect_type3(self):
        """
        Compare hash with incorrect type (float)
        """
        # Compare the hash with the password
        self.assertFalse(self.hashFunctions.compare_hash(1.1))
    
    def test_compare_hash_incorrect_type4(self):
        """
        Compare hash with incorrect type (boolean)
        """
        # Compare the hash with the password
        self.assertFalse(self.hashFunctions.compare_hash(True))
    
    def test_compare_hash_incorrect_type5(self):
        """
        Compare hash with incorrect type (list)
        """
        # Compare the hash with the password
        self.assertFalse(self.hashFunctions.compare_hash([1, 2, 3]))
    
    def test_compare_hash_incorrect_type6(self):
        """
        Compare hash with incorrect type (tuple)
        """
        # Compare the hash with the password
        self.assertFalse(self.hashFunctions.compare_hash((1, 2, 3)))
    
    def test_compare_hash_incorrect_type7(self):
        """
        Compare hash with incorrect type (dictionary)
        """
        # Compare the hash with the password
        self.assertFalse(self.hashFunctions.compare_hash({1: 1, 2: 2, 3: 3}))
