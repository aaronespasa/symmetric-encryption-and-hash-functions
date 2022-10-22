##########################################
# Main Interface of the 1st Delivery for the
# Cryptography & Computer Security Subject
#
# Authors:
#   - Aarón Espasandín Geselmann
#   - Alejandra Galán Arróspide
##########################################
from packages.SymmetricEncryption import SymmetricEncryption
from packages.HashFunctions import HashFunctions

def encrypt_password(password, password2):
    """
    Asks for a password
    """
    hashFunctions = HashFunctions(password.encode())
    hash = hashFunctions.generate_hash()
    hash_text = hash.hexdigest()

    # Encrypt the password
    symmetricEncryption = SymmetricEncryption(hash_text.encode())
    (key, iv, ciphertext) = symmetricEncryption.encrypt()

    # Decrypt the password
    hash_plaintext = symmetricEncryption.decrypt(key, iv, ciphertext)

    # Generate the hash of the second password
    hashFunctions_second_password = HashFunctions(password2.encode())
    hash_second_password = hashFunctions_second_password.generate_hash()
    hash_second_password_text = hash_second_password.hexdigest()

    # Compare the password with the decrypted one
    if hash_second_password_text == hash_plaintext.decode():
        print("The password is correct")
    else:
        print("The password is incorrect")

# def generate_hash(password):
#     """
#     Generates a hash of a password
#     """
#     # Generate a hash of the password
#     hashFunctions = HashFunctions(password.encode())
#     hash = hashFunctions.generate_hash()

#     # Compare the password with the hash
#     if hashFunctions.compare_hash(hash):
#         print("The password is correct")
#     else:
#         print("The password is incorrect")

if __name__ == "__main__":
    # Ask the user for a password
    password = input("Enter a password: ")

    # Ask the user for the password
    password2 = input("Enter the password again: ")

    encrypt_password(password, password2)
