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

if __name__ == "__main__":
    # Ask the user for a password
    password = input("Enter a password: ")

    # Encrypt the password
    symmetricEncryption = SymmetricEncryption(password.encode())
    (key, iv, ciphertext) = symmetricEncryption.encrypt()

    # Generate a hash of the password
    hashFunctions = HashFunctions(password.encode())
    hash = hashFunctions.generate_hash()

    # Ask the user for the password
    password2 = input("Enter the password again: ")

    # Compare the password with the hash
    if hashFunctions.compare_hash(hash):
        print("The password is correct")
    else:
        print("The password is incorrect")

    # Decrypt the password
    plaintext = symmetricEncryption.decrypt(key, iv, ciphertext)

    # Compare the password with the decrypted one
    if password == plaintext.decode():
        print("The password is correct")
    else:
        print("The password is incorrect")
