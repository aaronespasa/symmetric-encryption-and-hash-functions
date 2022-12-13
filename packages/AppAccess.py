#########################################
# App Access Class
#
# It allows us to:
# -
# -
#
# Authors:
#  - Aarón Espasandín Geselmann
#  - Alejandra Galán Arróspide
#########################################
from .SymmetricEncryption import SymmetricEncryption
from .AsymmetricEncryption import AsymmetricEncryption
from .HashFunctions import HashFunctions
from .Sign import Sign
import json
from random import randint
from Crypto.PublicKey import RSA
# from OpenSSL.crypto import load_privatekey, \
#                            FILETYPE_PEM, \
#                            sign, \
#                            verify, \
#                            load_certificate, \
#                            FILETYPE_ASN1, \
#                            dump_certificate, \
#                            FILETYPE_PEM


class AppAccess:
    def __init__(self, database_json_path) -> None:
        self.database_json = database_json_path
        
        # The following list of prescriptions will be assigned randomly to the users
        # The prescription is encrypted using AES
        self.prescriptions = [
            "12T_TB4Yue25F_67OKiHhXqlsXxSbr6wY",
            "1XbkwZuTso_wMXr8wbxwRXQVoJZSz2S75",
            "1_bBRIAHdVunX1i7vAWTLPJYXdl9OaV3o",
            "1AvW7U5dMWPBIwI4R9696rxYT2P_LLvmA",
        ]
        self.symmetricEncryption = SymmetricEncryption()
        self.asymmetricEncryption = AsymmetricEncryption()
        keyPair = self.asymmetricEncryption.generate_key()
        self.create_RSA_info(keyPair)

        self.sign = Sign(r"C:/Users/ALEJANDRA/Desktop/uni/tercero/cripto/cripto2.2/crypto-delivery-2/packages/aut_certificacion/A/") # path relative to the main.py file

    @staticmethod
    def get_prescription_link(prescriptionLink):
        return f"https://drive.google.com/file/d/{prescriptionLink}/view?usp=sharing"

    def initialize_json(self):
        """Initialize the JSON file (empty the database)"""

        #! We should generate and include the keys for the website so 
        #! that the user can send the encrypted password to the website??

        data = []
        file = open(self.database_json, "w")
        json.dump(data, file, indent=4)

    def welcome_message(self) -> None:
        print("Welcome to your personal health service!")
        print("Please, choose an option:")

    def get_user_option(self) -> str:
        """Ask the user if he/she wants to sign up or log in"""
        options = {0: "Login", 1: "Sign Up"}

        for option_value in options:
            print(f"{option_value} - {options[option_value]}")

        option = -1
        while option not in options.keys():
            option = int(input(">>> "))
            if option not in [0, 1]:
                print("Please, enter a valid option")
        return options[option]

    def generate_hash(self, password, salt=None):
        """Generate a hash of the password
        - If the salt is not provided, it is generated randomly
        - If the salt is provided, it is used to generate the hash
        """
        hashFunctions = HashFunctions(password, salt)
        hash = hashFunctions.generate_hash() # Generate the hash
        hash_text = hash.hexdigest() # Hash in hexadecimal format
        return hashFunctions.get_salt(), hash_text

    def create_RSA_info(self, keyPair): 

        #! in reality the private key is only owned by the user and the public key is shared with the website

        #! Nos podemos plantear crear un diccionario para almacenar los nombres de los ficheros con la clave 
        #! publica de cada usuario y asi poder acceder a ellos cuando se necesite

        #! Otra opcion es generar claves nuevas cada vez que el usuario inicia sesion pero no tiene mucho sentido
        #! teorico

        private_key = keyPair.export_key()
        file_out = open("private_user.pem", "wb")
        file_out.write(private_key)
        file_out.close()

        public_key = keyPair.publickey().export_key()
        file_out = open("receiver_user.pem", "wb")
        file_out.write(public_key)
        file_out.close()


    def create_user_json(self, user, key, iv, ciphertext, salt):
        """Create a JSON with the user information
        - This information is what is stored in the database.json file
        """
        #! For the second part, we will be generating and saving the 
        #! asimetrical keys for the user

        # Generate a random prescription for the user
        assigned_prescription = self.prescriptions[
            randint(0, len(self.prescriptions) - 1)
        ]

        # Encrypt the prescription using AES
        (
            prescription_key,
            prescription_iv,
            prescription_ciphertext,
        ) = self.symmetricEncryption.encrypt(assigned_prescription.encode())

        #! Ciframos las claves simetricas con la clave publica del usuario
        #! y no las guardamos porque deben ser de un solo uso 

        public_key = RSA.import_key(open("receiver_user.pem").read())
        prescription_key = self.asymmetricEncryption.encrypt(prescription_key,public_key )
        prescription_iv = self.asymmetricEncryption.encrypt(prescription_iv,public_key )
        signature = self.sign.sign(assigned_prescription)

        # private_key = RSA.import_key(open("private_user.pem").read())
        # create a hash of the assigned_prescription and then sign it with the private key
        # prescription_hash = SHA256.new(assigned_prescription.encode())

        #! Para la entrega final se deben eliminar las claves simetricas del json

        # Create the JSON for the user which contains:
        # - The user name
        # - The key, the initialize vector and the encoded text of the password (encrypted using AES)
        # - The salt of the password (used to generate the hash)
        # - The key, the initialize vector and the encoded text of the prescription (encrypted using AES)

        #! creo que no se puede añadir un keyPair al json, 
        #! igual en un fichero .pem o algo asi

        #! la mejor opcion es guardar en la base de datos la clave pública 
        #! (NO SE SI SE PUEDE) --no se puede, podemos crear un fichero .pem para cada usuario 
        #! La clave privada en el fichero del usuario .pem 


        #! Podemos considerar dejarlo y borrarlas y regenerarlas en cada uso
        user_information = {
            "user": user,
            "password": {
                "key": key.hex(),
                "iv": iv.hex(),
                "ciphertext": ciphertext.hex(),
                "salt": salt,
            },
            "prescription": {
                "key": prescription_key.hex(),
                "iv": prescription_iv.hex(),
                "ciphertext": prescription_ciphertext.hex(),
                "signature": signature
            },
            
        }
        return user_information

    def check_if_user_exists(self, user) -> bool:
        """Check if the user already exists in the database"""
        file = open(self.database_json, "r")
        data = json.load(file)
        for p in data:
            if p["user"] == user:
                print("User already exists")
                print("Please, choose another user or log in")
                return True
        return False


    def encrypt_password(self, user, password) -> None:
        """Encrypt the password and store it in the database.json file"""
        # Generate a hash for the password and get the salt that was used to generate it
        # The, encrypt the hash 
        # of the password using AES
        
        salt, hash_text = self.generate_hash(password)
        (key, iv, ciphertext) = self.symmetricEncryption.encrypt(hash_text.encode())
        #! Notese que estas claves solo pueden usarse una vez

        # Store the key, the initialize vector and the ciphertext in a JSON file (database.json)
        #! En vez de guardar las claves en el json tenemos que mandarlas por asimetrico. 
        #! Asumo que el json conterdrá las claves publicas y privadas de cada usuario
        #! Me parece interesante incluir un "usuario" llamado "admin" que tenga las 
        #! claves publicas y privadas de la empresa
        user_information = self.create_user_json(user, key, iv, ciphertext, salt)

        file = open(self.database_json, "r")
        data = json.load(file)

        # Append the user information to the database.json file
        data.append(user_information)
        file = open(self.database_json, "w")
        json.dump(data, file, indent=4)

    def decrypt_password(self, user, password) -> str:
        """Checks if the user exists and if the password is correct
        - If the user exists, it decrypts the password and checks if it
          is the same as the one provided by the user
        - If the user does not exist, that's notified to the user
        - If the password is incorrect, that's notified to the user
        """
        # Read the key, the initialize vector and the encoded text
        # from the JSON file (database.json)
        userFound = False
        file = open(self.database_json, "r")
        #! Las claves se estan obteniendo del json,
        #! deben pasarse por cifrado asimetrico
        data = json.load(file)

        for p in data:
            if p["user"] == user:
                userFound = True
                key = bytes.fromhex(p["password"]["key"])
                iv = bytes.fromhex(p["password"]["iv"])
                ciphertext = bytes.fromhex(p["password"]["ciphertext"])
                salt = p["password"]["salt"]
                prescription_key = bytes.fromhex(p["prescription"]["key"])
                prescription_iv = bytes.fromhex(p["prescription"]["iv"])
                prescription_ciphertext = bytes.fromhex(p["prescription"]["ciphertext"])
                prescription_signature = p["prescription"]["signature"]
                break

        if userFound == False:
            return False

        # Decrypt the password using AES
        password1_hash_text = self.symmetricEncryption.decrypt(
            key, iv, ciphertext
        ).decode()

        #! Se debe desencriptar la clave simetrica con la clave asimetrica
        #! y luego desencriptar el mensaje con la clave simetrica

        private_key = RSA.import_key(open("private_user.pem").read())
        prescription_key = self.asymmetricEncryption.decrypt(private_key, prescription_key)
        prescription_iv = self.asymmetricEncryption.decrypt(private_key, prescription_iv)
        # Decrypt the prescription using AES
        prescription = self.symmetricEncryption.decrypt(
            prescription_key, prescription_iv, prescription_ciphertext
        ).decode()

        if self.sign.check_signature(prescription, prescription_signature) == False:
            return False

        print(f"\nPassword (raw text): {password}\n")
        print(f"\nPassword once is desencrypted by the sender (hash) : {password1_hash_text}\n")
        print(f"\nPassword as it is sent from the sender to the receiver (text encoded by AES) : {ciphertext.hex()}\n")
        print(f"\nMessage as it is sent by the sender to the receiver (text encoded by AES) : {prescription_ciphertext.hex()}\n")
        print(f"\nMessage after being desencrypted by the sender (raw text) : {prescription}\n")

        # Compare the password with the decrypted one
        salt, hash_text = self.generate_hash(password, salt)

        # If the password is correct, return the prescription
        # We know it the password is correct because the hash of the password introduced by the user
        # is the same as the one generated when the password was encrypted
        return prescription if password1_hash_text == hash_text else None

    def print_password_requirements(self) -> None:
        """Print the password requirements"""
        # Ask the user for a password
        print("------ Enter a password ------")
        print("*The password is encrypted using AES*")
        print("*A hash of the password is generated using SHA256*")
        print("Restrictions:")
        print("  - At least 8 characters")
        print("  - At least 1 number")
        print("  - At least 1 uppercase letter")
        print("  - At least 1 lowercase letter")
        print("  - At least 1 special character")

    def check_password_requirements(self, password) -> bool:
        """Check if the password meets the requirements"""
        if len(password) < 8:
            print("The password must have at least 8 characters")
            return False
        elif not any(char.isdigit() for char in password):
            print("The password must have at least 1 number")
            return False
        elif not any(char.isupper() for char in password):
            print("The password must have at least 1 uppercase character")
            return False
        elif not any(char.islower() for char in password):
            print("The password must have at least 1 lowercase character")
            return False
        elif not any(not char.isalnum() for char in password):
            print("The password must have at least 1 special character")
            return False
        return True

    def check_password(self, password) -> bool:
        """Check if the password meets the requirements and if it is correct"""
        password_secure = self.check_password_requirements(password)
        if not password_secure:
            print("Password must check all requirements")
            return False
        return True

    def signup(self, user, password, password2) -> None:
        """Sign up a new user
        1. Check if the user already exists
        2. Generate a hash for the password
        3. Encrypt the hash of the password using AES
        4. Store the key, the initialize vector and the ciphertext in a JSON file (database.json)
        5. Assign a random prescription to the user that will be encrypted using AES
        6. If the user was created successfully, show a link to the user's prescription
        """
        self.encrypt_password(user, password)
        prescription = self.decrypt_password(user, password2)

        if prescription == False:
            print("Passwords do not match")
        else:
            print("You have been registered successfully!")
            print("Here is your prescription:")
            print(self.get_prescription_link(prescription))

    def login(self, user, password) -> None:
        """Login a user
        1. Check if the user exists
        2. Decrypt the password and check if it is correct
        3. If the user was logged in successfully, show a link to the user's prescription
        """
        prescription = self.decrypt_password(user, password)

        if prescription == False:
            print("The user was not found or the password is incorrect")
            return False
        else:
            print("User successfully logged in")
            print("Welcome to your personal health service!")
            print("Here is your prescription")
            print(self.get_prescription_link(prescription))
            return True

    def run(self, first_call=True) -> None:
        """Run the program
        1. Ask the user if they want to sign up or login
        2. Ask the user for a username and a password
        3. Check if the password meets the requirements
        4. If the user wants to sign up, ask for the password again
        5. If the user wants to login, check if the password is correct
        6. If the user was logged in successfully, show a link to the user's prescription
        """
        if first_call:
            self.welcome_message()

        option = self.get_user_option()

        if option == "Login":
            print("Please, enter your username and password to access your prescription")
            user = input("Username:\n>>> ")
            # The user has 3 attempts to enter the password
            user_tries = 3
            while user_tries > 0:
                password = input("Password:\n>>> ")
                if self.login(user, password):
                    return
                else:
                    user_tries -= 1
                    print("You have " + str(user_tries) + " tries left")
            print("You have introduced the wrong password too many times")
        elif option == "Sign Up":
            print("Please, enter your username and password to register")
            user = input("Username:\n>>> ")
            # Check if the user already exists
            if not self.check_if_user_exists(user):
                self.print_password_requirements()
                password = input("Password:\n>>> ")
                # Check if the password meets the requirements
                if self.check_password(password):
                    password2 = input("Password again:\n>>> ")
                    # Check if the password coincides with the one introduced before
                    self.signup(user, password, password2)
            else:
                # The user already exists
                # -> Ask the user if they want to login
                self.run(False)
