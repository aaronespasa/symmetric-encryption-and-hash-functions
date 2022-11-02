from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import status
from random import randint
from .serializers import UserSerializer, PasswordSerializer, PrescriptionSerializer
from .security.SymmetricEncryption import SymmetricEncryption
from .security.HashFunctions import HashFunctions

PRESCRIPTIONS = [
    "12T_TB4Yue25F_67OKiHhXqlsXxSbr6wY",
    "1XbkwZuTso_wMXr8wbxwRXQVoJZSz2S75",
    "1_bBRIAHdVunX1i7vAWTLPJYXdl9OaV3o",
    "1AvW7U5dMWPBIwI4R9696rxYT2P_LLvmA",
]

def generate_hash(password, salt=None):
    hashFunctions = HashFunctions(password, salt)
    hash = hashFunctions.generate_hash()
    hash_text = hash.hexdigest()
    return hashFunctions.get_salt(), hash_text

@api_view(['POST'])
def signup(request):
    # if request.method == 'POST':
    symmetricEncryption = SymmetricEncryption()

    # get username and password from request
    username = request.data.get('username')
    password = request.data.get('password')

    # generate hash of password
    salt, hash_text = generate_hash(password)
    (key, iv, ciphertext) = symmetricEncryption.encrypt(hash_text.encode())
    password_serializer = PasswordSerializer(
        data = {
            'key': key.hex(),
            'iv': iv.hex(),
            'ciphertext': ciphertext.hex(),
            'salt': salt
        }
    )

    password_id = None
    if password_serializer.is_valid():
        password_serializer.save()
        password_id = password_serializer.data.get('id')

    # generate random prescription
    assigned_prescription = PRESCRIPTIONS[randint(0, len(PRESCRIPTIONS) - 1)]
    (prescription_key, prescription_iv, prescription_ciphertext) = symmetricEncryption.encrypt(assigned_prescription.encode())
    prescription_serializer = PrescriptionSerializer(
        data = {
            'key': prescription_key.hex(),
            'iv': prescription_iv.hex(),
            'ciphertext': prescription_ciphertext.hex()
        }
    )

    prescription_id = None
    if prescription_serializer.is_valid():
        prescription_serializer.save()
        prescription_id = prescription_serializer.data.get('id')

    print("password_id: " + str(password_id))
    print("prescription_id: " + str(prescription_id))
    

    if password_id != None and prescription_id != None:
        user_serializer = UserSerializer(
            data = {
                'username': username,
                'password': password_id,
                'prescription': prescription_id
            }
        )

        if user_serializer.is_valid():
            user_serializer.save()
            return Response(user_serializer.data, status=status.HTTP_201_CREATED)
    return Response(user_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
