from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

msg = b'Hello World'


# Generate a secure key
# Note that kayPair is a tuple with the private and public keys
keyPair = RSA.generate(2048)
privkey = keyPair
pubkey = keyPair.publickey()
#? Podemos observar que al intentar imprimir las claves, se nos devuelve una direccion de memoria
#? en la que se encuentra la clave, por lo que no podemos imprimir su contenido

# Encrypt the message
#? Notese que se cifra con la clave pública del destinatario 
#? y se descifra con la clave privada del destinatario ( que de modo teorico solo tendria él)

cipher = PKCS1_OAEP.new(pubkey)
ciphertext = cipher.encrypt(msg)
print (cipher)
print(ciphertext)
# Decrypt the message

#? Podemos observar que introducir privkey es equivalente a introducir keyPair
cipher = PKCS1_OAEP.new(privkey)
plaintext = cipher.decrypt(ciphertext)
print(plaintext)