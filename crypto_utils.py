
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
#gera a chave pública e privada. Supondo o usuário Bob, A chave pública é acessada por todos os peers que se conectam a ele. 
#Quando um usuário quer mandar mensagem pro Bob, ele pega essa chave pública, criptografa a mensagem com ela e manda.
#Aí o Bob pega a mensagem criptografada e usa a chave privada dele(que só ele tem) para descriptografar a mensagem.
def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
   
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

def load_public_key(pem):
    return serialization.load_pem_public_key(pem.encode())

#aqui é a criptografia da msg com a chave pública
def encrypt_message(public_key, message: str):
    public_numbers = public_key.public_numbers()
    message_bytes = message.encode()
    message_int = int.from_bytes(message_bytes, 'big')
    ciphertext_int = pow(message_int, public_numbers.e, public_numbers.n)

    key_byte_size = (public_key.key_size + 7) // 8
    return ciphertext_int.to_bytes(key_byte_size, 'big')

#aqui é a descriptografia da msg com a chave privada
def decrypt_message(private_key, ciphertext: bytes):
    private_numbers = private_key.private_numbers()
    public_numbers = private_key.public_key().public_numbers()

    ciphertext_int = int.from_bytes(ciphertext, 'big')
    message_int = pow(ciphertext_int, private_numbers.d, public_numbers.n)
    key_byte_size = (private_key.key_size + 7) // 8
    message_bytes = message_int.to_bytes(key_byte_size, 'big')
    #decodifica a mensagem para string
    return message_bytes.lstrip(b'\x00').decode()