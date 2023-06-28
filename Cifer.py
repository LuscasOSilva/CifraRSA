from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key

escolha = input("Escolha: \n1 - Cifração e decifração AES, chave 128 bits \n2 - Geração de chaves e cifra RSA \n3 - Assinatura RSA \n4 - Verificação\n")
match escolha:
    case 1:
        print("ola mundo1")
    case 2:
        print("ola mundo2")
    case 3:
        print("ola mundo3")
    case 4:
        print("ola mundo4")

print(bytes("come meu cuzin", 'utf-8'))