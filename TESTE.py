from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

# Função para gerar uma chave AES de 128 bits aleatória
def gerar_chave_AES():
    backend = default_backend()
    salt = os.urandom(16)  # 16 bytes de sal aleatório
    password = os.urandom(16)  # 16 bytes de senha aleatória
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    chave = kdf.derive(password)
    return chave

# Gerar chave AES aleatória
chave_aes = gerar_chave_AES()

# Exibir a chave gerada
print("Chave AES gerada: ", chave_aes)
