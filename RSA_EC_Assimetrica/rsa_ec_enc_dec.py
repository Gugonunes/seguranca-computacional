from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


def encrypt_rsa(message):
    with open("./chaves/openssl/rsa/public.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())

    encrypted = public_key.encrypt(
      message,
      padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return encrypted

def decrypt_rsa(encrypted_message):
    with open("./chaves/openssl/rsa/key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())

    original_message = private_key.decrypt(
      encrypted_message,
      padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(), label=None)
    )
    return original_message

def derive_symmetric_key():
    with open("./chaves/openssl/ec/key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())

    with open("./chaves/openssl/ec/public.pem", "rb") as key_file:
        peer_public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())

    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
      algorithm=hashes.SHA256(),
      length=32,
      salt=None,
      info=b'handshake data',
      backend=default_backend()
    ).derive(shared_key)
    return derived_key

def encrypt_ec(key, message):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(message) + encryptor.finalize()
    return iv, ct

def decrypt_ec(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


# Mensagem a ser criptografada
message = b"Bom dia teste"

# Criptografia e descriptografia com RSA
encrypted_message_rsa = encrypt_rsa(message)
print(f"Mensagem criptografada RSA: {encrypted_message_rsa}")

original_message_rsa = decrypt_rsa(encrypted_message_rsa)
print(f"Mensagem descriptografada: {original_message_rsa.decode('utf-8')}")

# Criptografia e descriptografia com EC
symmetric_key_ec = derive_symmetric_key()
iv, encrypted_message_ec = encrypt_ec(symmetric_key_ec, message)
print(f"Mensagem criptografada EC: {encrypted_message_ec}")

original_message_ec = decrypt_ec(symmetric_key_ec, iv, encrypted_message_ec)
print(f"Mensagem descriptografada: {original_message_ec.decode('utf-8')}")
