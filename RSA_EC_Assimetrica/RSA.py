from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def generate_rsa_keypair():
  # Gerar um novo par de chaves RSA
  private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
  public_key = private_key.public_key()
  return public_key, private_key

def encrypt_message(message, public_key):
  # Criptografar a mensagem usando a chave pública
  encrypted_message = public_key.encrypt(
      message.encode(),
      padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
      )
    )
  return encrypted_message

def decrypt_message(encrypted_message, private_key):
  # Decriptografar a mensagem usando a chave privada
  decrypted_message = private_key.decrypt(
      encrypted_message,
      padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
      )
    )
  return decrypted_message.decode()

# Gerar um par de chaves RSA
public_key, private_key = generate_rsa_keypair()

# Mensagem de exemplo
message = "Diz uma mensagem ao Dani"

# Criptografar a mensagem usando a chave pública
encrypted_message = encrypt_message(message, public_key)
print("Mensagem criptografada:", encrypted_message)

# Decriptografar a mensagem usando a chave privada
decrypted_message = decrypt_message(encrypted_message, private_key)
print("Mensagem decriptografada:", decrypted_message)