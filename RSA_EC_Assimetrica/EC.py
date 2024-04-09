from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

def generate_ec_keypair():
    # Gerar um novo par de chaves EC
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    return public_key, private_key

# Gerar um par de chaves EC
public_key, private_key = generate_ec_keypair()

# Serializar as chaves para um formato legível
serialized_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

serialized_private_key = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Imprimir as chaves
print("Chave pública:")
print(serialized_public_key.decode())

print("\nChave privada:")
print(serialized_private_key.decode())
