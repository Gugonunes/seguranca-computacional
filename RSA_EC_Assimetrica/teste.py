from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def encrypt_text(public_key, plaintext):
    ciphertext = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_text(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()
    return plaintext

# Exemplo de uso
def main():
    # Aqui você precisa substituir 'public_key_bytes' e 'private_key_bytes' pelos bytes reais de suas chaves
    # Você pode carregar suas chaves a partir de arquivos ou como preferir
    public_key_bytes = b'-----BEGIN PUBLIC KEY-----MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEt+JG+maTVuc3SXQIpwzGHCeAqSmrjxTxmreGxVmlTa6vsfAPdLFKub4J1litmdPg2/Vy9/kihVPASchiFyIRG3ioho7k/6iR8KAjqX2n7j6jBnKS/bEYdHsif4WL/XiT-----END PUBLIC KEY-----'
    private_key_bytes = b'-----BEGIN PRIVATE KEY-----MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDBpjYMdf4lTxZDWLMwa6Hd9Xpefm7yiqjssJlv1PpgrGGK5ArZaCk/bx3lYIurElTChZANiAAS34kb6ZpNW5zdJdAinDMYcJ4CpKauPFPGat4bFWaVNrq+x8A90sUq5vgnWWK2Z0+Db9XL3+SKFU8BJyGIXIhEbeKiGjuT/qJHwoCOpfafuPqMGcpL9sRh0eyJ/hYv9eJM=-----END PRIVATE KEY-----'

    # Carregar as chaves
    public_key = serialization.load_pem_public_key(public_key_bytes)
    private_key = serialization.load_pem_private_key(private_key_bytes, password=None)

    # Texto simples
    plaintext = "Exemplo de texto para criptografar e descriptografar!"

    # Criptografar o texto
    ciphertext = encrypt_text(public_key, plaintext)
    print("Texto criptografado:", ciphertext)

    # Descriptografar o texto
    decrypted_text = decrypt_text(private_key, ciphertext)
    print("Texto descriptografado:", decrypted_text)

if __name__ == "__main__":
    main()
