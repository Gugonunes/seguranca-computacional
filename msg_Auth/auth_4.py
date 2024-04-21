from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

def encrypt_text(key, mensagem_original, cipher_AES):
  """
  Cria um hash com SHA, encripta o hash e une ele com a mensagem. Entao criptografa a tupla
  """
  hash_original = SHA256.new(mensagem_original.encode('utf-8'))
  signature_obj = pkcs1_15.new(key)
  hash_criptografado = signature_obj.sign(hash_original)
  tupla_original = (mensagem_original, hash_criptografado)
  tupla_serializada = str(tupla_original).encode('utf-8')
  tupla_serializada_padded = pad(tupla_serializada, AES.block_size)
  tupla_criptografada = cipher_AES.encrypt(tupla_serializada_padded)
  return tupla_original, tupla_criptografada

def decrypt_text(key, key_s, tupla_criptografada, cipher_AES):
  """
  Desencripta a tupla criptografada, calcula um hash e compara para verificar a autenticidade
  """
  cipher_AES = AES.new(key_s, AES.MODE_CBC, iv=cipher_AES.iv)
  tupla_descriptografada_padded = cipher_AES.decrypt(tupla_criptografada)
  tupla_descriptografada = unpad(tupla_descriptografada_padded, AES.block_size)
  tupla_original = eval(tupla_descriptografada.decode('utf-8'))
  mensagem_original, hash_criptografado = tupla_original
  hash_calculado = SHA256.new(mensagem_original.encode('utf-8'))
  public_key = key.publickey()
  try:
      pkcs1_15.new(public_key).verify(hash_calculado, hash_criptografado)
      return f"A mensagem é autêntica -> {mensagem_original}"
  except (ValueError, TypeError):
      return "A mensagem foi alterada ou não é autêntica."

def main():
  """
  Função principal do programa.
  Configura as variáveis necessárias, exibe um menu de opções e executa a função correspondente à escolha do usuário.
  """
  key_s = get_random_bytes(16)
  key = RSA.generate(2048)
  cipher_AES = AES.new(key_s, AES.MODE_CBC)
  while True:
    print("\nMenu:")
    print("1. Encrypt text from console")
    print("2. Exit")

    choice = input("Enter your choice (1-2): ")

    if choice == '1':
      mensagem_original = input("Enter the text to encrypt: ")
      tupla_original, tupla_criptografada = encrypt_text(key, mensagem_original, cipher_AES)
      print("\nOriginal tuple: ", tupla_original)
      print("\nEcrypted tuple: ", tupla_criptografada)
      decrypted_text = decrypt_text(key, key_s, tupla_criptografada, cipher_AES)
      print("\nDecrypted text: ", decrypted_text)
    elif choice == '2':
      break

if __name__ == '__main__':
  main()