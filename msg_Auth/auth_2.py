from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib

def encrypt_text(mensagem_original, cipher):
  """
  Cria um hash, encripta o hash e une ele com a mensagem
  """
  hash_original = hashlib.sha256(mensagem_original.encode()).digest()
  hash_serializado_padded = pad(hash_original, AES.block_size)
  hash_criptografado = cipher.encrypt(hash_serializado_padded)
  tupla_original = (mensagem_original, hash_criptografado)
  return tupla_original

def decrypt_text(key, tupla_original, cipher):
  """
  Separa o hash e a mensagem original, desencripta o hash e verifica a autenticidade
  """
  cipher = AES.new(key, AES.MODE_CBC, iv=cipher.iv)
  mensagem_original, hash_criptografado = tupla_original
  hash_descriptografado_padded = cipher.decrypt(hash_criptografado)
  hash_descriptografado = unpad(hash_descriptografado_padded, AES.block_size)
  hash_calculado = hashlib.sha256(mensagem_original.encode()).digest()

  if hash_calculado == hash_descriptografado:
      return f"A mensagem é autêntica -> {mensagem_original}"
  else:
      return "A mensagem foi alterada ou não é autêntica."

def main():
  """
  Função principal do programa.
  Configura as variáveis necessárias, exibe um menu de opções e executa a função correspondente à escolha do usuário.
  """
  key = get_random_bytes(16)
  cipher = AES.new(key, AES.MODE_CBC)
  while True:
    print("\nMenu:")
    print("1. Encrypt text from console")
    print("2. Exit")

    choice = input("Enter your choice (1-2): ")

    if choice == '1':
      mensagem_original = input("Enter the text to encrypt: ")
      encrypted_text = encrypt_text(key, mensagem_original, cipher)
      print("\nEcrypted text: ", encrypted_text)
      decrypted_text = decrypt_text(key, encrypted_text, cipher)
      print("\nDecrypted text: ", decrypted_text)
    elif choice == '2':
      break

if __name__ == '__main__':
  main()