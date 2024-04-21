from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib
import math

def setup_tuple(mensagem_original, salt):
  """"
  Une a mensagem a um salt, cria um hash e une o hash com a mensagem original
  """
  tupla_salt = (mensagem_original, salt)
  tupla_salt_serializada = str(tupla_salt).encode('utf-8')
  hash_original = hashlib.sha256(tupla_salt_serializada).digest()
  tupla_original = (mensagem_original, hash_original)
  return tupla_original

def encrypt_tuple(tupla_original, cipher):
  """"
  Encripta a tupla utilizando o cipher
  """
  tupla_serializada = str(tupla_original).encode('utf-8')
  tupla_serializada_padded = pad(tupla_serializada, AES.block_size)
  tupla_criptografada = cipher.encrypt(tupla_serializada_padded)
  return tupla_criptografada

def decrypt(tupla_criptografada, salt, cipher, key):
  """"
  Desencripta a tupla utilizando o cipher, separa a mensagem do hash original, calcula o hash e compara
  """
  cipher = AES.new(key, AES.MODE_CBC, iv=cipher.iv)
  tupla_descriptografada_padded = cipher.decrypt(tupla_criptografada)
  tupla_descriptografada = unpad(tupla_descriptografada_padded, AES.block_size)
  tupla_original = eval(tupla_descriptografada.decode('utf-8'))
  mensagem_descriptografada, hash_descriptografado = tupla_original
  tupla_salt = (mensagem_descriptografada, salt)
  tupla_salt_serializada = str(tupla_salt).encode('utf-8')
  hash_calculado = hashlib.sha256(tupla_salt_serializada).digest()

  if hash_descriptografado == hash_calculado:
      return f"A mensagem é autêntica -> {mensagem_descriptografada}"
  else:
      return "A mensagem foi alterada ou não é autêntica."

def main():
  """
  Função principal do programa.
  Configura as variáveis necessárias, exibe um menu de opções e executa a função correspondente à escolha do usuário.
  """
  key = get_random_bytes(16)
  salt = math.pi
  cipher = AES.new(key, AES.MODE_CBC)
  while True:
    print("\nMenu:")
    print("1. Encrypt text from console")
    print("2. Exit")

    choice = input("Enter your choice (1-2): ")

    if choice == '1':
      mensagem_original = input("Enter the text to encrypt: ")
      tupla_original = setup_tuple(mensagem_original, salt)
      print("\nOriginal tuple: ", tupla_original)
      tupla_criptografada = encrypt_tuple(tupla_original, cipher)
      print("\nEcrypted tuple: ", tupla_criptografada)
      decrypted_text = decrypt(tupla_criptografada, salt, cipher, key)
      print("\nDecrypted text: ", decrypted_text)
    elif choice == '2':
      break

if __name__ == '__main__':
  main()