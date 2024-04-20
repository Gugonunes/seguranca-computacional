from Crypto.Random import get_random_bytes
import hashlib
import math

def setup_tuple(mensagem_original, salt):
  tupla_salt = (mensagem_original, salt)
  tupla_salt_serializada = str(tupla_salt).encode('utf-8')
  hash_original = hashlib.sha256(tupla_salt_serializada).digest()
  tupla_original = (mensagem_original, hash_original)
  return tupla_original

def decrypt(tupla_original, salt):
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
  salt = math.pi
  while True:
    print("\nMenu:")
    print("1. Encrypt text from console")
    print("2. Exit")

    choice = input("Enter your choice (1-2): ")

    if choice == '1':
      mensagem_original = input("Enter the text to encrypt: ")
      tupla_original = setup_tuple(mensagem_original, salt)
      print("\nEcrypted tuple: ", tupla_original)
      decrypted_text = decrypt(tupla_original, salt)
      print("\nDecrypted text: ", decrypted_text)
    elif choice == '2':
      break

if __name__ == '__main__':
  main()