import hashlib
from Crypto.Cipher import AES
import random
import base64
def setup_variables(choice):
  """
  Função responsável por configurar as variáveis necessárias para a criptografia.
  Solicita ao usuário a senha, gera uma chave a partir da senha e um salt fixo,
  e retorna a chave dividida em duas partes: dk (chave de dados) e iv (vetor de inicialização).
  """
  password = input("Enter the password: ")
  salt = '\x28\xAB\xBC\xCD\xDE\xEF\x00\x33'
  key = password + salt
  m = hashlib.md5(key.encode('utf-8'))
  key = m.digest()
  if choice == '1':
    dk =(key[:16])
  else:
    dk =(key[:32])
  iv = random.randbytes(16)
  return dk, iv

def encrypt_text(text, dk, iv, mode, nonce):
  """
  Função responsável por criptografar um texto utilizando o algoritmo AES.
  Recebe como parâmetros o texto a ser criptografado, a chave de dados (dk),
  o vetor de inicialização (iv) e o mode selecionado.
  Retorna o texto criptografado.
  """
  if mode == AES.MODE_ECB:
    cipher = AES.new(dk, mode)
  elif mode == AES.MODE_CTR:
    cipher = AES.new(dk, mode, nonce=nonce)
  else:
    cipher = AES.new(dk, mode, iv=iv)
  padded_text = text + ' ' * (16 - len(text) % 16)
  encrypted_text = cipher.encrypt(padded_text.encode('utf-8'))
  return encrypted_text

def decrypt_text(encrypted_text, dk, iv, mode, nonce):
  """
  Função responsável por descriptografar um texto criptografado utilizando o algoritmo AES.
  Recebe como parâmetros o texto criptografado, a chave de dados (dk),
  o vetor de inicialização (iv) e o mode selecionado.
  Retorna o texto descriptografado.
  """
  if mode == AES.MODE_ECB:
    cipher = AES.new(dk, mode)
  elif mode == AES.MODE_CTR:
    cipher = AES.new(dk, mode, nonce=nonce)
    decrypted_text = cipher.decrypt(encrypted_text)
    return decrypted_text.decode('utf-8').strip()
  else:
    cipher = AES.new(dk, mode, iv=iv)
  decrypted_text = cipher.decrypt(encrypted_text)
  return decrypted_text.decode()

def main():
  """
  Função principal do programa.
  Configura as variáveis necessárias, exibe um menu de opções e executa a função correspondente à escolha do usuário.
  # """

  while True:
    print("\nMenu:")
    print("\nKey Size:")
    print("1. 128 bits")
    print("2. 256 bits")
    print("3. Exit")

    choice = input("Enter your choice (1-3): ")

    if choice == '1' or choice == '2':
      dk, iv = setup_variables(choice)
      print("\n Select Mode:")
      print("1. ECB")
      print("2. CBC")
      print("3. CFB")
      print("4. OFB")
      print("5. CTR")
      print("6. Exit")

      mode = input("Enter your choice (1-6): ")

      if mode == '1':
        mode = AES.MODE_ECB
      elif mode == '2':
        mode = AES.MODE_CBC
      elif mode == '3':
        mode = AES.MODE_CFB
      elif mode == '4':
        mode = AES.MODE_OFB
      elif mode == '5':
        mode = AES.MODE_CTR
      elif mode == '6':
        break
      else:
        print("Invalid choice. Please try again.")
        continue
      text = input("Enter the text: ")
      nonce = random.randbytes(8) if choice == '1' else random.randbytes(16)
      encrypted_text = encrypt_text(text, dk, iv, mode, nonce)
      decrypted_text = decrypt_text(encrypted_text, dk, iv, mode, nonce)
      print("Encrypted text: " + encrypted_text.hex())
      print("Decrypted text: " + decrypted_text)

    elif choice == '3':
      break
    else:
      print("Invalid choice. Please try again.")

if __name__ == '__main__':
  main()