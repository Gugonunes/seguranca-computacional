from Crypto.Cipher import DES
import hashlib

def setup_variables():
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
  (dk, iv) =(key[:8], key[8:])
  return dk, iv

def encrypt_text(text, dk, iv):
  """
  Função responsável por criptografar um texto utilizando o algoritmo DES.
  Recebe como parâmetros o texto a ser criptografado, a chave de dados (dk) e o vetor de inicialização (iv).
  Retorna o texto criptografado.
  """
  cipher = DES.new(dk, DES.MODE_CBC, iv)
  padded_text = text + ' ' * (8 - len(text) % 8)
  encrypted_text = cipher.encrypt(padded_text.encode('utf-8'))
  return encrypted_text

def decrypt_text(encrypted_text, dk, iv):
  """
  Função responsável por descriptografar um texto criptografado utilizando o algoritmo DES.
  Recebe como parâmetros o texto criptografado, a chave de dados (dk) e o vetor de inicialização (iv).
  Retorna o texto descriptografado.
  """
  cipher = DES.new(dk, DES.MODE_CBC, iv)
  decrypted_text = cipher.decrypt(encrypted_text)
  return decrypted_text.decode()

def encrypt_file(file_path, dk, iv):
  """
  Função responsável por criptografar um arquivo utilizando o algoritmo DES.
  Recebe como parâmetros o caminho do arquivo a ser criptografado, a chave de dados (dk) e o vetor de inicialização (iv).
  O arquivo original é lido, criptografado e salvo com a extensão ".enc".
  """
  with open(file_path, 'rb') as file:
    plaintext = file.read().decode("utf-8")
  encrypted_text = encrypt_text(plaintext, dk, iv)
  with open(file_path + '.enc', 'wb') as file:
    file.write(encrypted_text)

def decrypt_file(file_path, dk, iv):
  """
  Função responsável por descriptografar um arquivo criptografado utilizando o algoritmo DES.
  Recebe como parâmetros o caminho do arquivo a ser descriptografado, a chave de dados (dk) e o vetor de inicialização (iv).
  O arquivo criptografado é lido, descriptografado e salvo sem a extensão ".enc".
  """
  with open(file_path, 'rb') as file:
    encrypted_text = file.read()
  decrypted_text = decrypt_text(encrypted_text, dk, iv).encode('utf-8')
  with open(file_path[:-4], 'wb') as file:
    file.write(decrypted_text)

def encrypt_binary_file(file_path, dk, iv):
  """
  Função responsável por criptografar um arquivo binário utilizando o algoritmo DES.
  Recebe como parâmetros o caminho do arquivo binário a ser criptografado, a chave de dados (dk) e o vetor de inicialização (iv).
  O arquivo binário é lido, criptografado e salvo com a extensão ".enc".
  """
  with open(file_path, 'rb') as file:
    file_content = file.read()
  cipher = DES.new(dk, DES.MODE_CBC, iv)
  padded_content = file_content + b' ' * (8 - len(file_content) % 8)
  encrypted_text = cipher.encrypt(padded_content)
  with open(file_path + '.enc', 'wb') as file:
    file.write(encrypted_text)

def decrypt_binary_file(file_path, dk, iv):
  """
  Função responsável por descriptografar um arquivo binário criptografado utilizando o algoritmo DES.
  Recebe como parâmetros o caminho do arquivo binário a ser descriptografado, a chave de dados (dk) e o vetor de inicialização (iv).
  O arquivo binário criptografado é lido, descriptografado e salvo sem a extensão ".enc".
  """
  with open(file_path, 'rb') as file:
    encrypted_text = file.read()
  cipher = DES.new(dk, DES.MODE_CBC, iv)
  decrypted_text = cipher.decrypt(encrypted_text)
  with open(file_path[:-4], 'wb') as file:
    file.write(decrypted_text)

def main():
  """
  Função principal do programa.
  Configura as variáveis necessárias, exibe um menu de opções e executa a função correspondente à escolha do usuário.
  """
  dk, iv = setup_variables()

  while True:
    print("\nMenu:")
    print("1. Encrypt text from console")
    print("2. Decrypt text from console")
    print("3. Encrypt file")
    print("4. Decrypt file")
    print("5. Encrypt text from code")
    print("6. Decrypt text from code")
    print("7. Encrypt binary file")
    print("8. Decrypt binary file")
    print("9. Exit")

    choice = input("Enter your choice (1-9): ")

    if choice == '1':
      text = input("Enter the text to encrypt: ")
      encrypted_text = encrypt_text(text, dk, iv)
      print("Encrypted text:", encrypted_text.hex())
    elif choice == '2':
      encrypted_text = input("Enter the encrypted text: ")
      decrypted_text = decrypt_text(bytes.fromhex(encrypted_text), dk, iv)
      print("Decrypted text:", decrypted_text)
    elif choice == '3':
      file_path = input("Enter the path of the file to encrypt: ")
      encrypt_file(file_path, dk, iv)
      print("File encrypted successfully.")
    elif choice == '4':
      file_path = input("Enter the path of the file to decrypt: ")
      decrypt_file(file_path, dk, iv)
      print("File decrypted successfully.")
    elif choice == '5':
      text = "Hello, World!"
      encrypted_text = encrypt_text(text, dk, iv)
      print("Encrypted text:", encrypted_text.hex())
    elif choice == '6':
      encrypted_text = '7b76731d16cfa025a334f65d17191e7e'
      decrypted_text = decrypt_text(bytes.fromhex(encrypted_text), dk, iv)
      print("Decrypted text:", decrypted_text)
    elif choice == '7':
      file_path = input("Enter the path of the binary file to encrypt: ")
      encrypt_binary_file(file_path, dk, iv)
      print("Binary file encrypted successfully.")
    elif choice == '8':
      file_path = input("Enter the path of the binary file to decrypt: ")
      decrypt_binary_file(file_path, dk, iv)
      print("Binary file decrypted successfully.")
    elif choice == '9':
      break
    else:
      print("Invalid choice. Please try again.")

if __name__ == '__main__':
  main()