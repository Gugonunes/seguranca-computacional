from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def encrypt_text(key, mensagem_original):
  """
  Encripta a mensagem original e a retorna a tupla com o hash.
  """
  hash_original = SHA256.new(mensagem_original.encode('utf-8'))
  signature_obj = pkcs1_15.new(key)
  hash_criptografado = signature_obj.sign(hash_original)
  tupla_original = (mensagem_original, hash_criptografado)
  return tupla_original

def decrypt_text(key, tupla_original):
  """
  Desencripta a tupla criptografada e verifica a autenticidade da mensagem.
  """
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
  key = RSA.generate(2048)
  while True:
    print("\nMenu:")
    print("1. Encrypt text from console")
    print("2. Exit")

    choice = input("Enter your choice (1-2): ")

    if choice == '1':
      mensagem_original = input("Enter the text to encrypt: ")
      encrypted_text = encrypt_text(key, mensagem_original)
      print("\nEcrypted text: ", encrypted_text)
      decrypted_text = decrypt_text(key, encrypted_text)
      print("\nDecrypted text: ", decrypted_text)
    elif choice == '2':
      break

if __name__ == '__main__':
  main()