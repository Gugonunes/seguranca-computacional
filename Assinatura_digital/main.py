from dss import DSSVerifier
from dsa import DSAKeys
from aes import AESCipher
from mail import Mailer

def generate_keys():
  dsa = DSAKeys()
  private_key, public_key = dsa.generate_keys()
  print("Chaves geradas com sucesso!")
  dsa.save_keys(private_key, public_key)
  print("Chaves salvas com sucesso!")

def sign_message():
  dsa = DSAKeys()
  message = input("Digite a mensagem que deseja assinar: ")
  signature = dsa.sign(message)
  with open("signed_message", "wb") as f:
            f.write(message.encode() + signature)
  print("Mensagem assinada com sucesso!")

def sign_encrypted_message():
  dsa = DSAKeys()
  aes = AESCipher()

  message = input("Digite a mensagem que deseja assinar: ")
  signMessage = dsa.sign(message)
  encryptedMessage = aes.encrypt(message.encode() + signMessage)

  with open("encrypted_signed_message", "wb") as f:
    f.write(encryptedMessage.encode())
  print("Mensagem criptografada e assinada com sucesso!")

def send_mail():
    mailer = Mailer()
    mailer.login()

    # get file paths
    msg_file = '/Users/gugonunes/utfpr/seguranca-computacional/Assinatura_digital/signed_message'
    public_key = '/Users/gugonunes/utfpr/seguranca-computacional/Assinatura_digital/dsa.pub'

    if (msg_file) and (public_key):
        receiver = input('Informe o email do destinatário: ')
        subject = input('Informe o assunto da mensagem: ')
        body = input('Informe o corpo do email: ')
        
        mailer.send(
            receiver, 
            subject, 
            body, 
            attachments=[
                msg_file,
                public_key
            ]
        )

def verify_message():
  dsa = DSAKeys()
  dss = DSSVerifier()

  msg_file_path = input('Informe o caminho do arquivo assinado: ')

  msg_file = open(msg_file_path, 'rb')
  signed_message = msg_file.read()

  _, public_key = dsa.load_keys()
  dss.set_key(public_key)

  plain_text, signature = signed_message[:-56], signed_message[-56:]

  if dss.verify(plain_text, signature):
      print('Mensagem válida')
  else:
      print('Mensagem inválida')

def verify_encrypted_message():
    dsa = DSAKeys()
    dss = DSSVerifier()
    aes = AESCipher()

    msg_file_path = input('Informe o caminho do arquivo assinado: ')
    
    msg_file = open(msg_file_path, 'rb')
    encrypted_signed_message = msg_file.read()

    _, public_key = dsa.load_keys()
    dss.set_key(public_key)
    
    signed_message = aes.decrypt(encrypted_signed_message)
    plain_text, signature = signed_message[:-56], signed_message[-56:]

    if dss.verify(plain_text, signature):
        print('Mensagem válida')
    else:
        print('Mensagem inválida')

def main():
  while True:
    print("\nMenu:")
    print("1. Gerar par de chaves com DSA")
    print("2. Assinar mensagem")
    print("3. Assinar mensagem com criptografia AES")
    print("4. Enviar por email")
    print("5. Verificar mensagem recebida no email")
    print("6. Verificar mensagem criptografada recebida no email")
    print("7. Exit")

    choice = input("Selecione uma opção (1-7): ")

    if choice == '1':
      generate_keys()
      
    if choice == '2':
      sign_message()

    if choice == '3':
      sign_encrypted_message()

    if choice == '4':
      send_mail()

    if choice == '5':
      verify_message()

    if choice == '6':
      verify_encrypted_message()

    elif choice == '7':
      break

if __name__ == '__main__':
  main()