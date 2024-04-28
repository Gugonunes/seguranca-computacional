import smtplib
import os
from email import encoders
from email.message import EmailMessage
from email.mime.base import MIMEBase
from dotenv import load_dotenv
import ssl

class Mailer:
    def __init__(self):
        self.message = EmailMessage()
        self.sender = None
        self.password = None

    def login(self):
        load_dotenv()
        self.sender = os.getenv('EMAIL_USER')
        self.password = os.getenv('EMAIL_PASSWORD')

    def send(self, receiver_email, subject, body: str, attachments=None):
        self.message['From'] = self.sender
        self.message['To'] = receiver_email
        self.message['Subject'] = subject
        self.message.set_content(body)

        context = ssl.create_default_context()

        if attachments:
            for attachment in attachments:
                filename = os.path.basename(attachment)

                with open(attachment, 'rb') as file:
                    attachment_part = MIMEBase('application', 'octet-stream')
                    attachment_part.set_payload(file.read())

                encoders.encode_base64(attachment_part)
                attachment_part.add_header('Content-Disposition', f'attachment; filename= {filename}')
                self.message.add_attachment(attachment_part)

        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
            smtp.login(self.sender, self.password)
            smtp.sendmail(self.sender, receiver_email, self.message.as_string())
            smtp.quit()
            print(f"Mensagem para {receiver_email} enviada com sucesso")
