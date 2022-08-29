import email
from email.message import EmailMessage
from django.core.mail import send_mail
import os

class Util:
    @staticmethod
    def send_mail(data):
        email = EmailMessage(
        Subject= data['subject'],
        body = data['body'],
        from_email = os.environ.get('EMAIL_FROM'),
        to = [data['to_email']],
    )
    
        email.send()
