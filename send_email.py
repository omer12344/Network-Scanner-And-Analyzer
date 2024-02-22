from email.message import EmailMessage
import ssl
import smtplib
import os

def send_email_report(email_receiver, body, subject):
    # add here the credentials of the email you want sending you updates.
    email_sender = 'youremail@gmail.com'
    email_sender_password ="yourpassword"
    
    em = EmailMessage()
    em["From"] = email_sender
    em['To'] = email_receiver
    em['Subject'] = subject

    if len(body) == 0:
        default_message = ""
        if "security" in subject:
            default_message = "No Threats found."
        else:
            default_message = f"No {subject} available."
        em.set_content(default_message)
    else:
        em.set_content(body)

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
        smtp.login(email_sender, email_sender_password)
        smtp.sendmail(email_sender, email_receiver, em.as_string())

