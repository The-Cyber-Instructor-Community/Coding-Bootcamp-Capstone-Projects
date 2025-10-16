import getopt, sys
import re
import psutil
import time
import logging
import os
from dotenv import load_dotenv
import httplib2
import oauth2client
from oauth2client import client, tools, file
import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from apiclient import errors, discovery
import mimetypes
from email.mime.image import MIMEImage
from email.mime.audio import MIMEAudio
from email.mime.base import MIMEBase


"""
Capstone by Carol On
October 10, 2025

Host-based IDS (HIDS):
Monitoring  system processes and data files for signs of compromise.
Real-time Alerts

# pip3 install psutil
# pip3 install python-dotenv
# pip3 uninstall oauth2client
# pip3 install oauth2client
# RUN
# python3 ids.py rules.txt packets.txt -a alerts_on

"""

load_dotenv()
SCOPES = 'https://www.googleapis.com/auth/gmail.send'
CLIENT_SECRET_FILE = 'credentials.json'
APPLICATION_NAME = 'ServerOAuth2'

class Customized_IDS:  
    # Constructor method (initializer)
    def __init__(self):
      self.rules = []
      self.alerts = []

    def add_rule(self, rule_pattern):
      self.rules.append(rule_pattern)
      return rule_pattern

    def analyze_traffic(self, packet_data):
      # Simulate network traffic analysis
      for rule in self.rules:
          if rule in packet_data:
              alert_message = f"Intrusion detected: {rule} in {packet_data}"
              self.alerts.append(alert_message)
              return alert_message

    def get_alerts(self):
        return self.alerts
# END Customized_IDS class

def get_file_content(file_path):
    try:
        with open(file_path, 'r') as file:
            content = file.read()
            return content
    except FileNotFoundError:
        with open(file_path, 'w') as file:
            file.write()
            return file_path
    except Exception as e:
        with open(file_path, 'w') as file:
            file.write()
        print(f"An error occurred: {e}")
        return file_path
# END get_file_content


def is_valid_email_regex(emailaddress):
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.fullmatch(regex, emailaddress) is not None

def send_alert(subject, body, recipientemails):
    recipientemails = recipientemails
    senderemail = os.getenv("EMAIL_ADDRESS")
    msgHtml = ""
    msgPlain = body
    SendMessage(senderemail, recipientemails, subject, msgHtml, msgPlain)



def get_credentials():
    home_dir = os.path.expanduser('~')
    credential_dir = os.path.join(home_dir, '.credentials')
    if not os.path.exists(credential_dir):
        os.makedirs(credential_dir)
    credential_path = os.path.join(credential_dir,'gmail-python-email-send.json')
    store = oauth2client.file.Storage(credential_path)
    credentials = store.get()
    if not credentials or credentials.invalid:
        flow = client.flow_from_clientsecrets(CLIENT_SECRET_FILE, SCOPES)
        flow.user_agent = APPLICATION_NAME
        credentials = tools.run_flow(flow, store)
        print('Storing credentials to ' + credential_path)
    return credentials

def SendMessage(sender, to, subject, msgHtml, msgPlain, attachmentFile=None):
    credentials = get_credentials()
    http = credentials.authorize(httplib2.Http())
    service = discovery.build('gmail', 'v1', http=http)
    if attachmentFile:
        message1 = createMessageWithAttachment(sender, to, subject, msgHtml, msgPlain, attachmentFile)
    else: 
        message1 = CreateMessageHtml(sender, to, subject, msgHtml, msgPlain)
    result = SendMessageInternal(service, "me", message1)
    return result

def SendMessageInternal(service, user_id, message):
    try:
        message = (service.users().messages().send(userId=user_id, body=message).execute())
        print('Message Id: %s' % message['id'])
        return message
    except errors.HttpError as error:
        print('An error occurred: %s' % error)
        return "Error"
    return "OK"

def CreateMessageHtml(sender, to, subject, msgHtml, msgPlain):
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = to
    msg.attach(MIMEText(msgPlain, 'plain'))
    msg.attach(MIMEText(msgHtml, 'html'))
    # Convert the email message to bytes
    raw_message_bytes = msg.as_bytes()
    # Encode the bytes to Base64 (urlsafe) and then decode to a string
    encoded_message_string = base64.urlsafe_b64encode(raw_message_bytes).decode('utf-8')
    return {'raw':encoded_message_string}

def createMessageWithAttachment(
    sender, to, subject, msgHtml, msgPlain, attachmentFile):
    """Create a message for an email.

    Args:
    sender: Email address of the sender.
    to: Email address of the receiver.
    subject: The subject of the email message.
    msgHtml: Html message to be sent
    msgPlain: Alternative plain text message for older email clients          
    attachmentFile: The path to the file to be attached.

    Returns:
    An object containing a base64url encoded email object.
    """
    message = MIMEMultipart('mixed')
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject

    messageA = MIMEMultipart('alternative')
    messageR = MIMEMultipart('related')

    messageR.attach(MIMEText(msgHtml, 'html'))
    messageA.attach(MIMEText(msgPlain, 'plain'))
    messageA.attach(messageR)

    message.attach(messageA)

    print("create_message_with_attachment: file: %s" % attachmentFile)
    content_type, encoding = mimetypes.guess_type(attachmentFile)

    if content_type is None or encoding is not None:
        content_type = 'application/octet-stream'
    main_type, sub_type = content_type.split('/', 1)
    if main_type == 'text':
        fp = open(attachmentFile, 'rb')
        msg = MIMEText(fp.read(), _subtype=sub_type)
        fp.close()
    elif main_type == 'image':
        fp = open(attachmentFile, 'rb')
        msg = MIMEImage(fp.read(), _subtype=sub_type)
        fp.close()
    elif main_type == 'audio':
        fp = open(attachmentFile, 'rb')
        msg = MIMEAudio(fp.read(), _subtype=sub_type)
        fp.close()
    else:
        fp = open(attachmentFile, 'rb')
        msg = MIMEBase(main_type, sub_type)
        msg.set_payload(fp.read())
        fp.close()
    filename = os.path.basename(attachmentFile)
    msg.add_header('Content-Disposition', 'attachment', filename=filename)
    message.attach(msg)

    return {'raw': base64.urlsafe_b64encode(message.as_string())}
# END oauth2


if __name__ == "__main__":
    args = sys.argv[3:]
    options = "a:"
    long_options = ["Send Alerts="]
    file_rulepattern = sys.argv[1]
    file_datapacket = sys.argv[2]
    # --- Configuration ---
    rulepatterns = get_file_content(file_rulepattern)
    datapackets = get_file_content(file_datapacket)
    alertmode = "alert_on" # alert_on alert_off
    recipient_email = "carol.on@gmail.com"
    ALERT_THRESHOLD = 80.0  # Percentage
    CHECK_INTERVAL_SECONDS = 10
        
    finance_ids = Customized_IDS()

    for rulepattern in rulepatterns.splitlines():
      finance_ids.add_rule(rulepattern)

    for datapacket in datapackets.splitlines():
      finance_ids.analyze_traffic(datapacket)

    if alertmode == "alert_on":
      alert_messages = finance_ids.get_alerts()
      if alert_messages:
        send_alert("Finance Dept. Intrusion Alert", "\n".join(alert_messages), recipient_email)


    logging.info("Starting system monitor...")
    while True:
        cpu_percent = psutil.cpu_percent(interval=1)
        logging.info("Current CPU Usage: %s%%", cpu_percent)

        if cpu_percent > ALERT_THRESHOLD:
            alert_message = f"HIGH CPU ALERT! Current usage is {cpu_percent}%."
            logging.warning(alert_message)
            send_alert("High CPU Alert", "\n".join(alert_message), recipient_email)

        time.sleep(CHECK_INTERVAL_SECONDS)
        
    try:
        arguments, values = getopt.getopt(args, options, long_options)
        for currentArg, currentVal in arguments:
            if currentArg in ("-a", "--Alerts"):    
                alertmode =currentVal     
    except getopt.error as err:
        print(str(err))
    

#END IDS

