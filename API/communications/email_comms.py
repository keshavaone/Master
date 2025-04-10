import imaplib
import email
import smtplib
from email.header import decode_header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import getpass

class EmailClient:
    # Common IMAP and SMTP server configurations
    EMAIL_PROVIDERS = {
        'gmail': {
            'imap_server': 'imap.gmail.com',
            'imap_port': 993,
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': 587
        },
        'outlook': {
            'imap_server': 'outlook.office365.com',
            'imap_port': 993,
            'smtp_server': 'smtp.office365.com',
            'smtp_port': 587
        },
        'yahoo': {
            'imap_server': 'imap.mail.yahoo.com',
            'imap_port': 993,
            'smtp_server': 'smtp.mail.yahoo.com',
            'smtp_port': 587
        },
        'icloud': {
            'imap_server': 'imap.mail.me.com',
            'imap_port': 993,
            'smtp_server': 'smtp.mail.me.com',
            'smtp_port': 587
        }
    }
    
    def __init__(self, email_address, password, provider=None):
        self.email_address = email_address
        self.password = password
        
        # Auto-detect provider from email if not specified
        if not provider:
            domain = email_address.split('@')[1].lower()
            if 'gmail' in domain:
                provider = 'gmail'
            elif 'outlook' in domain or 'hotmail' in domain or 'live' in domain:
                provider = 'outlook'
                print('The provider is Outlook.')
            elif 'yahoo' in domain:
                provider = 'yahoo'
            elif 'icloud' in domain or 'me.com' in domain:
                provider = 'icloud'
            else:
                # Default to custom configuration that will be set later
                provider = 'custom'
        
        self.provider = provider
        self.imap_connection = None
        
        # Set server configurations
        if provider in self.EMAIL_PROVIDERS:
            self.imap_server = self.EMAIL_PROVIDERS[provider]['imap_server']
            self.imap_port = self.EMAIL_PROVIDERS[provider]['imap_port']
            self.smtp_server = self.EMAIL_PROVIDERS[provider]['smtp_server']
            self.smtp_port = self.EMAIL_PROVIDERS[provider]['smtp_port']
        else:
            # Will be set by set_custom_servers method
            self.imap_server = None
            self.imap_port = None
            self.smtp_server = None
            self.smtp_port = None
        print(f"Provider: {provider}")
        print(f"IMAP Server: {self.imap_server}")
        print(f"IMAP Port: {self.imap_port}")
        print(f"SMTP Server: {self.smtp_server}")
        print(f"SMTP Port: {self.smtp_port}")
        print(f"Email Address: {self.email_address}")
        print(f"Password: {self.password}")
    
    def set_custom_servers(self, imap_server, imap_port=993, smtp_server=None, smtp_port=587):
        """Set custom server information for providers not in the predefined list"""
        self.imap_server = imap_server
        self.imap_port = imap_port
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
    
    def connect(self):
        """Connect to the email server"""
        try:
            # Connect to IMAP server
            self.imap_connection = imaplib.IMAP4_SSL(self.imap_server, self.imap_port)
            
            # For Outlook specifically
            if self.provider == 'outlook':
                # Outlook with app password uses standard login but needs exact formatting
                try: 
                    # Try standard login method for app-specific passwords
                    # Strip spaces from password for Outlook app passwords
                    password_no_spaces = self.password.replace(' ', '')
                    self.imap_connection.login(self.email_address, password_no_spaces)
                except Exception as e:
                    print(f"Outlook login error: {e}")
                    print("For Outlook app passwords, ensure there are no spaces in the password.")
                    raise
            else:
                # For other providers like Gmail, Yahoo, etc.
                try:
                    self.imap_connection.login(self.email_address, self.password)
                except imaplib.IMAP4.error as e:
                    # If login failed and it's Gmail (which might need OAuth2)
                    if 'gmail' in self.provider:
                        print("Regular login failed, trying OAuth2 authentication...")
                        # Try with oauth method if supported by server
                        oauth_string = f'user={self.email_address}\1auth=Bearer {self.password}\1\1'
                        self.imap_connection.authenticate('XOAUTH2', lambda x: oauth_string)
                    else:
                        # Re-raise the original error
                        raise e
            
            return True
        except Exception as e:
            print(f"Connection error: {e}")
            print("For app-specific passwords: ensure it is correct, has no spaces, and hasn't expired.")
            return False
    
    def disconnect(self):
        """Disconnect from the email server"""
        if self.imap_connection:
            try:
                self.imap_connection.close()
                self.imap_connection.logout()
            except:
                pass
            self.imap_connection = None
    
    def get_folders(self):
        """Get all available folders/mailboxes"""
        if not self.imap_connection:
            if not self.connect():
                return []
        
        folders = []
        try:
            result, mailboxes = self.imap_connection.list()
            if result == 'OK':
                for mailbox in mailboxes:
                    decoded = mailbox.decode('utf-8')
                    if '"/"' in decoded:  # Skip namespace identifiers
                        folder = decoded.split('"/"')[-1].strip().strip('"')
                        folders.append(folder)
                    elif '"."' in decoded:  # Some servers use . as separator
                        folder = decoded.split('"."')[-1].strip().strip('"')
                        folders.append(folder)
        except Exception as e:
            print(f"Error getting folders: {e}")
        
        return folders
    
    def get_emails(self, folder="INBOX", limit=10, unread_only=False, search_criteria=None):
        """Get emails from the specified folder"""
        if not self.imap_connection:
            if not self.connect():
                return []
        
        emails = []
        try:
            # Select the mailbox
            result, data = self.imap_connection.select(folder)
            if result != 'OK':
                print(f"Error selecting folder {folder}")
                return []
            
            # Search for emails
            if search_criteria:
                result, messages = self.imap_connection.search(None, search_criteria)
            elif unread_only:
                result, messages = self.imap_connection.search(None, 'UNSEEN')
            else:
                result, messages = self.imap_connection.search(None, 'ALL')
            
            if result != 'OK':
                print("Error searching emails")
                return []
            
            # Get message IDs
            message_ids = messages[0].split()
            
            # Process the most recent emails (up to limit)
            for i in range(min(limit, len(message_ids))):
                # Get the latest email (count backwards)
                msg_id = message_ids[len(message_ids) - 1 - i]
                
                try:
                    # Fetch the email
                    result, msg_data = self.imap_connection.fetch(msg_id, "(RFC822)")
                    if result != 'OK':
                        continue
                    
                    # Parse the email content
                    msg = email.message_from_bytes(msg_data[0][1])
                    
                    # Get email ID
                    email_id = msg_id.decode('utf-8')
                    
                    # Get subject
                    subject = ""
                    subject_header = msg.get("Subject", "")
                    if subject_header:
                        subject_parts = decode_header(subject_header)
                        subject = self._decode_header_part(subject_parts[0])
                    
                    # Get sender
                    from_ = ""
                    from_header = msg.get("From", "")
                    if from_header:
                        from_parts = decode_header(from_header)
                        from_ = self._decode_header_part(from_parts[0])
                    
                    # Get date
                    date = msg.get("Date", "")
                    
                    # Get body
                    body = self._get_email_body(msg)
                    
                    # Get attachments info
                    attachments = self._get_attachments_info(msg)
                    
                    # Add to our list of emails
                    emails.append({
                        "id": email_id,
                        "subject": subject,
                        "from": from_,
                        "date": date,
                        "body": body,
                        "has_attachments": len(attachments) > 0,
                        "attachments": attachments
                    })
                except Exception as e:
                    print(f"Error processing email {msg_id}: {e}")
                    continue
        except Exception as e:
            print(f"Error getting emails: {e}")
        
        return emails
    
    def _decode_header_part(self, header_part):
        """Decode a header part"""
        value, encoding = header_part
        if isinstance(value, bytes):
            return value.decode(encoding if encoding else 'utf-8', errors='replace')
        return value
    
    def _get_email_body(self, msg):
        """Extract the email body text"""
        body = ""
        
        if msg.is_multipart():
            # If message has multiple parts, get the text from the first text/plain part
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                
                # Skip attachments
                if "attachment" in content_disposition:
                    continue
                
                # Get the email body text
                if content_type == "text/plain":
                    try:
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset() or 'utf-8'
                        body = payload.decode(charset, errors='replace')
                        break
                    except:
                        continue
            
            # If no text/plain found, try with text/html
            if not body:
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get("Content-Disposition"))
                    
                    if "attachment" in content_disposition:
                        continue
                    
                    if content_type == "text/html":
                        try:
                            payload = part.get_payload(decode=True)
                            charset = part.get_content_charset() or 'utf-8'
                            body = payload.decode(charset, errors='replace')
                            # You could convert HTML to plain text here if needed
                            break
                        except:
                            continue
        else:
            # If message isn't multipart, just get the payload
            try:
                payload = msg.get_payload(decode=True)
                charset = msg.get_content_charset() or 'utf-8'
                body = payload.decode(charset, errors='replace')
            except:
                body = "Could not decode email body"
        
        return body
    
    def _get_attachments_info(self, msg):
        """Get information about attachments"""
        attachments = []
        
        if msg.is_multipart():
            for part in msg.walk():
                content_disposition = str(part.get("Content-Disposition"))
                
                if "attachment" in content_disposition:
                    filename = part.get_filename()
                    if filename:
                        # Decode filename if needed
                        if isinstance(filename, str):
                            filename_parts = decode_header(filename)
                            filename = self._decode_header_part(filename_parts[0])
                        
                        content_type = part.get_content_type()
                        size = len(part.get_payload(decode=True))
                        
                        attachments.append({
                            "filename": filename,
                            "content_type": content_type,
                            "size": size
                        })
        
        return attachments
    
    def send_email(self, to_addresses, subject, body, cc_addresses=None, bcc_addresses=None, html_body=None):
        """Send an email"""
        if not self.smtp_server:
            print("SMTP server not configured")
            return False
        
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['From'] = self.email_address
            
            if isinstance(to_addresses, list):
                msg['To'] = ", ".join(to_addresses)
            else:
                msg['To'] = to_addresses
            
            if cc_addresses:
                if isinstance(cc_addresses, list):
                    msg['Cc'] = ", ".join(cc_addresses)
                else:
                    msg['Cc'] = cc_addresses
            
            if bcc_addresses:
                if isinstance(bcc_addresses, list):
                    msg['Bcc'] = ", ".join(bcc_addresses)
                else:
                    msg['Bcc'] = bcc_addresses
            
            msg['Subject'] = subject
            
            # Attach parts
            if body:
                msg.attach(MIMEText(body, 'plain'))
            
            if html_body:
                msg.attach(MIMEText(html_body, 'html'))
            
            # Connect to SMTP server
            smtp = smtplib.SMTP(self.smtp_server, self.smtp_port)
            smtp.ehlo()
            smtp.starttls()
            
            # Try to login with enhanced error handling for app-specific passwords
            try:
                # For Outlook specifically, additional handling
                if self.provider == 'outlook':
                    # Ensure password has no spaces for Outlook app passwords
                    password_no_spaces = self.password.replace(' ', '')
                    smtp.login(self.email_address, password_no_spaces)
                else:
                    smtp.login(self.email_address, self.password)
            except smtplib.SMTPAuthenticationError as e:
                print(f"SMTP Authentication error: {e}")
                raise Exception("Authentication failed. For app-specific passwords, ensure they are correctly formatted without spaces and haven't expired.")
            
            # Get all recipients
            all_recipients = []
            if isinstance(to_addresses, list):
                all_recipients.extend(to_addresses)
            else:
                all_recipients.append(to_addresses)
            
            if cc_addresses:
                if isinstance(cc_addresses, list):
                    all_recipients.extend(cc_addresses)
                else:
                    all_recipients.append(cc_addresses)
            
            if bcc_addresses:
                if isinstance(bcc_addresses, list):
                    all_recipients.extend(bcc_addresses)
                else:
                    all_recipients.append(bcc_addresses)
            
            # Send email
            smtp.sendmail(self.email_address, all_recipients, msg.as_string())
            smtp.quit()
            
            return True
        except Exception as e:
            print(f"Error sending email: {e}")
            return False


# Example usage
def main():
    print("Email Client")
    print("============")
    
    # Get user input
    # email = input("Enter your email address: ")
    email = 'iamkeshavrao@outlook.com'
    # password = getpass.getpass("Enter your password (or app-specific password): ")
    password = 'agmwafappzwnzztw'
    # Create client
    # For Outlook app-specific passwords, sometimes removing spaces helps
    password = password.replace(' ', '')
    client = EmailClient(email, password)
    
    # If it's a custom provider, ask for server details
    if client.provider == 'custom':
        print("\nYour email provider was not automatically recognized.")
        imap_server = input("Enter IMAP server (e.g., mail.example.com): ")
        imap_port = input("Enter IMAP port [993]: ") or 993
        smtp_server = input("Enter SMTP server (e.g., smtp.example.com): ")
        smtp_port = input("Enter SMTP port [587]: ") or 587
        
        client.set_custom_servers(imap_server, int(imap_port), smtp_server, int(smtp_port))
    
    # Connect to email server
    print("\nConnecting to email server...")
    if not client.connect():
        print("Failed to connect. Please check your credentials and server settings.")
        return
    
    print("Connected successfully!")
    
    # Get folders
    print("\nFetching folders...")
    folders = client.get_folders()
    print("Available folders:")
    for i, folder in enumerate(folders):
        print(f"{i+1}. {folder}")
    
    # Choose a folder
    folder_choice = input("\nEnter folder number to view (default is INBOX): ")
    if folder_choice.isdigit() and 1 <= int(folder_choice) <= len(folders):
        selected_folder = folders[int(folder_choice) - 1]
    else:
        selected_folder = "INBOX"
    
    # Get emails
    print(f"\nFetching emails from {selected_folder}...")
    emails = client.get_emails(folder=selected_folder, limit=10)
    
    if not emails:
        print("No emails found.")
    else:
        print(f"Found {len(emails)} emails:")
        for i, email_data in enumerate(emails):
            print(f"\nEmail {i+1}:")
            print(f"From: {email_data['from']}")
            print(f"Subject: {email_data['subject']}")
            print(f"Date: {email_data['date']}")
            print(f"Has Attachments: {'Yes' if email_data['has_attachments'] else 'No'}")
            
            # Show a preview of the body
            body_preview = email_data['body'][:150] + "..." if len(email_data['body']) > 150 else email_data['body']
            print(f"Body Preview: {body_preview}")
    
    # Disconnect
    client.disconnect()
    print("\nDisconnected from email server.")


if __name__ == "__main__":
    main()