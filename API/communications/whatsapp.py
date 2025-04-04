from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException
from datetime import datetime
import json
import time
from api.CONSTANTS import (
    TWILIO_SID,
    TWILIO_TOKEN,
    TWILIO_PHNO,
    TWILIO_WHATSAPP_NO
)

# Your Twilio credentials
account_sid = TWILIO_SID
auth_token = TWILIO_TOKEN

# Twilio phone number for SMS
TWILIO_PHONE_NUMBER = TWILIO_PHNO  # Your Twilio phone number for SMS

# Initialize the Twilio client
client = Client(account_sid, auth_token)

def check_message_status(message_sid, max_attempts=5):
    """
    Check the status of a sent message
    
    Args:
        message_sid (str): The SID of the message to check
        max_attempts (int): Maximum number of status check attempts
        
    Returns:
        dict: Message status details
    """
    attempts = 0
    while attempts < max_attempts:
        try:
            message = client.messages(message_sid).fetch()
            print(f"Message status: {message.status}, Error code: {message.error_code}, Error message: {message.error_message}")
            
            if message.status in ['delivered', 'read']:
                return {
                    'success': True,
                    'status': message.status
                }
            elif message.status in ['failed', 'undelivered']:
                return {
                    'success': False,
                    'status': message.status,
                    'error_code': message.error_code,
                    'error_message': message.error_message
                }
                
            # Still processing, wait and try again
            attempts += 1
            time.sleep(2)
        except Exception as e:
            print(f"Error checking message status: {str(e)}")
            return {
                'success': False,
                'status': 'error',
                'error_message': str(e)
            }
    
    # If we get here, we've exceeded maximum attempts
    return {
        'success': False,
        'status': 'timeout',
        'error_message': 'Exceeded maximum status check attempts'
    }

def send_sms_message(message_text, to_number):
    """
    Send an SMS message using Twilio
    
    Args:
        message_text (str): The message text to send
        to_number (str): The phone number to send to (including country code)
    
    Returns:
        str: The message SID if successful
    """
    # SMS has much stricter character limits than WhatsApp
    # For safety, keep each SMS under 140 characters
    SMS_CHAR_LIMIT = 140
    
    # Make sure the phone number is in the right format
    if not to_number.startswith('+'):
        to_number = f'+{to_number}'
    
    print(f"Sending SMS message to: {to_number}")
    print(f"Message length: {len(message_text)} characters")
    
    try:
        # For SMS, we need to create a simplified version of the message
        # Calendar summaries are too long for SMS
        lines = message_text.split('\n')
        title = next((line for line in lines if "*DAILY SCHEDULE" in line or "*TOMORROW'S SCHEDULE" in line or "*UPCOMING SCHEDULE" in line), "Calendar Summary")
        title = title.replace('*', '').replace('📅', '')
        
        # Extract event count
        event_count = 0
        for line in lines:
            if line.strip().startswith('*') and '. ' in line and not line.startswith('*📆'):
                event_count += 1
        
        # Create a simplified SMS message
        simplified_message = f"{title.strip()}\n\n"
        simplified_message += f"You have {event_count} events scheduled.\n"
        simplified_message += "Check WhatsApp for full details."
        
        # Message is short enough to send as is
        message = client.messages.create(
            body=simplified_message,
            from_=TWILIO_PHONE_NUMBER,
            to=to_number
        )
        print(f"SMS sent with SID: {message.sid}")
        
        # Check message status
        status = check_message_status(message.sid)
        if not status['success']:
            print(f"SMS delivery issue: {status.get('status')}: {status.get('error_message')}")
            
            # If failed due to country mismatch, try a fallback approach
            if status.get('error_code') == '21659':
                print("Country code mismatch detected. You may need to purchase a Twilio number for the recipient's country.")
                print("Or use the WhatsApp channel which doesn't have this restriction.")
        
        return message.sid
    except TwilioRestException as e:
        error_code = getattr(e, 'code', None)
        error_msg = getattr(e, 'msg', str(e))
        print(f"Error sending SMS: {error_msg}")
        
        if error_code == 21659:
            print("Country code mismatch detected. You may need to purchase a Twilio number for the recipient's country.")
            print("Or use the WhatsApp channel which doesn't have this restriction.")
        elif error_code == 21608:
            print("This Twilio account is not authorized to send messages to this region.")
            print("Consider using the WhatsApp channel instead.")
        
        return None
    except Exception as e:
        print(f"Unexpected error sending SMS: {str(e)}")
        return None

def send_whatsapp_message(message_text, to_number):
    """
    Send a WhatsApp message using Twilio
    
    Args:
        message_text (str): The message text to send
        to_number (str): The phone number to send to (including country code)
    
    Returns:
        str: The message SID if successful
    """
    # Twilio's WhatsApp has a 1600 character limit per message
    MAX_CHAR_LIMIT = 1600
    
    # Make sure the phone number is in the right format
    if not to_number.startswith('+'):
        to_number = f'+{to_number}'
    
    print(f"Sending WhatsApp message to: {to_number}")
    print(f"Message length: {len(message_text)} characters")
    
    try:
        # Always split the message into manageable chunks (Twilio WhatsApp has hard 1600 char limit)
        # We'll use 1500 to leave room for chunk markers
        CHUNK_SIZE = 1500
        
        # Check if we need to split
        if len(message_text) <= CHUNK_SIZE:
            # Message is short enough to send as is
            message = client.messages.create(
                from_=TWILIO_WHATSAPP_NO,
                body=message_text,
                to=f'whatsapp:{to_number}'
            )
            print(f"Message sent with SID: {message.sid}")
            
            # Check message status
            status = check_message_status(message.sid)
            if not status['success']:
                print(f"Message delivery issue: {status.get('status')}: {status.get('error_message')}")
                
                # If WhatsApp template error, try with a simple message
                if status.get('error_code') == '63016':
                    print("Trying with a simple message due to template restrictions...")
                    simple_message = "Your calendar summary is ready. Please reply to this message to view updates."
                    backup_message = client.messages.create(
                        from_='whatsapp:+14155238886',
                        body=simple_message,
                        to=f'whatsapp:{to_number}'
                    )
                    print(f"Simple message sent with SID: {backup_message.sid}")
                    return backup_message.sid
            
            return message.sid
        else:
            # Need to split the message intelligently
            print(f"Message length ({len(message_text)} chars) exceeds limit. Splitting into chunks...")
            
            # Split message at natural boundaries (paragraphs, line breaks)
            chunks = []
            current_chunk = ""
            for line in message_text.split('\n'):
                # If adding this line would exceed chunk size, start a new chunk
                if len(current_chunk) + len(line) + 1 > CHUNK_SIZE:
                    # If current chunk is not empty, add it to chunks
                    if current_chunk:
                        chunks.append(current_chunk)
                    
                    # If this single line is longer than a chunk, split it by character
                    if len(line) > CHUNK_SIZE:
                        # Split the line into chunks of CHUNK_SIZE characters
                        line_chunks = [line[i:i+CHUNK_SIZE] for i in range(0, len(line), CHUNK_SIZE)]
                        chunks.extend(line_chunks[:-1])  # Add all but the last line chunk
                        current_chunk = line_chunks[-1]  # Start a new chunk with the last line chunk
                    else:
                        current_chunk = line
                else:
                    # Add to current chunk if not first line in chunk
                    if current_chunk:
                        current_chunk += '\n' + line
                    else:
                        current_chunk = line
            
            # Add the last chunk if not empty
            if current_chunk:
                chunks.append(current_chunk)
            
            print(f"Split into {len(chunks)} natural chunks")
            
            # Now send each chunk with a counter
            last_sid = None
            for i, chunk in enumerate(chunks, 1):
                # Add chunk indicator
                chunk_header = f"📄 *Part {i}/{len(chunks)}*\n\n"
                chunk_text = chunk_header + chunk
                
                # Ensure we don't exceed the limit
                if len(chunk_text) > MAX_CHAR_LIMIT:
                    chunk_text = chunk_text[:MAX_CHAR_LIMIT - 10] + "..."
                
                try:
                    message = client.messages.create(
                        from_='whatsapp:+14155238886',
                        body=chunk_text,
                        to=f'whatsapp:{to_number}'
                    )
                    print(f"Chunk {i}/{len(chunks)} sent with SID: {message.sid}")
                    last_sid = message.sid
                    
                    # Give WhatsApp time to process between chunks
                    time.sleep(2)
                except TwilioRestException as e:
                    print(f"Error sending chunk {i}: {str(e)}")
                    # Continue with next chunk even if this one fails
            
            return last_sid
    except TwilioRestException as e:
        print(f"Error sending WhatsApp message: {str(e)}")
        print(f"Error code: {e.code}, Twilio error: {e.msg}")
        return None
    except Exception as e:
        print(f"Unexpected error sending WhatsApp message: {str(e)}")
        return None