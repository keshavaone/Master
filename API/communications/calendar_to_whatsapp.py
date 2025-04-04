import sys
import os
import datetime
from datetime import date, timedelta
import caldav
import pytz
# Import from the local modules
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)
import whatsapp
import icloud_calendar
from api.CONSTANTS import ICLOUD_USERNAME, ICLOUD_APP_PASSWORD, WHATSAPP_RECIPIENT, SMS_RECIPIENT
# iCloud Calendar credentials
ICLOUD_USERNAME = ICLOUD_USERNAME
ICLOUD_APP_PASSWORD = ICLOUD_APP_PASSWORD

# Message recipients
WHATSAPP_RECIPIENT = WHATSAPP_RECIPIENT
SMS_RECIPIENT = SMS_RECIPIENT

def get_calendar_events(days_ahead=2):
    """
    Get events from iCloud calendar including subscribed calendars
    
    Args:
        days_ahead (int): Number of days ahead to fetch events
    
    Returns:
        list: List of event details
    """
    try:
        # Get specific date based on days_ahead
        target_date = date.today() + timedelta(days=days_ahead)
        end_date = target_date + timedelta(days=1)
        
        # Convert to datetime objects with timezone for proper filtering
        target_datetime = datetime.datetime.combine(target_date, datetime.time.min)
        target_datetime = pytz.UTC.localize(target_datetime) if target_datetime.tzinfo is None else target_datetime
        
        end_datetime = datetime.datetime.combine(end_date, datetime.time.min)
        end_datetime = pytz.UTC.localize(end_datetime) if end_datetime.tzinfo is None else end_datetime
        
        all_event_details = []
        
        # 1. First get regular calendars
        client = caldav.DAVClient(
            url="https://caldav.icloud.com",
            username=ICLOUD_USERNAME,
            password=ICLOUD_APP_PASSWORD,
            ssl_verify_cert=True
        )
        
        # Get principal
        principal = client.principal()
        
        # List calendars
        calendars = principal.calendars()
        
        if calendars:
            # Process each calendar
            for cal_index, calendar in enumerate(calendars):
                print(f"{cal_index+1}. {calendar.name}")
                print(f"Processing calendar: {calendar.name}")
                
                # Get events only for the target date
                events = calendar.search(
                    start=target_date,
                    end=end_date,
                    expand=True
                )
                
                for event in events:
                    ical = event.icalendar_component
                    summary = ical.get('summary', 'No title')
                    start = ical.get('dtstart').dt if ical.get('dtstart') else 'N/A'
                    end = ical.get('dtend').dt if ical.get('dtend') else 'N/A'
                    location = ical.get('location', 'No location')
                    description = ical.get('description', 'No description')
                    
                    # Format datetime objects
                    if isinstance(start, datetime.datetime):
                        start_str = start.strftime('%Y-%m-%d %H:%M')
                    else:
                        start_str = start.strftime('%Y-%m-%d') if hasattr(start, 'strftime') else str(start)
                        
                    if isinstance(end, datetime.datetime):
                        end_str = end.strftime('%Y-%m-%d %H:%M')
                    else:
                        end_str = end.strftime('%Y-%m-%d') if hasattr(end, 'strftime') else str(end)
                    
                    all_event_details.append({
                        'summary': summary,
                        'start': start_str,
                        'end': end_str,
                        'location': location,
                        'description': description,
                        'calendar': calendar.name
                    })
        
        # 2. Now get subscribed calendars
        subscription_urls = icloud_calendar.get_subscription_urls()
        print(f"Found {len(subscription_urls)} subscribed calendars")
        
        for subscription in subscription_urls:
            print(f"Processing subscribed calendar: {subscription['name']}")
            
            subscription_events = icloud_calendar.get_events_from_subscription(
                subscription,
                start_date=target_datetime,
                end_date=end_datetime
            )
            
            for event in subscription_events:
                # Format datetime objects
                start = event.get('start')
                end = event.get('end')
                
                if isinstance(start, datetime.datetime):
                    start_str = start.strftime('%Y-%m-%d %H:%M')
                else:
                    start_str = start.strftime('%Y-%m-%d') if hasattr(start, 'strftime') else str(start)
                    
                if isinstance(end, datetime.datetime):
                    end_str = end.strftime('%Y-%m-%d %H:%M')
                else:
                    end_str = end.strftime('%Y-%m-%d') if hasattr(end, 'strftime') else str(end)
                
                all_event_details.append({
                    'summary': event.get('summary', 'No title'),
                    'start': start_str,
                    'end': end_str,
                    'location': event.get('location', 'No location'),
                    'description': event.get('description', 'No description'),
                    'calendar': event.get('calendar', 'External Calendar')
                })
                
        return all_event_details
    
    except Exception as e:
        print(f"Error fetching calendar events: {str(e)}")
        return []

def create_daily_summary(events, days_ahead=0, max_length=None):
    """
    Create a detailed daily summary message from calendar events
    
    Args:
        events (list): List of event details
        days_ahead (int): Number of days ahead for the summary (0 for today, 1 for tomorrow)
        max_length (int, optional): Maximum message length (removed limitation)
    
    Returns:
        str: Formatted summary message
    """
    if not events:
        if days_ahead == 0:
            return "😊 You have no events scheduled for today. Enjoy your free time!"
        else:
            return f"😊 You have no events scheduled for {days_ahead} day(s) ahead. Enjoy your free time!"
    
    target_date = date.today() + timedelta(days=days_ahead)
    
    if days_ahead == 0:
        title = f"📅 *DAILY SCHEDULE ({target_date.strftime('%a, %b %d')})* 📅\n\n"
    elif days_ahead == 1:
        title = f"📅 *TOMORROW'S SCHEDULE ({target_date.strftime('%a, %b %d')})* 📅\n\n"
    else:
        title = f"📅 *UPCOMING SCHEDULE ({target_date.strftime('%a, %b %d')})* 📅\n\n"
    
    message = title
    
    # Sort events by start time
    sorted_events = sorted(events, key=lambda x: x['start'])
    
    # Group events by calendar
    calendars = {}
    for event in sorted_events:
        cal_name = event.get('calendar', 'Default Calendar')
        if cal_name not in calendars:
            calendars[cal_name] = []
        calendars[cal_name].append(event)
    
    # Format events by calendar without length restrictions
    for cal_name, cal_events in calendars.items():
        # Highlight office calendar
        if cal_name == "SKF":
            cal_header = f"*📆 {cal_name} (OFFICE)*\n\n"
        else:
            cal_header = f"*📆 {cal_name}*\n\n"
            
        message += cal_header
        
        for i, event in enumerate(cal_events, 1):
            # Create event entry with all information
            if cal_name == "SKF":
                event_title = f"*{i}. {event['summary']} 🏢*\n"
            else:
                event_title = f"*{i}. {event['summary']}*\n"
                
            event_time = f"⏰ {event['start']} - {event['end']}\n"
            
            # Add location only if it exists and isn't the default
            location_text = ""
            if event['location'] and event['location'] != 'No location':
                location_text = f"📍 {event['location']}\n"
                
            # Add the full description if it exists and isn't the default
            description_text = ""
            if event['description'] and event['description'] != 'No description':
                description_text = f"📝 {event['description']}\n"
                
            event_text = event_title + event_time + location_text + description_text + "\n"
            message += event_text
    
    # Add footer
    message += "Have a productive day! 🌟"
        
    return message

def send_calendar_summary(days_ahead=1, method="whatsapp", recipient=None):
    """
    Send calendar summary using the specified method
    
    Args:
        days_ahead (int): Number of days ahead to fetch events (default is 1)
        method (str): Messaging method to use ("whatsapp", "sms", or "both")
        recipient (str, optional): Override the default recipient number
    
    Returns:
        dict: Dictionary with results for each method used
    """
    events = get_calendar_events(days_ahead=days_ahead)
    summary = create_daily_summary(events, days_ahead=days_ahead)
    results = {}
    
    # Determine which recipient to use
    whatsapp_to = recipient if recipient else WHATSAPP_RECIPIENT
    sms_to = recipient if recipient else SMS_RECIPIENT
    
    # Send via requested method(s)
    if method.lower() in ["whatsapp", "both"]:
        results["whatsapp"] = whatsapp.send_whatsapp_message(summary, whatsapp_to)
    
    if method.lower() in ["sms", "both"]:
        results["sms"] = whatsapp.send_sms_message(summary, sms_to)
    
    return results

def add_subscription_calendar(name, url):
    """
    Add a subscription calendar to be included in events
    
    Args:
        name (str): Name of the calendar
        url (str): URL to the iCal feed
        
    Returns:
        bool: True if successful, False otherwise
    """
    return icloud_calendar.add_manual_subscription(name, url)
    
def remove_subscription_calendar(url_or_name):
    """
    Remove a subscription calendar by URL or name
    
    Args:
        url_or_name (str): URL or name of the calendar to remove
        
    Returns:
        bool: True if successful, False otherwise
    """
    return icloud_calendar.remove_manual_subscription(url_or_name)
    
def list_subscription_calendars():
    """
    List all subscription calendars
    
    Returns:
        list: List of subscription calendars
    """
    return icloud_calendar.get_subscription_urls()

if __name__ == "__main__":
    # Check if script was called with arguments
    import sys
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        # Add a subscription calendar
        if command == 'add-subscription' and len(sys.argv) >= 4:
            calendar_name = sys.argv[2]
            calendar_url = sys.argv[3]
            success = add_subscription_calendar(calendar_name, calendar_url)
            if success:
                print(f"Successfully added subscription calendar: {calendar_name}")
            else:
                print(f"Failed to add subscription calendar: {calendar_name}")
        
        # Remove a subscription calendar
        elif command == 'remove-subscription' and len(sys.argv) >= 3:
            calendar_name_or_url = sys.argv[2]
            success = remove_subscription_calendar(calendar_name_or_url)
            if success:
                print(f"Successfully removed subscription calendar: {calendar_name_or_url}")
            else:
                print(f"Failed to remove subscription calendar: {calendar_name_or_url}")
        
        # List all subscription calendars
        elif command == 'list-subscriptions':
            subscriptions = list_subscription_calendars()
            if subscriptions:
                print(f"Found {len(subscriptions)} subscription calendars:")
                for i, sub in enumerate(subscriptions):
                    print(f"{i+1}. {sub['name']}: {sub['url']}")
            else:
                print("No subscription calendars found")
        
        # Send calendar summary for specific days ahead
        elif command == 'send-summary' and len(sys.argv) >= 3:
            try:
                days = int(sys.argv[2])
                
                # Check if method is specified
                method = "whatsapp"  # Default method
                if len(sys.argv) >= 4:
                    method = sys.argv[3].lower()
                    if method not in ["whatsapp", "sms", "both"]:
                        print("Error: method must be 'whatsapp', 'sms', or 'both'")
                        sys.exit(1)
                
                # Check if recipient is specified
                recipient = None
                if len(sys.argv) >= 5:
                    recipient = sys.argv[4]
                
                results = send_calendar_summary(days_ahead=days, method=method, recipient=recipient)
                
                # Report results
                success = False
                for method_name, sid in results.items():
                    if sid:
                        print(f"Successfully sent {method_name.upper()} message with calendar summary for {days} day(s) ahead. SID: {sid}")
                        success = True
                    else:
                        print(f"Failed to send {method_name.upper()} message with calendar summary.")
                
                if not success:
                    print("Failed to send any messages with calendar summary.")
            except ValueError:
                print("Error: days_ahead must be a number")
        else:
            print("Usage:")
            print("  python calendar_to_whatsapp.py add-subscription <name> <url>")
            print("  python calendar_to_whatsapp.py remove-subscription <name or url>")
            print("  python calendar_to_whatsapp.py list-subscriptions")
            print("  python calendar_to_whatsapp.py send-summary <days_ahead> [method] [recipient]")
            print("")
            print("  Method options: 'whatsapp' (default), 'sms', or 'both'")
    else:
        # Default behavior: Send tomorrow's calendar summary via WhatsApp
        results = send_calendar_summary(days_ahead=0, method="whatsapp")
        if results.get("whatsapp"):
            print(f"Successfully sent WhatsApp message with tomorrow's calendar summary. SID: {results['whatsapp']}")
        else:
            print("Failed to send WhatsApp message with calendar summary.")