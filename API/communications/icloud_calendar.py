
import caldav
import logging
import requests
import icalendar
from datetime import datetime, timedelta
import pytz
import os
import json
from api.CONSTANTS import ICLOUD_USERNAME, ICLOUD_APP_PASSWORD, WHATSAPP_RECIPIENT, SMS_RECIPIENT

# Set up logging to see detailed connection information
logging.basicConfig(level=logging.DEBUG)

# Your credentials
username = ICLOUD_USERNAME
app_specific_password = ICLOUD_APP_PASSWORD

def get_caldav_client():
    """Create and return a CalDAV client connected to iCloud"""
    client = caldav.DAVClient(
        url="https://caldav.icloud.com",
        username=username,
        password=app_specific_password,
        ssl_verify_cert=True
    )
    return client

def get_all_calendars():
    """Get all calendars from iCloud account including subscribed calendars"""
    try:
        client = get_caldav_client()
        principal = client.principal()
        calendars = principal.calendars()
        
        print(f"Found {len(calendars)} calendars:")
        for i, calendar in enumerate(calendars):
            print(f"{i+1}. {calendar.name}")
            # Check if this is a subscription
            try:
                props = calendar.get_properties(["{http://calendarserver.org/ns/}subscribed-url"])
                sub_url = props.get("{http://calendarserver.org/ns/}subscribed-url")
                if sub_url:
                    print(f"   - Subscription URL: {sub_url}")
            except:
                pass  # Not a subscription or can't get subscription URL
                
        return calendars
    except Exception as e:
        print(f"Error getting calendars: {str(e)}")
        return []

def get_subscription_urls():
    """
    Extract subscription URLs from iCloud calendars
    If none are found via CalDAV, returns a list of manually configured subscriptions
    """
    try:
        client = get_caldav_client()
        principal = client.principal()
        calendars = principal.calendars()
        
        subscription_urls = []
        
        # Try to get subscriptions via CalDAV
        for calendar in calendars:
            try:
                props = calendar.get_properties(["{http://calendarserver.org/ns/}subscribed-url"])
                sub_url = props.get("{http://calendarserver.org/ns/}subscribed-url")
                if sub_url:
                    subscription_urls.append({
                        "name": calendar.name,
                        "url": sub_url
                    })
            except:
                pass  # Not a subscription or can't get subscription URL
        
        # If no subscriptions found via CalDAV, use manually configured subscriptions
        if not subscription_urls:
            # Load subscriptions from config file if it exists
            config_dir = os.path.dirname(os.path.abspath(__file__))
            config_path = os.path.join(config_dir, 'calendar_subscriptions.json')
            
            if os.path.exists(config_path):
                try:
                    with open(config_path, 'r') as f:
                        manual_subscriptions = json.load(f)
                        subscription_urls.extend(manual_subscriptions)
                except Exception as e:
                    print(f"Error loading subscription config: {str(e)}")
            else:
                # Default subscriptions - you may add some defaults here
                manual_subscriptions = [
                    # Example: 
                    # {"name": "External Calendar", "url": "https://calendar.google.com/calendar/ical/example%40gmail.com/public/basic.ics"},
                ]
                subscription_urls.extend(manual_subscriptions)
                
        return subscription_urls
    except Exception as e:
        print(f"Error getting subscription URLs: {str(e)}")
        return []

# Function to manage manual calendar subscriptions
def add_manual_subscription(name, url):
    """
    Add a manual calendar subscription and save to configuration file
    
    Args:
        name (str): Name of the calendar
        url (str): URL to the iCal feed
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Verify URL is valid by fetching it
        ical_data = fetch_ical_from_url(url)
        if not ical_data:
            print(f"Error: Could not fetch calendar data from {url}")
            return False
            
        # Parse to verify it's a valid iCal feed
        calendar = icalendar.Calendar.from_ical(ical_data)
        
        # Save to configuration file
        config_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(config_dir, 'calendar_subscriptions.json')
        
        subscriptions = []
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    subscriptions = json.load(f)
            except Exception as e:
                print(f"Warning: Could not load existing subscriptions: {str(e)}")
        
        # Check if subscription already exists
        for i, sub in enumerate(subscriptions):
            if sub.get('url') == url:
                # Update existing subscription
                subscriptions[i] = {"name": name, "url": url}
                break
        else:
            # Add new subscription
            subscriptions.append({"name": name, "url": url})
        
        # Save the updated subscriptions list
        with open(config_path, 'w') as f:
            json.dump(subscriptions, f, indent=2)
        
        print(f"Successfully added calendar subscription: {name}")
        return True
    except Exception as e:
        print(f"Error adding manual subscription: {str(e)}")
        return False

def remove_manual_subscription(url_or_name):
    """
    Remove a manual calendar subscription by URL or name
    
    Args:
        url_or_name (str): URL or name of the calendar to remove
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        config_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(config_dir, 'calendar_subscriptions.json')
        
        if not os.path.exists(config_path):
            print("No subscriptions configuration file found")
            return False
        
        with open(config_path, 'r') as f:
            subscriptions = json.load(f)
        
        original_count = len(subscriptions)
        
        # Filter out the subscription to remove
        subscriptions = [sub for sub in subscriptions 
                        if sub.get('url') != url_or_name and sub.get('name') != url_or_name]
        
        if len(subscriptions) == original_count:
            print(f"No subscription found with URL or name: {url_or_name}")
            return False
        
        # Save the updated subscriptions list
        with open(config_path, 'w') as f:
            json.dump(subscriptions, f, indent=2)
        
        print(f"Successfully removed calendar subscription: {url_or_name}")
        return True
    except Exception as e:
        print(f"Error removing manual subscription: {str(e)}")
        return False

def fetch_ical_from_url(url):
    """Fetch calendar data directly from a subscription URL"""
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.text
        else:
            print(f"Failed to fetch calendar data: {response.status_code}")
            return None
    except Exception as e:
        print(f"Error fetching calendar data: {str(e)}")
        return None

def parse_ical_data(ical_data, calendar_name="External Calendar"):
    """Parse iCalendar data and return events"""
    if not ical_data:
        return []
        
    events = []
    try:
        calendar = icalendar.Calendar.from_ical(ical_data)
        
        for component in calendar.walk():
            if component.name == "VEVENT":
                # Extract event details
                summary = str(component.get('summary', 'No Title'))
                
                # Handle start date/time
                dtstart = component.get('dtstart')
                start_dt = dtstart.dt if dtstart else None
                
                # Handle end date/time
                dtend = component.get('dtend')
                end_dt = dtend.dt if dtend else None
                
                # If only start date is provided with no end date
                if end_dt is None and start_dt is not None:
                    if isinstance(start_dt, datetime):
                        # For datetime, assume 1 hour duration
                        end_dt = start_dt + timedelta(hours=1)
                    else:
                        # For date, assume all-day event
                        end_dt = start_dt
                
                # Get other properties
                location = str(component.get('location', 'No Location'))
                description = str(component.get('description', 'No Description'))
                
                events.append({
                    'summary': summary,
                    'start': start_dt,
                    'end': end_dt,
                    'location': location,
                    'description': description,
                    'calendar': calendar_name
                })
        
        return events
    except Exception as e:
        print(f"Error parsing iCalendar data: {str(e)}")
        return []

def get_events_from_subscription(subscription_info, start_date=None, end_date=None):
    """Get events from a calendar subscription"""
    url = subscription_info.get("url")
    name = subscription_info.get("name", "External Calendar")
    
    if not url:
        return []
    
    ical_data = fetch_ical_from_url(url)
    events = parse_ical_data(ical_data, name)
    
    # Filter by date range if specified
    if start_date or end_date:
        filtered_events = []
        for event in events:
            event_start = event.get('start')
            
            # Skip events with no start date
            if not event_start:
                continue
                
            # Check start date
            if start_date and event_start < start_date:
                continue
                
            # Check end date
            if end_date and event_start > end_date:
                continue
                
            filtered_events.append(event)
        return filtered_events
    
    return events

if __name__ == "__main__":
    # Get all calendars including subscriptions
    calendars = get_all_calendars()
    
    # Get subscription URLs
    subscription_urls = get_subscription_urls()
    print(f"\nFound {len(subscription_urls)} calendar subscriptions:")
    for i, sub in enumerate(subscription_urls):
        print(f"{i+1}. {sub['name']}: {sub['url']}")
    
    # Get events from a subscription (using the first one as example)
    if subscription_urls:
        print(f"\nFetching events from subscription: {subscription_urls[0]['name']}")
        today = datetime.now(pytz.UTC)
        next_week = today + timedelta(days=7)
        
        events = get_events_from_subscription(
            subscription_urls[0],
            start_date=today,
            end_date=next_week
        )
        
        print(f"Found {len(events)} events in the next week")
        for event in events:
            print("\n----- EVENT DETAILS -----")
            print(f"Summary: {event['summary']}")
            print(f"Start: {event['start']}")
            print(f"End: {event['end']}")
            print(f"Location: {event['location']}")
            print(f"Description: {event['description']}")
            print(f"Calendar: {event['calendar']}")
            print("------------------------")
