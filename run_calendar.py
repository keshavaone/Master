#!/usr/bin/env python3
"""
Run script for testing calendar-to-whatsapp integration
"""

import os
import sys
import argparse
from api.communications import calendar_to_whatsapp

def main():
    """Parse arguments and run the appropriate command"""
    parser = argparse.ArgumentParser(description='Calendar to WhatsApp/SMS Tool')
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Send summary command
    send_parser = subparsers.add_parser('send', help='Send calendar summary')
    send_parser.add_argument('--days', type=int, default=0, help='Days ahead (0 for today, 1 for tomorrow, etc.)')
    send_parser.add_argument('--method', choices=['whatsapp', 'sms', 'both'], default='whatsapp', 
                            help='Method to send the message')
    send_parser.add_argument('--recipient', type=str, help='Recipient phone number (with country code)')
    
    # List subscriptions command
    list_parser = subparsers.add_parser('list', help='List calendar subscriptions')
    
    # Add subscription command
    add_parser = subparsers.add_parser('add', help='Add calendar subscription')
    add_parser.add_argument('name', type=str, help='Name of the calendar')
    add_parser.add_argument('url', type=str, help='URL of the iCal calendar feed')
    
    # Remove subscription command
    remove_parser = subparsers.add_parser('remove', help='Remove calendar subscription')
    remove_parser.add_argument('name_or_url', type=str, help='Name or URL of the calendar to remove')
    
    args = parser.parse_args()
    
    # Execute the appropriate command
    if args.command == 'send':
        results = calendar_to_whatsapp.send_calendar_summary(
            days_ahead=args.days,
            method=args.method,
            recipient=args.recipient
        )
        
        # Report results
        success = False
        for method_name, sid in results.items():
            if sid:
                print(f"Successfully sent {method_name.upper()} message with calendar summary. SID: {sid}")
                success = True
            else:
                print(f"Failed to send {method_name.upper()} message with calendar summary.")
        
        if not success:
            print("Failed to send any messages with calendar summary.")
            return 1
        
    elif args.command == 'list':
        subscriptions = calendar_to_whatsapp.list_subscription_calendars()
        if subscriptions:
            print(f"Found {len(subscriptions)} subscription calendars:")
            for i, sub in enumerate(subscriptions):
                print(f"{i+1}. {sub['name']}: {sub['url']}")
        else:
            print("No subscription calendars found")
            
    elif args.command == 'add':
        success = calendar_to_whatsapp.add_subscription_calendar(args.name, args.url)
        if success:
            print(f"Successfully added subscription calendar: {args.name}")
        else:
            print(f"Failed to add subscription calendar: {args.name}")
            return 1
            
    elif args.command == 'remove':
        success = calendar_to_whatsapp.remove_subscription_calendar(args.name_or_url)
        if success:
            print(f"Successfully removed subscription calendar: {args.name_or_url}")
        else:
            print(f"Failed to remove subscription calendar: {args.name_or_url}")
            return 1
            
    else:
        parser.print_help()
        return 1
        
    return 0

if __name__ == "__main__":
    sys.exit(main())