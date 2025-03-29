"""
Data validation and error handling utilities for the GUARD application.

This module provides standardized data validation and error handling functions
to ensure data integrity, security, and proper error reporting throughout
the application.
"""

import logging
import traceback
import re
import json
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional, Union, Callable

from PyQt5.QtWidgets import QMessageBox
from PyQt5.QtCore import QObject

# Configure logging
logger = logging.getLogger("guard.validation")


class DataValidator:
    """
    Data validation utilities for secure PII data management.
    
    This class provides static methods for validating different types of data
    before transmission or storage, ensuring data integrity and security.
    """
    
    @staticmethod
    def validate_pii_item(data: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Validate a PII data item structure.
        
        Args:
            data: The data item to validate
            
        Returns:
            Tuple[bool, str]: (is_valid, error_message)
        """
        # Check for required fields
        required_fields = ['Category', 'Type', 'PII']
        missing_fields = [field for field in required_fields if field not in data]
        
        if missing_fields:
            return False, f"Missing required fields: {', '.join(missing_fields)}"
        
        # Check for empty required fields
        empty_fields = [field for field in required_fields if not data.get(field)]
        if empty_fields:
            return False, f"Empty required fields: {', '.join(empty_fields)}"
        
        # Validate PII data structure
        pii_data = data.get('PII', '')
        if isinstance(pii_data, str):
            try:
                # Try to parse as list of dictionaries
                pii_items = eval(pii_data)  # Note: This is safe here as we're just validating structure
                
                if not isinstance(pii_items, list):
                    return False, "PII data must be a list of items"
                
                # Check each item has required structure
                for idx, item in enumerate(pii_items):
                    if not isinstance(item, dict):
                        return False, f"PII item #{idx+1} must be a dictionary"
                    
                    if 'Item Name' not in item or 'Data' not in item:
                        return False, f"PII item #{idx+1} missing 'Item Name' or 'Data' field"
            except Exception as e:
                return False, f"Invalid PII data structure: {str(e)}"
        
        # Validate field lengths
        if len(data['Category']) > 100:
            return False, "Category name is too long (maximum 100 characters)"
            
        if len(data['Type']) > 100:
            return False, "Type name is too long (maximum 100 characters)"
        
        # Validation passed
        return True, ""
    
    @staticmethod
    def sanitize_pii_item(data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize a PII data item to ensure it's safe for storage.
        
        Args:
            data: The data item to sanitize
            
        Returns:
            Dict[str, Any]: Sanitized data item
        """
        # Create a copy to avoid modifying the original
        sanitized = data.copy()
        
        # Sanitize Category and Type fields
        if 'Category' in sanitized:
            # Remove any HTML or special characters
            sanitized['Category'] = re.sub(r'<[^>]*>', '', str(sanitized['Category']))
            sanitized['Category'] = sanitized['Category'].strip()
            
        if 'Type' in sanitized:
            # Remove any HTML or special characters
            sanitized['Type'] = re.sub(r'<[^>]*>', '', str(sanitized['Type']))
            sanitized['Type'] = sanitized['Type'].strip()
        
        # Sanitize PII data
        if 'PII' in sanitized and isinstance(sanitized['PII'], str):
            try:
                # Try to parse PII data
                pii_items = eval(sanitized['PII'])
                
                if isinstance(pii_items, list):
                    # Sanitize each item
                    for item in pii_items:
                        if isinstance(item, dict):
                            if 'Item Name' in item:
                                item['Item Name'] = re.sub(r'<[^>]*>', '', str(item['Item Name'])).strip()
                            if 'Data' in item:
                                # For Data field, we don't strip to preserve whitespace
                                item['Data'] = re.sub(r'<[^>]*>', '', str(item['Data']))
                    
                    # Update the PII field with sanitized data
                    sanitized['PII'] = str(pii_items)
            except:
                # If parsing fails, sanitize as regular string
                sanitized['PII'] = re.sub(r'<[^>]*>', '', str(sanitized['PII']))
        
        return sanitized


class ErrorHandler(QObject):
    """
    Centralized error handling for the GUARD application.
    
    This class provides standardized error handling, logging, and user feedback
    for different types of errors throughout the application.
    """
    
    def __init__(self, parent=None):
        """
        Initialize the error handler.
        
        Args:
            parent: Parent QObject
        """
        super().__init__(parent)
        self.logger = logging.getLogger("guard.errors")
    
    def handle_network_error(self, exception: Exception, context: str = "", show_ui: bool = True) -> str:
        """
        Handle network-related errors.
        
        Args:
            exception: The exception that occurred
            context: Additional context about where the error occurred
            show_ui: Whether to show a UI error message
            
        Returns:
            str: Error message
        """
        error_type = type(exception).__name__
        error_msg = str(exception)
        
        # Create detailed error message
        context_info = f" during {context}" if context else ""
        message = f"Network error{context_info}: {error_type} - {error_msg}"
        
        # Log the error
        self.logger.error(message)
        self.logger.debug(traceback.format_exc())
        
        if show_ui and self.parent():
            # Show user-friendly error dialog
            QMessageBox.warning(
                self.parent(),
                "Network Error",
                f"A network error occurred{context_info}.\n\n"
                f"Details: {error_msg}\n\n"
                "Please check your connection and try again."
            )
        
        return message
    
    def handle_data_error(self, error_info: Union[str, Exception], data: Any = None, context: str = "", show_ui: bool = True) -> str:
        """
        Handle data-related errors.
        
        Args:
            error_info: Error information (string or exception)
            data: The data causing the error (will be sanitized in logs)
            context: Additional context about where the error occurred
            show_ui: Whether to show a UI error message
            
        Returns:
            str: Error message
        """
        # Create error message
        if isinstance(error_info, Exception):
            error_type = type(error_info).__name__
            error_msg = str(error_info)
            message = f"Data error{' during ' + context if context else ''}: {error_type} - {error_msg}"
        else:
            message = f"Data error{' during ' + context if context else ''}: {error_info}"
        
        # Log the error
        self.logger.error(message)
        
        # Log sanitized data for debugging
        if data is not None:
            try:
                # Sanitize potentially sensitive data for logging
                if isinstance(data, dict):
                    sanitized_data = data.copy()
                    # Remove or mask sensitive fields
                    for key in list(sanitized_data.keys()):
                        if any(sensitive in key.lower() for sensitive in ['password', 'token', 'secret', 'key', 'credential']):
                            sanitized_data[key] = "***REDACTED***"
                    self.logger.debug(f"Error with data: {sanitized_data}")
                else:
                    self.logger.debug(f"Error with data type: {type(data)}")
            except:
                self.logger.debug("Could not log data information")
        
        if show_ui and self.parent():
            # Show user-friendly error dialog
            QMessageBox.warning(
                self.parent(),
                "Data Error",
                f"An error occurred with the data{' during ' + context if context else ''}.\n\n"
                f"Details: {error_msg if isinstance(error_info, Exception) else error_info}\n\n"
                "Please check the data and try again."
            )
        
        return message
    
    def handle_auth_error(self, error_info: Union[str, Exception], context: str = "", show_ui: bool = True) -> str:
        """
        Handle authentication-related errors.
        
        Args:
            error_info: Error information (string or exception)
            context: Additional context about where the error occurred
            show_ui: Whether to show a UI error message
            
        Returns:
            str: Error message
        """
        # Create error message
        if isinstance(error_info, Exception):
            error_type = type(error_info).__name__
            error_msg = str(error_info)
            message = f"Authentication error{' during ' + context if context else ''}: {error_type} - {error_msg}"
        else:
            message = f"Authentication error{' during ' + context if context else ''}: {error_info}"
        
        # Log the error
        self.logger.error(message)
        if isinstance(error_info, Exception):
            self.logger.debug(traceback.format_exc())
        
        if show_ui and self.parent():
            # Show user-friendly error dialog
            QMessageBox.warning(
                self.parent(),
                "Authentication Error",
                f"An authentication error occurred{' during ' + context if context else ''}.\n\n"
                f"Details: {error_msg if isinstance(error_info, Exception) else error_info}\n\n"
                "Please check your credentials and try again."
            )
        
        return message
    
    def handle_application_error(self, exception: Exception, context: str = "", show_ui: bool = True) -> str:
        """
        Handle general application errors.
        
        Args:
            exception: The exception that occurred
            context: Additional context about where the error occurred
            show_ui: Whether to show a UI error message
            
        Returns:
            str: Error message
        """
        error_type = type(exception).__name__
        error_msg = str(exception)
        
        # Create detailed error message
        message = f"Application error{' during ' + context if context else ''}: {error_type} - {error_msg}"
        
        # Log the error with stacktrace
        self.logger.error(message)
        self.logger.error(traceback.format_exc())
        
        if show_ui and self.parent():
            # Show user-friendly error dialog
            QMessageBox.critical(
                self.parent(),
                "Application Error",
                f"An unexpected error occurred{' during ' + context if context else ''}.\n\n"
                f"Details: {error_type}: {error_msg}\n\n"
                "Please try again. If the problem persists, please contact support."
            )
        
        return message
    
    def handle_security_event(self, event_type: str, details: str, severity: str = "warning", show_ui: bool = True) -> None:
        """
        Handle security-related events.
        
        Args:
            event_type: Type of security event
            details: Details about the event
            severity: Severity level ('info', 'warning', 'error', 'critical')
            show_ui: Whether to show a UI message
        """
        # Create security event message
        timestamp = datetime.now().isoformat()
        message = f"Security event [{event_type}] at {timestamp}: {details}"
        
        # Log based on severity
        if severity == "info":
            self.logger.info(message)
        elif severity == "warning":
            self.logger.warning(message)
        elif severity == "error":
            self.logger.error(message)
        elif severity == "critical":
            self.logger.critical(message)
        else:
            self.logger.warning(message)
        
        if show_ui and self.parent():
            # Show security alert to user
            if severity in ["error", "critical"]:
                QMessageBox.critical(
                    self.parent(),
                    "Security Alert",
                    f"Security issue detected: {event_type}\n\n{details}\n\n"
                    "Please contact your system administrator immediately."
                )
            elif severity == "warning":
                QMessageBox.warning(
                    self.parent(),
                    "Security Warning",
                    f"Security warning: {event_type}\n\n{details}"
                )
            else:
                QMessageBox.information(
                    self.parent(),
                    "Security Information",
                    f"Security notice: {event_type}\n\n{details}"
                )


class InputValidator:
    """
    Utility class for validating user input.
    
    This class provides static methods for validating different types of user input
    to ensure data integrity and security.
    """
    
    @staticmethod
    def validate_category_name(name: str) -> Tuple[bool, str]:
        """
        Validate a category name.
        
        Args:
            name: Category name to validate
            
        Returns:
            Tuple[bool, str]: (is_valid, error_message)
        """
        if not name:
            return False, "Category name cannot be empty"
        
        if len(name) > 100:
            return False, "Category name is too long (maximum 100 characters)"
        
        # Check for invalid characters
        if re.search(r'[<>"\'\\/;]', name):
            return False, "Category name contains invalid characters"
        
        return True, ""
    
    @staticmethod
    def validate_type_name(name: str) -> Tuple[bool, str]:
        """
        Validate a type name.
        
        Args:
            name: Type name to validate
            
        Returns:
            Tuple[bool, str]: (is_valid, error_message)
        """
        if not name:
            return False, "Type name cannot be empty"
        
        if len(name) > 100:
            return False, "Type name is too long (maximum 100 characters)"
        
        # Check for invalid characters
        if re.search(r'[<>"\'\\/;]', name):
            return False, "Type name contains invalid characters"
        
        return True, ""
    
    @staticmethod
    def validate_pii_field_name(name: str) -> Tuple[bool, str]:
        """
        Validate a PII field name.
        
        Args:
            name: Field name to validate
            
        Returns:
            Tuple[bool, str]: (is_valid, error_message)
        """
        if not name:
            return False, "Field name cannot be empty"
        
        if len(name) > 100:
            return False, "Field name is too long (maximum 100 characters)"
        
        # Check for invalid characters
        if re.search(r'[<>"\'\\/;]', name):
            return False, "Field name contains invalid characters"
        
        return True, ""
    
    @staticmethod
    def validate_pii_data(data: str) -> Tuple[bool, str]:
        """
        Validate PII data content.
        
        Args:
            data: PII data to validate
            
        Returns:
            Tuple[bool, str]: (is_valid, error_message)
        """
        # We allow empty data in some cases
        if not data:
            return True, ""
        
        # For security, limit the size of PII data
        if len(data) > 10000:
            return False, "PII data is too large (maximum 10000 characters)"
        
        return True, ""


class SecurityAuditor:
    """
    Utility class for security auditing and logging.
    
    This class provides methods for recording security-related events
    and maintaining an audit trail for compliance and security purposes.
    """
    
    def __init__(self, logger_name: str = "guard.security"):
        """
        Initialize the security auditor.
        
        Args:
            logger_name: Name for the security logger
        """
        self.logger = logging.getLogger(logger_name)
        self.events = []
    
    def log_auth_event(self, user_id: str, event_type: str, success: bool, 
                      ip_address: str = None, details: str = None) -> None:
        """
        Log an authentication event.
        
        Args:
            user_id: User identifier
            event_type: Type of authentication event
            success: Whether the authentication was successful
            ip_address: IP address of the client
            details: Additional event details
        """
        timestamp = datetime.now().isoformat()
        result = "SUCCESS" if success else "FAILURE"
        
        # Create log entry
        log_entry = {
            "timestamp": timestamp,
            "user_id": user_id,
            "event_type": event_type,
            "result": result,
            "ip_address": ip_address or "unknown",
            "details": details or ""
        }
        
        # Add to events list
        self.events.append(log_entry)
        
        # Log the event
        message = (
            f"AUTH {result} - User: {user_id}, Event: {event_type}, "
            f"IP: {ip_address or 'unknown'}, Details: {details or 'none'}"
        )
        
        if success:
            self.logger.info(message)
        else:
            self.logger.warning(message)
    
    def log_data_access(self, user_id: str, action: str, data_type: str, 
                       data_id: str = None, success: bool = True, details: str = None) -> None:
        """
        Log a data access event.
        
        Args:
            user_id: User identifier
            action: Action performed (view, create, update, delete)
            data_type: Type of data accessed
            data_id: Identifier of the data accessed
            success: Whether the access was successful
            details: Additional event details
        """
        timestamp = datetime.now().isoformat()
        result = "SUCCESS" if success else "FAILURE"
        
        # Create log entry
        log_entry = {
            "timestamp": timestamp,
            "user_id": user_id,
            "action": action,
            "data_type": data_type,
            "data_id": data_id or "n/a",
            "result": result,
            "details": details or ""
        }
        
        # Add to events list
        self.events.append(log_entry)
        
        # Log the event
        message = (
            f"DATA ACCESS {result} - User: {user_id}, Action: {action}, "
            f"Type: {data_type}, ID: {data_id or 'n/a'}, Details: {details or 'none'}"
        )
        
        if success:
            self.logger.info(message)
        else:
            self.logger.warning(message)
    
    def log_security_event(self, event_type: str, severity: str, 
                          user_id: str = None, details: str = None) -> None:
        """
        Log a security event.
        
        Args:
            event_type: Type of security event
            severity: Severity of the event (info, warning, error, critical)
            user_id: User identifier (if applicable)
            details: Additional event details
        """
        timestamp = datetime.now().isoformat()
        
        # Create log entry
        log_entry = {
            "timestamp": timestamp,
            "event_type": event_type,
            "severity": severity,
            "user_id": user_id or "system",
            "details": details or ""
        }
        
        # Add to events list
        self.events.append(log_entry)
        
        # Log the event
        message = (
            f"SECURITY {severity.upper()} - Type: {event_type}, "
            f"User: {user_id or 'system'}, Details: {details or 'none'}"
        )
        
        if severity == "info":
            self.logger.info(message)
        elif severity == "warning":
            self.logger.warning(message)
        elif severity == "error":
            self.logger.error(message)
        elif severity == "critical":
            self.logger.critical(message)
        else:
            self.logger.warning(message)
    
    def get_recent_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get recent security events.
        
        Args:
            limit: Maximum number of events to return
            
        Returns:
            List[Dict[str, Any]]: Recent security events
        """
        return self.events[-limit:] if self.events else []
    
    def export_audit_log(self, format_type: str = "json") -> str:
        """
        Export the audit log in the specified format.
        
        Args:
            format_type: Format for export ("json", "csv")
            
        Returns:
            str: Exported audit log
        """
        if format_type == "json":
            return json.dumps(self.events, indent=2)
        elif format_type == "csv":
            # Create CSV header
            header = "timestamp,user_id,event_type,action,data_type,data_id,result,severity,details\n"
            
            # Create CSV rows
            rows = []
            for event in self.events:
                row = [
                    event.get("timestamp", ""),
                    event.get("user_id", ""),
                    event.get("event_type", ""),
                    event.get("action", ""),
                    event.get("data_type", ""),
                    event.get("data_id", ""),
                    event.get("result", ""),
                    event.get("severity", ""),
                    event.get("details", "").replace(",", ";")  # Escape commas in details
                ]
                rows.append(",".join([str(item) for item in row]))
            
            return header + "\n".join(rows)
        else:
            return "Unsupported export format"


# Create global instances for convenience
security_auditor = SecurityAuditor()