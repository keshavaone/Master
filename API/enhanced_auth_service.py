"""
AWS SSO Session Manager for GUARD Application

This module provides specialized session management for AWS SSO, properly 
handling token TTLs and refreshing credentials when needed.
"""

import os
import sys
import time
import json
import logging
import datetime
import tempfile
import subprocess
from typing import Dict, Any, Optional, Tuple, List
import boto3
from botocore.exceptions import ClientError, ProfileNotFound
from PyQt5.QtWidgets import QMessageBox, QInputDialog, QProgressDialog
from PyQt5.QtCore import QTimer, QObject, pyqtSignal, Qt, QDateTime

# Configure logging
logger = logging.getLogger("aws_sso_manager")
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

class AwsSsoSessionManager(QObject):
    """
    Enhanced AWS SSO session manager that properly handles credentials and token TTLs.
    
    This manager provides a robust implementation for AWS SSO authentication
    and session management, focusing on security and proper credential handling.
    """
    
    # Define signals for UI notifications
    session_expired = pyqtSignal()
    session_refreshed = pyqtSignal()
    session_expiring_soon = pyqtSignal(int)  # Minutes remaining
    auth_success = pyqtSignal(str)  # Authentication type
    auth_failure = pyqtSignal(str)  # Error message
    
    def __init__(self, parent=None):
        """
        Initialize the AWS SSO session manager.
        
        Args:
            parent: Parent QObject for Qt signals
        """
        super().__init__(parent)
        self.parent = parent
        
        # Authentication state
        self.is_authenticated = False
        self.user_id = None
        self.auth_type = "aws_sso"
        self.auth_timestamp = None
        self.session_token = None
        
        # AWS-specific state
        self.aws_profile = None
        self.aws_session = None
        self.aws_credentials = None
        self.aws_role_arn = None
        self.aws_account_id = None
        
        # Token expiration handling
        self.expiration_time = None
        self.refresh_timer = None
        self.refresh_threshold = 30 * 60  # 30 minutes
        self.warning_threshold = 60 * 60  # 60 minutes
        
        # Security tracking
        self.auth_ip = self._get_user_ip()
        self.auth_events = []
        
        logger.info("AWS SSO Session Manager initialized")
    
    def _get_user_ip(self):
        """Get the user's IP address for audit logging."""
        try:
            # Try to get local IP (if connected to internet)
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            # Fallback to hostname if not connected
            try:
                return socket.gethostname()
            except:
                return "unknown"
    
    def _get_now_datetime(self):
        """
        Get a datetime object for the current time that's compatible with expiration_time.
        
        Returns:
            datetime.datetime: Current time in the same timezone as expiration_time
        """
        if self.expiration_time and self.expiration_time.tzinfo:
            # If expiration time is timezone-aware, create a timezone-aware "now"
            return datetime.datetime.now(datetime.timezone.utc).astimezone(self.expiration_time.tzinfo)
        else:
            # If expiration time is naive, create a naive "now"
            return datetime.datetime.now()
    
    def start_session_timer(self):
        """Start the session timer for token refresh and expiration checking."""
        # Stop existing timer if running
        if self.refresh_timer is not None:
            self.refresh_timer.stop()
        
        # Create and start new timer
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.check_session_status)
        self.refresh_timer.start(30000)  # Check every 30 seconds
        
        logger.debug("Session status timer started")
    
    def stop_session_timer(self):
        """Stop the session timer."""
        if self.refresh_timer is not None:
            self.refresh_timer.stop()
            self.refresh_timer = None
            logger.debug("Session timer stopped")
    
    def check_session_status(self):
        """Check if the session needs refresh or has expired."""
        if not self.is_session_valid():
            logger.warning("Session has expired")
            self.logout()
            self.session_expired.emit()
            return

        # Calculate remaining time
        remaining_time = self.get_remaining_time()
        
        if remaining_time is None:
            return
            
        # Emit warning if session is expiring soon
        if remaining_time <= self.warning_threshold:
            minutes_remaining = remaining_time // 60
            logger.info(f"Session expiring soon: {minutes_remaining} minutes remaining")
            self.session_expiring_soon.emit(minutes_remaining)

        # Check if token requires refresh
        if self.requires_refresh():
            logger.info("Session token needs refresh")
            success = self.refresh_token()
            if success:
                logger.info("Token refreshed successfully")
                self.session_refreshed.emit()
            else:
                logger.warning("Token refresh failed")
    
    def authenticate_aws_sso(self, parent_widget=None) -> bool:
        """
        Authenticate with AWS SSO.
        
        This method handles the complete AWS SSO authentication flow:
        1. Prompts user to select AWS profile or creates one
        2. Launches browser for AWS SSO authentication
        3. Retrieves and validates the credentials
        4. Sets up session with proper TTL
        
        Args:
            parent_widget: Parent widget for dialog displays
            
        Returns:
            bool: True if authentication was successful
        """
        try:
            # Import Qt namespace explicitly for progress dialog
            from PyQt5.QtWidgets import QProgressDialog, QApplication
            
            # Create progress dialog to show authentication steps
            progress_dialog = QProgressDialog("Initializing AWS SSO login...", "Cancel", 0, 100, parent_widget)
            progress_dialog.setWindowTitle("AWS SSO Login")
            progress_dialog.setWindowModality(Qt.WindowModal)
            progress_dialog.setMinimumDuration(0)
            progress_dialog.setValue(10)
            progress_dialog.show()
            QApplication.processEvents()
            
            # Check for existing AWS configuration
            progress_dialog.setLabelText("Reading AWS configuration...")
            progress_dialog.setValue(20)
            QApplication.processEvents()
            
            # Get available AWS SSO profiles
            sso_profiles = self._get_aws_sso_profiles()
            
            if not sso_profiles:
                progress_dialog.close()
                QMessageBox.warning(
                    parent_widget, 
                    "AWS SSO Error",
                    "No SSO profiles found in AWS config.\n\n"
                    "Please run 'aws configure sso' to set up an SSO profile."
                )
                return False
            
            # Select profile (or use the only one if just one exists)
            selected_profile = None
            
            if len(sso_profiles) == 1:
                selected_profile = sso_profiles[0]
            else:
                # Let user select from multiple profiles
                selected_profile, ok = QInputDialog.getItem(
                    parent_widget,
                    "Select AWS Profile",
                    "Multiple AWS SSO profiles found. Please select one:",
                    sso_profiles,
                    0,
                    False
                )
                
                if not ok or not selected_profile:
                    progress_dialog.close()
                    return False
            
            # Store the selected profile
            self.aws_profile = selected_profile
            
            # Update progress dialog
            progress_dialog.setLabelText(
                f"Logging in with profile: {selected_profile}\n\n"
                "A browser window will open for authentication."
            )
            progress_dialog.setValue(30)
            QApplication.processEvents()
            
            # Perform SSO login (opens browser)
            try:
                logger.info(f"Starting AWS SSO login with profile {selected_profile}")
                progress_dialog.setLabelText("Opening browser for SSO login.\n\nPlease complete the login in your browser.")
                progress_dialog.setValue(40)
                QApplication.processEvents()
                
                login_process = subprocess.run(
                    ["aws", "sso", "login", "--profile", selected_profile],
                    check=True,
                    capture_output=True,
                    text=True
                )
                
                logger.info(f"AWS SSO login process completed: {login_process.stdout}")
                progress_dialog.setLabelText("Browser login completed.\nRetrieving credentials...")
                progress_dialog.setValue(60)
                QApplication.processEvents()
                
            except subprocess.CalledProcessError as e:
                progress_dialog.close()
                error_message = f"AWS SSO login failed:\n{e.stderr}"
                logger.error(error_message)
                QMessageBox.warning(parent_widget, "AWS SSO Error", error_message)
                return False
            
            # Create session with the profile
            progress_dialog.setLabelText("Creating AWS session with SSO credentials...")
            progress_dialog.setValue(70)
            QApplication.processEvents()
            
            # Wait for credentials to be available (retry with backoff)
            max_retries = 5
            retry_delays = [1, 2, 3, 5, 8]  # Increasing delays between retries
            session = None
            credentials = None
            
            for retry, delay in enumerate(retry_delays):
                try:
                    logger.info(f"Credential retrieval attempt {retry+1}/{max_retries}...")
                    progress_dialog.setLabelText(f"Retrieving credentials... ({retry+1}/{max_retries})")
                    progress_dialog.setValue(70 + (retry * 5))
                    QApplication.processEvents()
                    
                    # Create boto3 session with the profile
                    session = boto3.Session(profile_name=selected_profile)
                    credentials = session.get_credentials()
                    
                    if credentials and hasattr(credentials, 'access_key') and credentials.access_key:
                        logger.info("Successfully retrieved credentials")
                        break
                    
                    # If credentials not available, try AWS CLI directly
                    logger.info("Trying AWS CLI directly for credentials")
                    result = subprocess.run(
                        ["aws", "sts", "get-caller-identity", "--profile", selected_profile],
                        capture_output=True,
                        text=True,
                        check=True
                    )
                    
                    if result.returncode == 0:
                        logger.info("AWS CLI successfully retrieved identity, retrying session")
                        session = boto3.Session(profile_name=selected_profile)
                        credentials = session.get_credentials()
                        
                        if credentials and hasattr(credentials, 'access_key') and credentials.access_key:
                            logger.info("Successfully retrieved credentials after CLI check")
                            break
                
                except Exception as e:
                    logger.warning(f"Credential retrieval attempt {retry+1} failed: {str(e)}")
                
                # Wait before next attempt if not the last retry
                if retry < len(retry_delays) - 1:
                    logger.info(f"Waiting {delay}s before next attempt...")
                    time.sleep(delay)
            
            # Check if we got valid credentials
            if not session or not credentials or not hasattr(credentials, 'access_key') or not credentials.access_key:
                progress_dialog.close()
                QMessageBox.warning(
                    parent_widget,
                    "AWS SSO Error",
                    "Failed to obtain AWS credentials after successful browser login."
                )
                return False
            
            # Verify credentials with a simple API call
            progress_dialog.setLabelText("Verifying credentials...")
            progress_dialog.setValue(90)
            QApplication.processEvents()
            
            try:
                sts = session.client('sts')
                identity = sts.get_caller_identity()
                logger.info(f"AWS identity verified: {identity['UserId']}")
                
                # Extract account ID and role from ARN if available
                if 'Arn' in identity:
                    arn = identity['Arn']
                    self.aws_role_arn = arn
                    
                    # Extract account ID from ARN
                    if ':' in arn:
                        parts = arn.split(':')
                        if len(parts) >= 5:
                            self.aws_account_id = parts[4]
                
            except Exception as e:
                progress_dialog.close()
                error_message = f"Failed to verify AWS credentials:\n{str(e)}"
                logger.error(error_message)
                QMessageBox.warning(parent_widget, "AWS SSO Error", error_message)
                return False
            
            # Set up session state
            progress_dialog.setLabelText("Setting up authenticated session...")
            progress_dialog.setValue(95)
            QApplication.processEvents()
            
            self.is_authenticated = True
            self.auth_type = "aws_sso"
            self.auth_timestamp = datetime.datetime.now()
            self.user_id = identity.get('UserId', 'unknown')
            self.aws_session = session
            
            # Store credentials
            self.aws_credentials = {
                'AccessKeyId': credentials.access_key,
                'SecretAccessKey': credentials.secret_key,
            }
            
            if hasattr(credentials, 'token') and credentials.token:
                self.aws_credentials['SessionToken'] = credentials.token
                self.session_token = credentials.token
            
            # Set expiration time
            if hasattr(credentials, '_expiry_time') and credentials._expiry_time:
                self.expiration_time = credentials._expiry_time
                logger.info(f"Credential expiration time: {self.expiration_time}")
            else:
                # Default to 8 hours if we can't determine actual expiry (typical AWS SSO default)
                self.expiration_time = datetime.datetime.now() + datetime.timedelta(hours=8)
                logger.info(f"Using default 8-hour expiration time: {self.expiration_time}")
            
            # Set environment variables for child processes
            os.environ['AWS_ACCESS_KEY_ID'] = credentials.access_key
            os.environ['AWS_SECRET_ACCESS_KEY'] = credentials.secret_key
            if hasattr(credentials, 'token') and credentials.token:
                os.environ['AWS_SESSION_TOKEN'] = credentials.token
            
            # Start session timer
            self.start_session_timer()
            
            # Complete the login
            progress_dialog.setLabelText("AWS SSO authentication complete!")
            progress_dialog.setValue(100)
            QApplication.processEvents()
            
            # Log the successful authentication
            self._log_auth_event(True, f"AWS SSO authentication successful for user: {self.user_id}")
            self._log_auth_event(True, f"Using profile: {self.aws_profile}")
            self._log_auth_event(True, f"Session expiration: {self.expiration_time}")
            
            # Emit success signal
            self.auth_success.emit("aws_sso")
            
            # Close the progress dialog after a small delay
            QTimer.singleShot(1000, progress_dialog.close)
            
            return True
            
        except Exception as e:
            logger.error(f"AWS SSO authentication error: {str(e)}")
            
            # Close progress dialog if it exists
            if 'progress_dialog' in locals():
                progress_dialog.close()
            
            # Show error message
            if parent_widget:
                QMessageBox.warning(
                    parent_widget,
                    "AWS SSO Error",
                    f"Authentication error: {str(e)}"
                )
            
            # Emit failure signal
            self.auth_failure.emit(str(e))
            
            return False
    
    def _get_aws_sso_profiles(self) -> List[str]:
        """
        Get list of AWS SSO profiles from AWS config.
        
        Returns:
            List[str]: List of SSO profile names
        """
        import configparser
        
        sso_profiles = []
        config_file = os.path.expanduser("~/.aws/config")
        
        if not os.path.exists(config_file):
            logger.warning(f"AWS config file not found: {config_file}")
            return sso_profiles
        
        try:
            config = configparser.ConfigParser()
            config.read(config_file)
            
            for section in config.sections():
                # AWS config uses "profile name" format except for default
                if section.startswith("profile "):
                    profile_name = section[8:]  # Strip "profile " prefix
                    # Check if it's an SSO profile
                    if "sso_start_url" in config[section]:
                        sso_profiles.append(profile_name)
                elif section == "default" and "sso_start_url" in config[section]:
                    sso_profiles.append("default")
            
            logger.info(f"Found {len(sso_profiles)} SSO profiles: {', '.join(sso_profiles)}")
            return sso_profiles
            
        except Exception as e:
            logger.error(f"Error reading AWS config: {str(e)}")
            return []
    
    def is_session_valid(self) -> bool:
        """
        Check if the current session is valid and not expired.
        
        Returns:
            bool: True if session is valid
        """
        if not self.is_authenticated or not self.expiration_time:
            return False

        now = self._get_now_datetime()
        is_valid = now < self.expiration_time

        if not is_valid:
            logger.warning(f"Session expired at {self.expiration_time}")

        return is_valid
    
    def requires_refresh(self) -> bool:
        """
        Check if the token requires refresh.
        
        Returns:
            bool: True if token needs refresh
        """
        if not self.is_authenticated or not self.expiration_time:
            return False

        now = self._get_now_datetime()
        time_to_expiry = (self.expiration_time - now).total_seconds()
        needs_refresh = time_to_expiry < self.refresh_threshold

        if needs_refresh:
            logger.info(f"Token refresh required - {time_to_expiry:.0f} seconds to expiry")

        return needs_refresh
    
    def refresh_token(self) -> bool:
        """
        Refresh the AWS SSO session token.
        
        This handles extending the token's validity or obtaining a new token
        if needed. For AWS SSO, we may need to re-run the 'aws sso login' command.
        
        Returns:
            bool: True if refresh successful
        """
        if not self.is_authenticated:
            logger.warning("Cannot refresh token: Not authenticated")
            return False
        
        try:
            # For AWS SSO, first check if the credentials are still valid
            if self.aws_session:
                try:
                    # Try to make a lightweight AWS call
                    sts = self.aws_session.client('sts')
                    sts.get_caller_identity()
                    
                    # If successful, credentials are still valid
                    logger.info("Credentials are still valid - extending expiration")
                    
                    # Extend the expiration time
                    remaining_time = (self.expiration_time - self._get_now_datetime()).total_seconds()
                    extension_time = 60 * 60  # 1 hour extension
                    
                    # Only extend if we're getting close to expiration
                    if remaining_time < self.refresh_threshold:
                        self.expiration_time = self._get_now_datetime() + datetime.timedelta(seconds=extension_time)
                        logger.info(f"Extended expiration time to {self.expiration_time}")
                        return True
                    else:
                        # No extension needed yet
                        return True
                    
                except Exception as e:
                    logger.warning(f"Token validation failed: {str(e)}")
                    # Continue to token refresh
            
            # If we get here, we need to refresh the token via AWS SSO login
            if self.aws_profile:
                try:
                    logger.info(f"Refreshing AWS SSO token for profile {self.aws_profile}")
                    
                    # Run AWS SSO login to refresh token
                    subprocess.run(
                        ["aws", "sso", "login", "--profile", self.aws_profile],
                        check=True,
                        capture_output=True
                    )
                    
                    # Create a new session with fresh credentials
                    session = boto3.Session(profile_name=self.aws_profile)
                    credentials = session.get_credentials()
                    
                    if not credentials or not credentials.access_key:
                        logger.error("Failed to get fresh credentials after AWS SSO login")
                        return False
                    
                    # Update session and credentials
                    self.aws_session = session
                    self.aws_credentials = {
                        'AccessKeyId': credentials.access_key,
                        'SecretAccessKey': credentials.secret_key,
                    }
                    
                    if hasattr(credentials, 'token') and credentials.token:
                        self.aws_credentials['SessionToken'] = credentials.token
                        self.session_token = credentials.token
                    
                    # Update expiration time
                    if hasattr(credentials, '_expiry_time') and credentials._expiry_time:
                        self.expiration_time = credentials._expiry_time
                    else:
                        # Default to 8 hours if we can't determine actual expiry
                        self.expiration_time = datetime.datetime.now() + datetime.timedelta(hours=8)
                    
                    # Update environment variables
                    os.environ['AWS_ACCESS_KEY_ID'] = credentials.access_key
                    os.environ['AWS_SECRET_ACCESS_KEY'] = credentials.secret_key
                    if hasattr(credentials, 'token') and credentials.token:
                        os.environ['AWS_SESSION_TOKEN'] = credentials.token
                    
                    logger.info(f"Successfully refreshed AWS SSO token, new expiration: {self.expiration_time}")
                    self._log_auth_event(True, "Token refreshed successfully")
                    return True
                    
                except Exception as e:
                    logger.error(f"Failed to refresh AWS SSO token: {str(e)}")
                    self._log_auth_event(False, f"Token refresh failed: {str(e)}")
                    return False
            else:
                logger.error("No AWS profile set for token refresh")
                return False
                
        except Exception as e:
            logger.error(f"Error refreshing token: {str(e)}")
            return False
    
    def get_remaining_time(self) -> Optional[int]:
        """
        Get remaining session time in seconds.
        
        Returns:
            Optional[int]: Remaining time in seconds or None if not authenticated
        """
        if not self.is_authenticated or not self.expiration_time:
            return None

        now = self._get_now_datetime()
        remaining = (self.expiration_time - now).total_seconds()
        return max(0, int(remaining))
    
    def get_session_info(self) -> Dict[str, Any]:
        """
        Get information about the current session.
        
        Returns:
            Dict[str, Any]: Session information
        """
        remaining_time = self.get_remaining_time()

        return {
            "is_authenticated": self.is_authenticated,
            "auth_type": self.auth_type,
            "user_id": self.user_id,
            "auth_timestamp": self.auth_timestamp.isoformat() if self.auth_timestamp else None,
            "auth_ip": self.auth_ip,
            "expiration_time": self.expiration_time.isoformat() if self.expiration_time else None,
            "remaining_seconds": remaining_time,
            "remaining_formatted": self._format_time(remaining_time) if remaining_time else None,
            "aws_profile": self.aws_profile,
            "aws_account_id": self.aws_account_id,
            "has_credentials": bool(self.aws_credentials)
        }
    
    def _format_time(self, seconds: int) -> str:
        """
        Format seconds into a human-readable string.
        
        Args:
            seconds (int): Time in seconds
            
        Returns:
            str: Formatted time string (e.g., "1h 30m")
        """
        if seconds is None:
            return "--:--"
            
        minutes, seconds = divmod(seconds, 60)
        hours, minutes = divmod(minutes, 60)
        
        if hours > 0:
            return f"{hours}h {minutes}m"
        else:
            return f"{minutes}m {seconds}s"
    
    def logout(self):
        """Perform logout operations and clean up resources."""
        try:
            # Log the logout
            if self.is_authenticated:
                self._log_auth_event(True, f"Logged out user {self.user_id}")
            
            # Clear state
            prev_user = self.user_id
            self.is_authenticated = False
            self.user_id = None
            self.session_token = None
            self.expiration_time = None
            self.aws_credentials = None
            self.aws_session = None
            
            # Stop timer
            self.stop_session_timer()
            
            # Clear AWS environment variables
            aws_vars = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY',
                        'AWS_SESSION_TOKEN', 'AWS_PROFILE']
            for var in aws_vars:
                if var in os.environ:
                    del os.environ[var]
            
            logger.info(f"Logout complete for user {prev_user}")
            return True
        except Exception as e:
            logger.error(f"Error during logout: {str(e)}")
            return False
    
    def _log_auth_event(self, success: bool, message: str):
        """
        Log an authentication event for audit purposes.
        
        Args:
            success (bool): Whether the event was successful
            message (str): Event message
        """
        event_type = "SUCCESS" if success else "FAILURE"
        timestamp = datetime.datetime.now().isoformat()
        
        event = {
            "timestamp": timestamp,
            "event_type": f"AUTH_{event_type}",
            "user_id": self.user_id if self.user_id else "unknown",
            "ip_address": self.auth_ip,
            "message": message
        }
        
        # Add to event log
        self.auth_events.append(event)
        
        # Log to logger
        log_method = logger.info if success else logger.warning
        log_method(f"AUTH: {message}")
        
        # Write to audit log file
        try:
            log_dir = os.path.expanduser("~/.guard_config/logs")
            os.makedirs(log_dir, exist_ok=True)
            
            log_file = os.path.join(log_dir, "aws_sso_audit.log")
            with open(log_file, 'a') as f:
                f.write(json.dumps(event) + "\n")
        except Exception as e:
            logger.error(f"Failed to write to audit log: {str(e)}")
            
    def get_aws_session(self):
        """
        Get the current AWS session.
        
        Returns:
            boto3.Session: The AWS session or None if not authenticated
        """
        if not self.is_authenticated or not self.aws_session:
            return None
        
        return self.aws_session
    
    def get_aws_resource(self, service_name, region_name=None):
        """
        Get an AWS resource client.
        
        Args:
            service_name (str): Name of the AWS service
            region_name (str, optional): AWS region
            
        Returns:
            Resource: AWS resource client or None if not authenticated
        """
        if not self.is_authenticated or not self.aws_session:
            return None
        
        try:
            return self.aws_session.resource(service_name, region_name=region_name)
        except Exception as e:
            logger.error(f"Error creating AWS resource client: {str(e)}")
            return None
    
    def get_aws_client(self, service_name, region_name=None):
        """
        Get an AWS service client.
        
        Args:
            service_name (str): Name of the AWS service
            region_name (str, optional): AWS region
            
        Returns:
            Client: AWS service client or None if not authenticated
        """
        if not self.is_authenticated or not self.aws_session:
            return None
        
        try:
            return self.aws_session.client(service_name, region_name=region_name)
        except Exception as e:
            logger.error(f"Error creating AWS client: {str(e)}")
            return None
    
    def get_auth_headers(self) -> Dict[str, str]:
        """
        Get authentication headers for API requests.
        
        Returns:
            Dict[str, str]: Authentication headers
        """
        headers = {}
        
        if not self.is_authenticated or not self.aws_credentials:
            return headers
        
        # Add AWS credentials headers for API authentication
        headers["X-AWS-Access-Key-ID"] = self.aws_credentials.get('AccessKeyId', '')
        headers["X-AWS-Secret-Access-Key"] = self.aws_credentials.get('SecretAccessKey', '')
        
        if 'SessionToken' in self.aws_credentials:
            headers["X-AWS-Session-Token"] = self.aws_credentials.get('SessionToken', '')
        
        # Add user identity information
        if self.user_id:
            headers["X-User-ID"] = self.user_id
        
        return headers
    
    def export_session_info(self, file_path=None):
        """
        Export session information to a file.
        
        Args:
            file_path (str, optional): Path to export file
            
        Returns:
            str: Path to the export file
        """
        if not file_path:
            # Create a temporary file
            temp_dir = os.path.expanduser("~/.guard_config/temp")
            os.makedirs(temp_dir, exist_ok=True)
            file_path = os.path.join(temp_dir, f"aws_session_{int(time.time())}.json")
        
        try:
            # Get session info
            session_info = self.get_session_info()
            
            # Add profile and account info
            session_info["aws_profile"] = self.aws_profile
            session_info["aws_account_id"] = self.aws_account_id
            session_info["aws_role_arn"] = self.aws_role_arn
            
            # Remove sensitive data
            if "aws_credentials" in session_info:
                del session_info["aws_credentials"]
            
            # Write to file
            with open(file_path, 'w') as f:
                json.dump(session_info, f, indent=2)
            
            logger.info(f"Session info exported to {file_path}")
            return file_path
            
        except Exception as e:
            logger.error(f"Error exporting session info: {str(e)}")
            return None