"""
Session management module for the GUARD application.

This module handles authentication, session tokens, and AWS SSO integration,
ensuring secure and time-limited sessions with proper credential management.
"""

import os
import sys
import time
import json
import hashlib
import logging
import datetime
import subprocess
import threading
from typing import Dict, Any, Optional, Tuple
import boto3
from PyQt5.QtWidgets import QMessageBox, QInputDialog, QLineEdit
from PyQt5.QtCore import QTimer, QDateTime, QObject, pyqtSignal


class SessionManager(QObject):
    """
    Manages user sessions with AWS SSO integration.
    
    Handles authentication, session tokens, and AWS credential management
    with support for token refresh and timeout functionality.
    """
    
    # Signals
    session_expired = pyqtSignal()
    token_refreshed = pyqtSignal()
    
    def __init__(self, parent=None, token_ttl=3600, refresh_threshold=300):
        """
        Initialize the session manager.
        
        Args:
            parent: Parent QObject
            token_ttl (int): Time-to-live for session tokens in seconds (default: 1 hour)
            refresh_threshold (int): Time threshold for token refresh in seconds (default: 5 minutes)
        """
        super().__init__(parent)
        self.token_ttl = token_ttl
        self.refresh_threshold = refresh_threshold
        self.session_token = None
        self.expiration_time = None
        self.refresh_timer = None
        self.credentials = None
        self.user_id = None
        self.is_authenticated = False
        
        # For traditional password auth (fallback)
        self.password_hash = None
        
        # Set up logging
        self.logger = logging.getLogger('SessionManager')
    
    def start_session_timer(self):
        """Start the session timer for token refresh and expiration."""
        if self.refresh_timer is None:
            self.refresh_timer = QTimer(self)
            self.refresh_timer.timeout.connect(self.check_session_status)
            self.refresh_timer.start(60000)  # Check every minute
    
    def stop_session_timer(self):
        """Stop the session timer."""
        if self.refresh_timer is not None:
            self.refresh_timer.stop()
            self.refresh_timer = None
    
    def check_session_status(self):
        """Check if the session needs refresh or has expired."""
        if not self.is_session_valid():
            self.logger.info("Session expired")
            self.logout()
            self.session_expired.emit()
            return
        
        if self.requires_refresh():
            self.logger.info("Session token needs refresh")
            success = self.refresh_token()
            if success:
                self.token_refreshed.emit()
    
    def authenticate_password(self, password: str, stored_password_hash: str) -> bool:
        """
        Authenticate using traditional password.
        
        Args:
            password (str): User input password
            stored_password_hash (str): Stored password hash to compare against
            
        Returns:
            bool: True if authentication successful
        """
        try:
            # Hash the input password
            hashed_input = hashlib.sha256(password.encode()).hexdigest()
            
            # Compare with stored hash
            if hashed_input == stored_password_hash:
                self.is_authenticated = True
                
                # Set expiration time based on token_ttl
                self.expiration_time = datetime.datetime.now() + datetime.timedelta(seconds=self.token_ttl)
                self.start_session_timer()
                
                # Generate a simple session token (in a real implementation, this would be more secure)
                self.session_token = hashlib.sha256(
                    (password + str(time.time())).encode()
                ).hexdigest()
                
                self.logger.info("Password authentication successful")
                return True
            else:
                self.logger.warning("Password authentication failed")
                return False
        except Exception as e:
            self.logger.error(f"Password authentication error: {str(e)}")
            return False
    
    def configure_aws_sso(self, parent_widget=None):
        """
        Configure AWS SSO settings through UI dialog.
        
        Args:
            parent_widget: Parent widget for dialogs
            
        Returns:
            bool: True if configuration successful
        """
        if parent_widget:
            # Get SSO start URL
            sso_url, ok_pressed = QInputDialog.getText(
                parent_widget,
                "AWS SSO Configuration",
                "Enter your AWS SSO start URL:",
                QLineEdit.Normal,
                "https://your-sso-portal.awsapps.com/start"
            )
            if not ok_pressed or not sso_url:
                return False
            
            # Get SSO region
            sso_region, ok_pressed = QInputDialog.getText(
                parent_widget,
                "AWS SSO Configuration",
                "Enter your AWS SSO region:",
                QLineEdit.Normal,
                "us-east-1"
            )
            if not ok_pressed or not sso_region:
                return False
            
            # Get account ID
            account_id, ok_pressed = QInputDialog.getText(
                parent_widget,
                "AWS SSO Configuration",
                "Enter your AWS account ID:",
                QLineEdit.Normal,
                ""
            )
            if not ok_pressed or not account_id:
                return False
            
            # Get role name
            role_name, ok_pressed = QInputDialog.getText(
                parent_widget,
                "AWS SSO Configuration",
                "Enter the role name to use:",
                QLineEdit.Normal,
                "PowerUserAccess"
            )
            if not ok_pressed or not role_name:
                return False
            
            # Save configuration
            config = {
                'sso_start_url': sso_url,
                'sso_region': sso_region,
                'account_id': account_id,
                'role_name': role_name
            }
            
            self._save_sso_config(config)
            return True
        return False
    
    def _save_sso_config(self, config: Dict[str, str]):
        """
        Save SSO configuration to file.
        
        Args:
            config (Dict[str, str]): SSO configuration
        """
        config_dir = os.path.expanduser("~/.guard")
        os.makedirs(config_dir, exist_ok=True)
        
        config_file = os.path.join(config_dir, "sso_config.json")
        with open(config_file, 'w') as f:
            json.dump(config, f)
    
    def _load_sso_config(self) -> Optional[Dict[str, str]]:
        """
        Load SSO configuration from file.
        
        Returns:
            Optional[Dict[str, str]]: SSO configuration or None if not found
        """
        config_file = os.path.expanduser("~/.guard/sso_config.json")
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                self.logger.error(f"Error loading SSO config: {str(e)}")
        return None
    
    def authenticate_aws_sso(self, parent_widget=None) -> bool:
        """
        Authenticate using AWS SSO.
        
        Args:
            parent_widget: Parent widget for dialogs
            
        Returns:
            bool: True if authentication successful
        """
        # Load SSO configuration
        config = self._load_sso_config()
        if not config:
            if parent_widget:
                reply = QMessageBox.question(
                    parent_widget,
                    "AWS SSO Configuration",
                    "AWS SSO is not configured. Would you like to configure it now?",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.Yes
                )
                if reply == QMessageBox.Yes:
                    if not self.configure_aws_sso(parent_widget):
                        return False
                    config = self._load_sso_config()
                else:
                    return False
            else:
                self.logger.error("AWS SSO not configured")
                return False
        
        # Start AWS SSO login process
        if parent_widget:
            QMessageBox.information(
                parent_widget,
                "AWS SSO Login",
                "You will now be redirected to your AWS SSO login page. "
                "Please complete the login process in your browser."
            )
        
        try:
            # Use aws configure sso login command
            sso_login_process = subprocess.Popen(
                [
                    "aws", "sso", "login",
                    "--sso-start-url", config["sso_start_url"],
                    "--sso-region", config["sso_region"]
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            stdout, stderr = sso_login_process.communicate()
            
            if sso_login_process.returncode != 0:
                self.logger.error(f"AWS SSO login failed: {stderr}")
                if parent_widget:
                    QMessageBox.warning(
                        parent_widget,
                        "AWS SSO Login Failed",
                        f"Failed to login with AWS SSO: {stderr}"
                    )
                return False
            
            # Get credentials
            self.credentials = self._get_credentials(config)
            if not self.credentials:
                return False
            
            # Set up session
            self.is_authenticated = True
            self.expiration_time = datetime.datetime.fromtimestamp(
                self.credentials["Expiration"].timestamp()
            )
            self.start_session_timer()
            
            self.logger.info("AWS SSO authentication successful")
            return True
            
        except Exception as e:
            self.logger.error(f"AWS SSO authentication error: {str(e)}")
            if parent_widget:
                QMessageBox.critical(
                    parent_widget,
                    "AWS SSO Error",
                    f"An error occurred during AWS SSO login: {str(e)}"
                )
            return False
    
    def _get_credentials(self, config: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """
        Get AWS credentials from SSO session.
        
        Args:
            config (Dict[str, str]): SSO configuration
            
        Returns:
            Optional[Dict[str, Any]]: AWS credentials or None if failed
        """
        try:
            sso_client = boto3.client('sso', region_name=config["sso_region"])
            
            # Get SSO access token
            # This is a simplified approach - in production, you'd parse the token from the AWS credentials cache
            # The following command gets credentials directly from the CLI
            credentials_process = subprocess.Popen(
                [
                    "aws", "sso", "get-role-credentials",
                    "--account-id", config["account_id"],
                    "--role-name", config["role_name"],
                    "--region", config["sso_region"],
                    "--output", "json"
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            stdout, stderr = credentials_process.communicate()
            
            if credentials_process.returncode != 0:
                self.logger.error(f"Error getting SSO credentials: {stderr}")
                return None
            
            credentials_data = json.loads(stdout)
            role_credentials = credentials_data.get("roleCredentials", {})
            
            # Format credentials
            credentials = {
                "AccessKeyId": role_credentials.get("accessKeyId"),
                "SecretAccessKey": role_credentials.get("secretAccessKey"),
                "SessionToken": role_credentials.get("sessionToken"),
                "Expiration": datetime.datetime.fromtimestamp(
                    role_credentials.get("expiration") / 1000  # Convert from milliseconds
                )
            }
            
            # Set environment variables for AWS SDK
            os.environ["AWS_ACCESS_KEY_ID"] = credentials["AccessKeyId"]
            os.environ["AWS_SECRET_ACCESS_KEY"] = credentials["SecretAccessKey"]
            os.environ["AWS_SESSION_TOKEN"] = credentials["SessionToken"]
            
            return credentials
            
        except Exception as e:
            self.logger.error(f"Error getting SSO credentials: {str(e)}")
            return None
    
    def is_session_valid(self) -> bool:
        """
        Check if the current session is valid.
        
        Returns:
            bool: True if session is valid
        """
        if not self.is_authenticated or not self.expiration_time:
            return False
        
        now = datetime.datetime.now()
        return now < self.expiration_time
    
    def requires_refresh(self) -> bool:
        """
        Check if the token requires refresh.
        
        Returns:
            bool: True if token needs refresh
        """
        if not self.is_authenticated or not self.expiration_time:
            return False
        
        now = datetime.datetime.now()
        time_to_expiry = (self.expiration_time - now).total_seconds()
        return time_to_expiry < self.refresh_threshold
    
    def refresh_token(self) -> bool:
        """
        Refresh the session token.
        
        Returns:
            bool: True if refresh successful
        """
        if not self.is_authenticated:
            return False
        
        # If using AWS SSO, refresh credentials
        if self.credentials:
            config = self._load_sso_config()
            if not config:
                return False
            
            new_credentials = self._get_credentials(config)
            if not new_credentials:
                return False
            
            self.credentials = new_credentials
            self.expiration_time = datetime.datetime.fromtimestamp(
                self.credentials["Expiration"].timestamp()
            )
            self.logger.info("AWS SSO credentials refreshed")
            return True
        
        # For traditional auth, just extend the expiration time
        self.expiration_time = datetime.datetime.now() + datetime.timedelta(seconds=self.token_ttl)
        self.logger.info("Session token refreshed")
        return True
    
    def logout(self):
        """Perform logout operations."""
        self.is_authenticated = False
        self.session_token = None
        self.expiration_time = None
        self.credentials = None
        self.stop_session_timer()
        
        # Clear AWS environment variables
        if "AWS_ACCESS_KEY_ID" in os.environ:
            del os.environ["AWS_ACCESS_KEY_ID"]
        if "AWS_SECRET_ACCESS_KEY" in os.environ:
            del os.environ["AWS_SECRET_ACCESS_KEY"]
        if "AWS_SESSION_TOKEN" in os.environ:
            del os.environ["AWS_SESSION_TOKEN"]
        
        self.logger.info("User logged out")
    
    def get_remaining_time(self) -> Optional[int]:
        """
        Get remaining session time in seconds.
        
        Returns:
            Optional[int]: Remaining time in seconds or None if not authenticated
        """
        if not self.is_authenticated or not self.expiration_time:
            return None
        
        now = datetime.datetime.now()
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
            "auth_type": "aws_sso" if self.credentials else "password",
            "expiration_time": self.expiration_time.isoformat() if self.expiration_time else None,
            "remaining_seconds": remaining_time,
            "remaining_formatted": self._format_time(remaining_time) if remaining_time else None
        }
    
    def _format_time(self, seconds: int) -> str:
        """
        Format seconds into a human-readable string.
        
        Args:
            seconds (int): Time in seconds
            
        Returns:
            str: Formatted time string (e.g., "1h 30m")
        """
        minutes, seconds = divmod(seconds, 60)
        hours, minutes = divmod(minutes, 60)
        
        if hours > 0:
            return f"{hours}h {minutes}m"
        else:
            return f"{minutes}m {seconds}s"


# For testing the module directly
if __name__ == "__main__":
    from PyQt5.QtWidgets import QApplication
    
    app = QApplication(sys.argv)
    
    session_manager = SessionManager()
    
    # Test AWS SSO authentication
    print("Testing AWS SSO authentication...")
    success = session_manager.authenticate_aws_sso()
    
    if success:
        print("Authentication successful!")
        print("Session info:", session_manager.get_session_info())
        
        # Wait for a moment to test token refresh
        time.sleep(5)
        
        # Test logout
        session_manager.logout()
        print("Logged out.")
        print("Session info:", session_manager.get_session_info())
    else:
        print("Authentication failed!")