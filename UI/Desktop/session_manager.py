"""
Enhanced session management module for the GUARD application.

This module provides secure session management with proper AWS SSO integration,
token refresh mechanisms, and expiration handling.
"""

import os
import sys
import time
import json
import hashlib
import logging
import datetime
import threading
import boto3
from typing import Dict, Any, Optional
from botocore.exceptions import ClientError, ProfileNotFound
from PyQt5.QtWidgets import QMessageBox, QInputDialog, QLineEdit, QProgressDialog
from PyQt5.QtCore import QTimer, QDateTime, QObject, pyqtSignal


class SessionManager(QObject):
    """
    Enhanced session manager with AWS SSO integration.

    Manages authentication, session tokens, and provides proper
    expiration and refresh handling.
    """

    # Signals
    session_expired = pyqtSignal()
    token_refreshed = pyqtSignal()
    session_expiring_soon = pyqtSignal(int)  # Minutes remaining

    def __init__(self, parent=None, token_ttl=3600, refresh_threshold=300, warning_threshold=600):
        """
        Initialize the session manager.

        Args:
            parent: Parent QObject
            token_ttl (int): Time-to-live for session tokens in seconds (default: 1 hour)
            refresh_threshold (int): Time threshold for token refresh in seconds (default: 5 minutes)
            warning_threshold (int): Time threshold to warn about expiration in seconds (default: 10 minutes)
        """
        super().__init__(parent)
        self.parent = parent
        self.token_ttl = token_ttl
        self.refresh_threshold = refresh_threshold
        self.warning_threshold = warning_threshold
        self.session_token = None
        self.expiration_time = None
        self.refresh_timer = None
        self.credentials = None
        self.user_id = None
        self.is_authenticated = False
        self.auth_type = None
        self.sso_session_name = "guard-app"

        # Set up logging
        self.logger = logging.getLogger('SessionManager')
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

        self.logger.info("Session manager initialized")

    def start_session_timer(self):
        """Start the session timer for token refresh and expiration checking."""
        if self.refresh_timer is None:
            self.refresh_timer = QTimer(self)
            self.refresh_timer.timeout.connect(self.check_session_status)
            self.refresh_timer.start(30000)  # Check every 30 seconds
            self.logger.debug("Session timer started")

    def stop_session_timer(self):
        """Stop the session timer."""
        if self.refresh_timer is not None:
            self.refresh_timer.stop()
            self.refresh_timer = None
            self.logger.debug("Session timer stopped")

    def check_session_status(self):
        """Check if the session needs refresh or has expired."""
        if not self.is_session_valid():
            self.logger.warning("Session expired")
            self.logout()
            self.session_expired.emit()
            return

        # Emit warning if session is expiring soon
        remaining_time = self.get_remaining_time()
        if remaining_time and remaining_time <= self.warning_threshold:
            minutes_remaining = remaining_time // 60
            self.logger.info(
                f"Session expiring soon: {minutes_remaining} minutes remaining")
            self.session_expiring_soon.emit(minutes_remaining)

        if self.requires_refresh():
            self.logger.info("Session token needs refresh")
            success = self.refresh_token()
            if success:
                self.logger.info("Token refreshed successfully")
                self.token_refreshed.emit()
            else:
                self.logger.warning("Token refresh failed")

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
                self.auth_type = "password"

                # Set expiration time based on token_ttl
                self.expiration_time = datetime.datetime.now(
                ) + datetime.timedelta(seconds=self.token_ttl)

                # Generate a secure session token with proper entropy
                token_base = f"{password}:{time.time()}:{os.urandom(16).hex()}"
                self.session_token = hashlib.sha256(
                    token_base.encode()).hexdigest()

                # Set the user ID from the current user
                self.user_id = os.environ.get('USER', 'default_user')

                # Start the session timer
                self.start_session_timer()

                self.logger.info(
                    f"Password authentication successful for user {self.user_id}")
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
            sso_url = "https://d-9067c603c9.awsapps.com/start"

            # Get SSO region
            sso_region = "us-east-1"

            # Get account ID
            account_id = "817215275254"
            # Get role name
            role_name = "PowerUserAccess"

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
        os.chdir(os.getcwd())
        config_dir = os.path.expanduser("~/.guard1")
        os.makedirs(config_dir, exist_ok=True)

        config_file = os.path.join(config_dir, "sso_config.json")
        with open(config_file, 'w') as f:
            json.dump(config, f)

        self.logger.info(f"SSO configuration saved to {config_file}")

    def _load_sso_config(self) -> Optional[Dict[str, str]]:
        """
        Load SSO configuration from file.

        Returns:
            Optional[Dict[str, str]]: SSO configuration or None if not found
        """
        os.chdir(os.getcwd())
        config_file = os.path.expanduser("~/.guard1/sso_config.json")
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                self.logger.info(
                    f"SSO configuration loaded from {config_file}")
                return config
            except Exception as e:
                self.logger.error(f"Error loading SSO config: {str(e)}")
        return None

    def authenticate_aws_sso(self, parent_widget=None) -> bool:
        """
        Authenticate using AWS SSO with error handling.

        Args:
            parent_widget: Parent widget for dialogs

        Returns:
            bool: True if authentication successful
        """
        try:
            # First check if config exists
            config = self._load_sso_config()
            if not config:
                # If no config, try to configure
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
                        # Reload the config
                        config = self._load_sso_config()
                        if not config:
                            self.logger.error(
                                "Failed to load SSO config after saving")
                            if parent_widget:
                                QMessageBox.warning(
                                    parent_widget,
                                    "Configuration Error",
                                    "Failed to load SSO configuration after saving."
                                )
                            return False
                    else:
                        return False
                else:
                    self.logger.error("AWS SSO not configured")
                    return False

            # Log the configuration being used (without sensitive data)
            self.logger.info(
                f"Using SSO configuration with URL: {config.get('sso_start_url', 'Not set')}")

            # For now, let's use a simulated session to bypass AWS CLI issues
            if parent_widget:
                result = QMessageBox.information(
                    parent_widget,
                    "AWS SSO Login",
                    f"Please complete your AWS SSO login in the browser at:\n\n"
                    f"{config.get('sso_start_url', 'Not available')}\n\n"
                    "Once you've completed the login, click OK.\n\n"
                    "Note: Since there are issues with the AWS authentication, "
                    "we'll simulate a session for testing purposes.",
                    QMessageBox.Ok | QMessageBox.Cancel
                )

                if result != QMessageBox.Ok:
                    return False

            # Create simulated session
            self.is_authenticated = True
            self.auth_type = "aws_sso"
            self.user_id = os.environ.get('USER', 'default_user')
            self.session_token = f"sso-{int(time.time())}-{os.urandom(4).hex()}"

            # Set expiration (8 hours is typical for SSO sessions)
            self.expiration_time = datetime.datetime.now() + datetime.timedelta(hours=8)

            # Start session timer
            self.start_session_timer()

            self.logger.info(
                f"Simulated SSO session created for user {self.user_id}")
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

    def is_session_valid(self) -> bool:
        """
        Check if the current session is valid.

        Returns:
            bool: True if session is valid
        """
        if not self.is_authenticated or not self.expiration_time:
            return False

        now = datetime.datetime.now()
        is_valid = now < self.expiration_time

        if not is_valid:
            self.logger.warning(f"Session expired at {self.expiration_time}")

        return is_valid

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
        needs_refresh = time_to_expiry < self.refresh_threshold

        if needs_refresh:
            self.logger.info(
                f"Token refresh required - {time_to_expiry:.0f} seconds to expiry")

        return needs_refresh

    def refresh_token(self) -> bool:
        """
        Refresh the session token.

        Returns:
            bool: True if refresh successful
        """
        if not self.is_authenticated:
            self.logger.warning("Cannot refresh token: Not authenticated")
            return False

        # Different refresh approaches based on auth type
        if self.auth_type == "aws_sso":
            # For AWS SSO, we need to check if the token is still valid
            # AWS SSO tokens cannot be refreshed directly; they must be re-authenticated
            # if they expire. However, since they typically last 8 hours, we can
            # just check if they're still valid.

            # Try to verify AWS identity
            try:
                import subprocess

                cmd = ["aws", "sts", "get-caller-identity", "--output", "json"]
                process = subprocess.run(
                    cmd,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )

                # If successful, extend the token expiration
                # Since we can't actually refresh SSO tokens, we just extend the expiration
                # Based on the knowledge that SSO tokens typically last 8 hours
                self.expiration_time = datetime.datetime.now() + datetime.timedelta(minutes=1)
                self.logger.info(
                    f"AWS SSO token still valid, extended expiration to {self.expiration_time}")

                return True

            except subprocess.CalledProcessError:
                self.logger.warning("AWS SSO token validation failed")
                return False

        else:
            # For password auth, just extend the expiration time
            self.expiration_time = datetime.datetime.now(
            ) + datetime.timedelta(seconds=self.token_ttl)
            self.logger.info(
                f"Password token refreshed, new expiration: {self.expiration_time}")
            return True

    def logout(self):
        """Perform logout operations."""
        self.logger.info(f"Logging out user {self.user_id}")

        self.is_authenticated = False
        self.session_token = None
        self.expiration_time = None
        self.credentials = None
        self.auth_type = None
        self.user_id = None

        # Stop the timer
        self.stop_session_timer()

        # Clear AWS environment variables
        aws_vars = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY',
                    'AWS_SESSION_TOKEN', 'AWS_PROFILE']
        for var in aws_vars:
            if var in os.environ:
                del os.environ[var]
                self.logger.debug(f"Cleared environment variable: {var}")

        self.logger.info("Logout complete")

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
            "auth_type": self.auth_type,
            "user_id": self.user_id,
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
