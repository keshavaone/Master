"""
Enhanced session management module for the GUARD application.

This module provides secure session management with real AWS SSO integration,
token refresh mechanisms, and expiration handling.
"""

import os
import sys
import time
import json
import hashlib
import logging
import datetime
import boto3
import tempfile
import subprocess
from typing import Dict, Any, Optional, Tuple
from botocore.exceptions import ClientError, ProfileNotFound
from PyQt5.QtWidgets import QMessageBox, QInputDialog, QLineEdit, QProgressDialog
from PyQt5.QtCore import QTimer, QDateTime, QObject, pyqtSignal, QEventLoop


class SessionManager(QObject):
    """
    Enhanced session manager with real AWS SSO integration.

    Manages authentication, session tokens, and provides proper
    expiration and refresh handling based on AWS SSO token TTLs.
    """

    # Signals
    session_expired = pyqtSignal()
    token_refreshed = pyqtSignal()
    session_expiring_soon = pyqtSignal(int)  # Minutes remaining
    auth_success = pyqtSignal(str)  # Authentication type
    auth_failure = pyqtSignal(str)  # Error message

    def __init__(self, parent=None, token_ttl=3600, refresh_threshold=300, warning_threshold=600):
        """
        Initialize the session manager.

        Args:
            parent: Parent QObject
            token_ttl (int): Time-to-live for password session tokens in seconds (default: 1 hour)
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
        self.auth_timestamp = None
        self.auth_ip = None
        self.sso_config = None
        self.aws_profile = None

        # Set up logging
        self.logger = logging.getLogger('SessionManager')
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

        self.logger.info("Session manager initialized")
        
        # Track user IP for audit purposes
        self._get_user_ip()

    def _get_user_ip(self):
        """Get the user's IP address for audit logging."""
        try:
            # Try to get public IP (if connected to internet)
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            self.auth_ip = s.getsockname()[0]
            s.close()
        except:
            # Fallback to hostname if not connected
            self.auth_ip = socket.gethostname()
        
        self.logger.info(f"Session initialized from IP: {self.auth_ip}")

    def _get_now_datetime(self):
        """
        Get a datetime object for the current time that's compatible with self.expiration_time.
        
        Returns:
            datetime.datetime: A datetime object representing the current time
        """
        if self.expiration_time and self.expiration_time.tzinfo:
            # If expiration_time is timezone-aware, create a timezone-aware "now"
            return datetime.datetime.now(datetime.timezone.utc).astimezone(self.expiration_time.tzinfo)
        else:
            # If expiration_time is naive, create a naive "now"
            return datetime.datetime.now()

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
                self.auth_timestamp = datetime.datetime.now()

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

                # Log successful authentication
                self._log_auth_event(True, "Password authentication successful")
                self.auth_success.emit("password")
                return True
            else:
                self._log_auth_event(False, "Password authentication failed - incorrect password")
                self.auth_failure.emit("Incorrect password")
                return False
        except Exception as e:
            error_msg = f"Password authentication error: {str(e)}"
            self.logger.error(error_msg)
            self._log_auth_event(False, error_msg)
            self.auth_failure.emit(f"Authentication error: {str(e)}")
            return False

    def _load_sso_config(self) -> Optional[Dict[str, str]]:
        """
        Load SSO configuration from file.

        Returns:
            Optional[Dict[str, str]]: SSO configuration or None if not found
        """
        config_file = os.path.expanduser("~/.guard_session/sso_config.json")
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                self.logger.info(f"SSO configuration loaded from {config_file}")
                return config
            except Exception as e:
                self.logger.error(f"Error loading SSO config: {str(e)}")
        return None

    def _save_sso_config(self, config: Dict[str, str]):
        """
        Save SSO configuration to file.

        Args:
            config (Dict[str, str]): SSO configuration
        """
        config_dir = os.path.expanduser("~/.guard_session")
        os.makedirs(config_dir, exist_ok=True)

        config_file = os.path.join(config_dir, "sso_config.json")
        with open(config_file, 'w') as f:
            json.dump(config, f)

        self.logger.info(f"SSO configuration saved to {config_file}")

    def authenticate_aws_sso(self, parent_widget=None) -> bool:
        """
        Authenticate using real AWS SSO with actual token retrieval.

        Args:
            parent_widget: Parent widget for dialogs

        Returns:
            bool: True if authentication successful
        """
        try:
            # Load the SSO configuration
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
                        config = self._configure_aws_sso(parent_widget)
                        if not config:
                            self._log_auth_event(False, "AWS SSO configuration failed")
                            return False
                    else:
                        return False
                else:
                    self.logger.error("AWS SSO not configured")
                    return False

            # Store the config
            self.sso_config = config
            
            # Create progress dialog
            progress = None
            if parent_widget:
                progress = QProgressDialog("Authenticating with AWS SSO...", 
                                          "Cancel", 0, 0, parent_widget)
                progress.setWindowTitle("AWS SSO Authentication")
                progress.setModal(True)
                progress.show()
            
            # Set the AWS_PROFILE environment variable if specified
            self.aws_profile = config.get('profile_name', 'guard-sso-profile')
            
            # Prepare AWS SSO login command
            sso_start_url = config.get('sso_start_url')
            sso_region = config.get('sso_region', 'us-east-1')
            
            # First check if we already have valid credentials
            if self._check_existing_sso_credentials():
                self.logger.info("Using existing valid AWS SSO credentials")
                if progress:
                    progress.close()
                return True
            
            # We need to authenticate - display URL to user
            if parent_widget:
                if progress:
                    progress.close()
                    
                result = QMessageBox.information(
                    parent_widget,
                    "AWS SSO Login",
                    f"Please complete your AWS SSO login in the browser. A browser window should open automatically.\n\n"
                    f"If not, please visit:\n{sso_start_url}\n\n"
                    "After logging in through the browser, click OK to continue.",
                    QMessageBox.Ok | QMessageBox.Cancel
                )
                
                if result != QMessageBox.Ok:
                    self._log_auth_event(False, "AWS SSO authentication cancelled by user")
                    return False
                
                # Show progress dialog again
                progress = QProgressDialog("Completing AWS SSO authentication...", 
                                           "Cancel", 0, 0, parent_widget)
                progress.setWindowTitle("AWS SSO Authentication")
                progress.setModal(True)
                progress.show()
            
            # Create a temporary AWS configuration
            with tempfile.TemporaryDirectory() as temp_dir:
                # Set environment variables to use our temporary directory
                env = os.environ.copy()
                env['AWS_CONFIG_FILE'] = os.path.join(temp_dir, 'config')
                env['AWS_SHARED_CREDENTIALS_FILE'] = os.path.join(temp_dir, 'credentials')
                
                # Create the config file
                with open(env['AWS_CONFIG_FILE'], 'w') as f:
                    f.write(f"[profile {self.aws_profile}]\n")
                    f.write(f"sso_start_url = {sso_start_url}\n")
                    f.write(f"sso_region = {sso_region}\n")
                    f.write(f"region = {sso_region}\n")
                    f.write(f"output = json\n")
                
                # Run AWS SSO login
                try:
                    cmd = ["aws", "sso", "login", "--profile", self.aws_profile]
                    self.logger.info(f"Running AWS SSO login command: {' '.join(cmd)}")
                    
                    process = subprocess.Popen(
                        cmd,
                        env=env,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    
                    # Process output in real-time
                    while True:
                        output = process.stdout.readline()
                        if output == '' and process.poll() is not None:
                            break
                        if output:
                            self.logger.info(output.strip())
                            
                    rc = process.poll()
                    if rc != 0:
                        error = process.stderr.read()
                        self.logger.error(f"AWS SSO login failed with code {rc}: {error}")
                        if progress:
                            progress.close()
                        self._log_auth_event(False, f"AWS SSO login command failed: {error}")
                        return False
                    
                    # Get the SSO token information
                    cmd = ["aws", "sts", "get-caller-identity", "--profile", self.aws_profile]
                    process = subprocess.run(
                        cmd,
                        env=env,
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    
                    identity_info = json.loads(process.stdout)
                    self.user_id = identity_info.get('UserId', 'unknown')
                    
                    # Get temporary credentials
                    cmd = ["aws", "sts", "get-session-token", "--profile", self.aws_profile]
                    process = subprocess.run(
                        cmd,
                        env=env,
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    
                    creds_info = json.loads(process.stdout)
                    credentials = creds_info.get('Credentials', {})
                    
                    # Set up the session
                    self.is_authenticated = True
                    self.auth_type = "aws_sso"
                    self.auth_timestamp = datetime.datetime.now()
                    self.session_token = credentials.get('SessionToken')
                    
                    # AWS SSO tokens typically expire in 8 hours
                    expiry_str = credentials.get('Expiration')
                    if expiry_str:
                        # Parse ISO format datetime
                        expiry_datetime = datetime.datetime.fromisoformat(
                            expiry_str.replace('Z', '+00:00'))
                        # Convert to local timezone
                        self.expiration_time = expiry_datetime.replace(
                            tzinfo=datetime.timezone.utc).astimezone(tz=None)
                    else:
                        # Fallback to 8 hours if no expiration provided
                        self.expiration_time = datetime.datetime.now() + datetime.timedelta(hours=8)
                    
                    # Store credentials
                    self.credentials = {
                        'AccessKeyId': credentials.get('AccessKeyId'),
                        'SecretAccessKey': credentials.get('SecretAccessKey'),
                        'SessionToken': credentials.get('SessionToken'),
                        'Expiration': expiry_str
                    }
                    
                    # Set environment variables for AWS services to use
                    os.environ['AWS_ACCESS_KEY_ID'] = credentials.get('AccessKeyId', '')
                    os.environ['AWS_SECRET_ACCESS_KEY'] = credentials.get('SecretAccessKey', '')
                    os.environ['AWS_SESSION_TOKEN'] = credentials.get('SessionToken', '')
                    
                    # Start the session timer
                    self.start_session_timer()
                    
                    if progress:
                        progress.close()
                    
                    # Log successful authentication
                    self._log_auth_event(True, "AWS SSO authentication successful")
                    self.auth_success.emit("aws_sso")
                    return True
                    
                except subprocess.CalledProcessError as e:
                    if progress:
                        progress.close()
                    error_msg = f"AWS SSO command failed: {e.stderr}"
                    self.logger.error(error_msg)
                    self._log_auth_event(False, error_msg)
                    self.auth_failure.emit(error_msg)
                    return False
                except Exception as e:
                    if progress:
                        progress.close()
                    error_msg = f"AWS SSO authentication error: {str(e)}"
                    self.logger.error(error_msg)
                    self._log_auth_event(False, error_msg)
                    self.auth_failure.emit(f"Authentication error: {str(e)}")
                    return False
        except Exception as e:
            error_msg = f"Unexpected error during AWS SSO authentication: {str(e)}"
            self.logger.error(error_msg)
            self._log_auth_event(False, error_msg)
            if parent_widget:
                QMessageBox.critical(
                    parent_widget,
                    "AWS SSO Error",
                    error_msg
                )
            return False

    def _configure_aws_sso(self, parent_widget) -> Optional[Dict[str, str]]:
        """
        Configure AWS SSO settings through UI dialog.

        Args:
            parent_widget: Parent widget for dialogs

        Returns:
            Optional[Dict[str, str]]: SSO configuration or None if cancelled
        """
        if parent_widget:
            # Get SSO start URL
            sso_url, ok = QInputDialog.getText(
                parent_widget,
                "AWS SSO Configuration",
                "Enter SSO start URL:",
                QLineEdit.Normal,
                "https://d-9067c603c9.awsapps.com/start/"
            )
            if not ok or not sso_url:
                return None

            # Get SSO region
            sso_region, ok = QInputDialog.getText(
                parent_widget,
                "AWS SSO Configuration",
                "Enter SSO region:",
                QLineEdit.Normal,
                "us-east-1"
            )
            if not ok or not sso_region:
                return None

            # Get account ID
            account_id, ok = QInputDialog.getText(
                parent_widget,
                "AWS SSO Configuration",
                "Enter AWS account ID:",
                QLineEdit.Normal,
                "817215275254"
            )
            if not ok or not account_id:
                return None

            # Get role name
            role_name, ok = QInputDialog.getText(
                parent_widget,
                "AWS SSO Configuration",
                "Enter role name:",
                QLineEdit.Normal,
                "PowerUserAccess"
            )
            if not ok or not role_name:
                return None

            # Get profile name
            profile_name, ok = QInputDialog.getText(
                parent_widget,
                "AWS SSO Configuration",
                "Enter AWS profile name:",
                QLineEdit.Normal,
                "guard_session"
            )
            if not ok or not profile_name:
                return None

            # Save configuration
            config = {
                'sso_start_url': sso_url,
                'sso_region': sso_region,
                'account_id': account_id,
                'role_name': role_name,
                'profile_name': profile_name
            }

            self._save_sso_config(config)
            return config
        return None

    def _check_existing_sso_credentials(self) -> bool:
        """
        Check if we have existing valid AWS SSO credentials.

        Returns:
            bool: True if valid credentials exist
        """
        try:
            # Check if the AWS CLI has valid credentials
            process = subprocess.run(
                ["aws", "sts", "get-caller-identity"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Parse the identity information
            identity_info = json.loads(process.stdout)
            self.user_id = identity_info.get('UserId', 'unknown')
            
            # Get session token information
            session_info = None
            try:
                process = subprocess.run(
                    ["aws", "sts", "get-session-token"],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                session_info = json.loads(process.stdout)
            except:
                # If get-session-token fails, the user might have permanent credentials
                # We'll create a session with 8 hours expiration
                self.is_authenticated = True
                self.auth_type = "aws_sso"
                self.auth_timestamp = datetime.datetime.now()
                self.session_token = f"sso-{int(time.time())}-{os.urandom(4).hex()}"
                self.expiration_time = datetime.datetime.now() + datetime.timedelta(hours=8)
                
                # Attempt to get credentials from AWS CLI config
                try:
                    # Try to get credentials from AWS CLI configuration
                    aws_config_file = os.path.expanduser("~/.aws/credentials")
                    if os.path.exists(aws_config_file):
                        self.logger.info("Reading AWS credentials from ~/.aws/credentials")
                        # Parse the credentials file
                        import configparser
                        config = configparser.ConfigParser()
                        config.read(aws_config_file)
                        
                        # Try default profile first, then any available profile
                        profile = os.environ.get('AWS_PROFILE', 'default')
                        if profile not in config.sections() and config.sections():
                            profile = config.sections()[0]
                            
                        if profile in config.sections():
                            # Set environment variables from the credentials file
                            os.environ['AWS_ACCESS_KEY_ID'] = config[profile].get('aws_access_key_id', '')
                            os.environ['AWS_SECRET_ACCESS_KEY'] = config[profile].get('aws_secret_access_key', '')
                            if 'aws_session_token' in config[profile]:
                                os.environ['AWS_SESSION_TOKEN'] = config[profile].get('aws_session_token', '')
                            self.logger.info(f"Set AWS credentials from profile: {profile}")
                            
                            # Create dummy credentials for storage
                            self.credentials = {
                                'AccessKeyId': os.environ.get('AWS_ACCESS_KEY_ID', ''),
                                'SecretAccessKey': os.environ.get('AWS_SECRET_ACCESS_KEY', ''),
                                'SessionToken': os.environ.get('AWS_SESSION_TOKEN', '')
                            }
                except Exception as e:
                    self.logger.error(f"Error reading AWS credentials file: {e}")
                
                # Start the session timer
                self.start_session_timer()
                
                # Log successful authentication
                self._log_auth_event(True, "Using existing AWS credentials")
                self.auth_success.emit("aws_sso")
                return True
            
            if session_info:
                credentials = session_info.get('Credentials', {})
                
                # Set up the session
                self.is_authenticated = True
                self.auth_type = "aws_sso"
                self.auth_timestamp = datetime.datetime.now()
                self.session_token = credentials.get('SessionToken')
                
                # Parse expiration time
                expiry_str = credentials.get('Expiration')
                if expiry_str:
                    # Parse ISO format datetime
                    expiry_datetime = datetime.datetime.fromisoformat(
                        expiry_str.replace('Z', '+00:00'))
                    # Convert to local timezone
                    self.expiration_time = expiry_datetime.replace(
                        tzinfo=datetime.timezone.utc).astimezone(tz=None)
                else:
                    # Fallback to 8 hours if no expiration provided
                    self.expiration_time = datetime.datetime.now() + datetime.timedelta(hours=8)
                
                # Store credentials
                self.credentials = {
                    'AccessKeyId': credentials.get('AccessKeyId'),
                    'SecretAccessKey': credentials.get('SecretAccessKey'),
                    'SessionToken': credentials.get('SessionToken'),
                    'Expiration': expiry_str
                }
                
                # IMPORTANT: Explicitly set environment variables for AWS services to use
                # This ensures they're available for all parts of the application
                os.environ['AWS_ACCESS_KEY_ID'] = credentials.get('AccessKeyId', '')
                os.environ['AWS_SECRET_ACCESS_KEY'] = credentials.get('SecretAccessKey', '')
                os.environ['AWS_SESSION_TOKEN'] = credentials.get('SessionToken', '')
                self.logger.info("Set AWS credentials in environment variables")
                
                # Start the session timer
                self.start_session_timer()
                
                # Log successful authentication
                self._log_auth_event(True, "Using existing AWS session token")
                self.auth_success.emit("aws_sso")
                return True
            
            return False
            
        except subprocess.CalledProcessError:
            self.logger.info("No valid AWS credentials found")
            return False
        except Exception as e:
            self.logger.error(f"Error checking existing credentials: {str(e)}")
            return False

    def is_session_valid(self) -> bool:
        """
        Check if the current session is valid.

        Returns:
            bool: True if session is valid
        """
        if not self.is_authenticated or not self.expiration_time:
            return False

        now = self._get_now_datetime()
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

        now = self._get_now_datetime()
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
            try:
                # For AWS SSO, we need to validate the token and possibly re-authenticate
                # Try to call a lightweight AWS service to test if credentials are valid
                boto3.client('sts').get_caller_identity()
                
                # If successful with AWS SSO and we're getting close to expiration,
                # attempt to obtain a new session token
                if self.requires_refresh() and self.credentials:
                    try:
                        # Try to get a new session token
                        sts = boto3.client('sts')
                        response = sts.get_session_token()
                        
                        # Update credentials with new session token
                        if 'Credentials' in response:
                            credentials = response['Credentials']
                            self.session_token = credentials['SessionToken']
                            
                            # Update expiration time
                            expiry_datetime = credentials['Expiration']
                            if isinstance(expiry_datetime, str):
                                expiry_datetime = datetime.datetime.fromisoformat(
                                    expiry_datetime.replace('Z', '+00:00'))
                            self.expiration_time = expiry_datetime.replace(
                                tzinfo=datetime.timezone.utc).astimezone(tz=None)
                            
                            # Update stored credentials
                            self.credentials = {
                                'AccessKeyId': credentials['AccessKeyId'],
                                'SecretAccessKey': credentials['SecretAccessKey'],
                                'SessionToken': credentials['SessionToken'],
                                'Expiration': credentials['Expiration'].isoformat() if hasattr(credentials['Expiration'], 'isoformat') else credentials['Expiration']
                            }
                            
                            # Update environment variables
                            os.environ['AWS_ACCESS_KEY_ID'] = credentials['AccessKeyId']
                            os.environ['AWS_SECRET_ACCESS_KEY'] = credentials['SecretAccessKey']
                            os.environ['AWS_SESSION_TOKEN'] = credentials['SessionToken']
                            
                            self.logger.info(f"AWS session token refreshed, new expiration: {self.expiration_time}")
                            return True
                            
                    except Exception as e:
                        self.logger.warning(f"Failed to refresh AWS session token: {str(e)}")
                        # Continue with existing token if refresh fails
                
                # If we didn't successfully refresh but the token is still valid,
                # just extend the timeout
                if not self.requires_refresh():
                    return True
                    
                # For AWS SSO we can't easily refresh automatically without user interaction
                # Instead we'll check if the existing token is still valid
                return True
                
            except Exception as e:
                self.logger.warning(f"AWS SSO token validation failed: {str(e)}")
                return False

        else:  # "password" auth type
            # For password auth, just extend the expiration time
            self.expiration_time = datetime.datetime.now() + datetime.timedelta(seconds=self.token_ttl)
            self.logger.info(
                f"Password token refreshed, new expiration: {self.expiration_time}")
            return True

    def logout(self):
        """Perform logout operations."""
        self.logger.info(f"Logging out user {self.user_id}")

        # Log the logout event
        if self.is_authenticated:
            self._log_auth_event(True, "User logged out")

        self.is_authenticated = False
        self.session_token = None
        self.expiration_time = None
        self.credentials = None
        self.auth_type = None
        previous_user = self.user_id
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

        self.logger.info(f"Logout complete for user {previous_user}")

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
            "aws_profile": self.aws_profile
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
            
    def _log_auth_event(self, success: bool, message: str):
        """
        Log an authentication event for audit purposes.
        
        Args:
            success (bool): Whether the authentication was successful
            message (str): A message describing the event
        """
        event_type = "SUCCESS" if success else "FAILURE"
        auth_type = self.auth_type if self.auth_type else "N/A"
        user = self.user_id if self.user_id else "unknown"
        timestamp = datetime.datetime.now().isoformat()
        
        log_entry = {
            "timestamp": timestamp,
            "event_type": f"AUTH_{event_type}",
            "auth_type": auth_type,
            "user": user,
            "ip_address": self.auth_ip,
            "message": message
        }
        
        # Log to application log
        self.logger.info(f"AUTH: {json.dumps(log_entry)}")
        
        # Write to audit log file
        try:
            log_dir = os.path.expanduser("~/.guard_session/logs")
            os.makedirs(log_dir, exist_ok=True)
            
            log_file = os.path.join(log_dir, "auth_audit.log")
            with open(log_file, 'a') as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            self.logger.error(f"Failed to write to audit log: {str(e)}")
            
    def get_auth_token(self) -> Optional[str]:
        """
        Get the current authentication token for API requests.
        
        Returns:
            Optional[str]: The authentication token or None if not authenticated
        """
        if not self.is_authenticated:
            return None
            
        if self.auth_type == "aws_sso" and self.credentials:
            # For AWS SSO, use the session token
            return self.credentials.get('SessionToken')
        else:
            # For password auth, use our generated token
            return self.session_token
            
    def get_auth_headers(self) -> Dict[str, str]:
        """
        Get authentication headers for API requests.
        
        Returns:
            Dict[str, str]: Headers to include in API requests
        """
        headers = {}
        
        if self.is_authenticated:
            # Add token to Authorization header
            token = self.get_auth_token()
            if token:
                headers["Authorization"] = f"Bearer {token}"
                
            # Add user info
            if self.user_id:
                headers["X-User-ID"] = self.user_id
                
            # Add authentication type
            if self.auth_type:
                headers["X-Auth-Type"] = self.auth_type
        
        return headers