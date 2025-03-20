"""
Enhanced session management module for the GUARD application.

This module provides secure session management with real AWS SSO integration,
token refresh mechanisms, and expiration handling.
"""

import os
import time
import json
import hashlib
import logging
import datetime
import boto3
import subprocess
from typing import Dict, Any, Optional
from PyQt5.QtWidgets import QInputDialog, QLineEdit
from PyQt5.QtCore import QTimer, QObject, pyqtSignal


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
        config_file = os.path.expanduser("~/.guard_config/sso_config.json")
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
        config_dir = os.path.expanduser("~/.guard_config")
        os.makedirs(config_dir, exist_ok=True)

        config_file = os.path.join(config_dir, "sso_config.json")
        with open(config_file, 'w') as f:
            json.dump(config, f)

        self.logger.info(f"SSO configuration saved to {config_file}")

    def authenticate_aws_sso(self, parent_widget=None) -> bool:
        """Authenticate with AWS SSO correctly."""
        try:
            # Import Qt namespace explicitly
            from PyQt5.QtCore import Qt, QTimer
            from PyQt5.QtWidgets import QProgressDialog, QMessageBox, QApplication

            # Create progress dialog that can be updated
            progress_dialog = QProgressDialog("Initializing AWS SSO login...", "Cancel", 0, 100, parent_widget)
            progress_dialog.setWindowTitle("AWS SSO Login")
            progress_dialog.setWindowModality(Qt.WindowModal)
            progress_dialog.setMinimumDuration(0)
            progress_dialog.setValue(10)
            progress_dialog.show()
            QApplication.processEvents()  # Ensure UI updates
            
            # Get available profiles
            progress_dialog.setLabelText("Reading AWS configuration...")
            progress_dialog.setValue(20)
            QApplication.processEvents()
            
            import configparser
            config_file = os.path.expanduser("~/.aws/config")
            if not os.path.exists(config_file):
                progress_dialog.close()
                QMessageBox.warning(parent_widget, "AWS SSO Error", 
                                "AWS CLI not configured.\n\nPlease run the following commands in your terminal:\n"
                                "1. aws configure sso\n"
                                "2. Follow prompts to set up SSO")
                return False
                
            config = configparser.ConfigParser()
            config.read(config_file)
            
            sso_profiles = []
            for section in config.sections():
                if section.startswith("profile ") and "sso_start_url" in config[section]:
                    sso_profiles.append(section.replace("profile ", ""))
            
            if not sso_profiles:
                progress_dialog.close()
                QMessageBox.warning(parent_widget, "AWS SSO Error", 
                                "No SSO profiles found in AWS config.\n\n"
                                "Please run 'aws configure sso' to set up an SSO profile.")
                return False
            
            # Use first SSO profile (or let user select if multiple profiles)
            selected_profile = "PowerUserAccess-817215275254"
            if len(sso_profiles) > 1 and parent_widget:
                from PyQt5.QtWidgets import QInputDialog
                selected_profile, ok = QInputDialog.getItem(
                    parent_widget, 
                    "Select AWS Profile", 
                    "Multiple AWS SSO profiles found. Please select one:", 
                    sso_profiles, 
                    0, 
                    False
                )
                if not ok:
                    progress_dialog.close()
                    return False
            
            # Update progress
            progress_dialog.setLabelText(f"Logging in with profile: {selected_profile}\n\nA browser window will open for authentication.")
            progress_dialog.setValue(30)
            QApplication.processEvents()
            
            # Run login process (this will open browser)
            try:
                self.logger.info(f"Starting AWS SSO login with profile {selected_profile}")
                progress_dialog.setLabelText("Opening browser for SSO login.\n\nPlease complete the login in your browser.")
                progress_dialog.setValue(40)
                QApplication.processEvents()
                
                login_process = subprocess.run(
                    ["aws", "sso", "login", "--profile", selected_profile], 
                    check=True,
                    capture_output=True,
                    text=True
                )
                
                self.logger.info(f"AWS SSO login process completed: {login_process.stdout}")
                progress_dialog.setLabelText("Browser login completed.\nRetrieving credentials...")
                progress_dialog.setValue(60)
                QApplication.processEvents()
                
            except subprocess.CalledProcessError as e:
                progress_dialog.close()
                error_message = f"AWS SSO login failed:\n{e.stderr}"
                self.logger.error(error_message)
                QMessageBox.warning(parent_widget, "AWS SSO Error", error_message)
                return False
            
            # Create session with profile
            progress_dialog.setLabelText("Creating AWS session with SSO credentials...")
            progress_dialog.setValue(70)
            QApplication.processEvents()
            
            # Add retry mechanism for credential retrieval
            max_retries = 3
            retry_delay = 2  # seconds
            
            for retry in range(max_retries):
                try:
                    # After browser login completes successfully:
                    self.logger.info("Browser login completed. Waiting for credentials...")
                    progress_dialog.setLabelText("Browser login completed.\nRetrieving credentials...")
                    progress_dialog.setValue(60)
                    QApplication.processEvents()

                    # Wait a moment for credentials to be written to disk
                    time.sleep(2)

                    # Add improved retry mechanism for credential retrieval
                    max_retries = 5
                    retry_delays = [1, 2, 3, 5, 8]  # Increasing delays between retries
                    credentials = None

                    for retry, delay in enumerate(retry_delays):
                        try:
                            self.logger.info(f"Credential retrieval attempt {retry+1}/{max_retries}...")
                            progress_dialog.setLabelText(f"Attempting to retrieve credentials... ({retry+1}/{max_retries})")
                            progress_dialog.setValue(60 + (retry * 5))
                            QApplication.processEvents()
                            
                            # Method 1: Standard boto3 session approach
                            session = boto3.Session(profile_name=selected_profile)
                            credentials = session.get_credentials()
                            
                            if credentials and hasattr(credentials, 'access_key') and credentials.access_key:
                                self.logger.info("Successfully retrieved credentials via boto3 Session")
                                break  # Success!
                            
                            # Method 2: Alternative direct token loading from SSO cache
                            import glob
                            import json
                            cache_dir = os.path.expanduser('~/.aws/sso/cache')
                            token_files = glob.glob(os.path.join(cache_dir, '*.json'))
                            
                            if token_files:
                                self.logger.info(f"Found {len(token_files)} SSO cache files, trying most recent...")
                                # Sort by modification time (newest first)
                                token_files.sort(key=os.path.getmtime, reverse=True)
                                
                                with open(token_files[0], 'r') as f:
                                    try:
                                        token_data = json.load(f)
                                        if 'accessToken' in token_data:
                                            self.logger.info("Found access token in SSO cache")
                                            # Could use this token directly with AWS APIs if needed
                                    except json.JSONDecodeError:
                                        self.logger.warning(f"Failed to parse JSON from cache file")
                            
                            # Method 3: Try invoking AWS CLI directly to get caller identity
                            try:
                                self.logger.info(f"Trying AWS CLI directly...")
                                result = subprocess.run(
                                    ["aws", "sts", "get-caller-identity", "--profile", selected_profile], 
                                    capture_output=True, 
                                    text=True,
                                    check=True
                                )
                                
                                if result.returncode == 0:
                                    self.logger.info("AWS CLI successfully retrieved identity")
                                    # AWS CLI worked, so credentials should be available now
                                    session = boto3.Session(profile_name=selected_profile)
                                    credentials = session.get_credentials()
                                    
                                    if credentials and hasattr(credentials, 'access_key') and credentials.access_key:
                                        self.logger.info("Successfully retrieved credentials after AWS CLI call")
                                        break  # Success!
                            except subprocess.CalledProcessError:
                                self.logger.warning("AWS CLI identity check failed")
                            
                        except Exception as session_error:
                            self.logger.warning(f"Credential retrieval attempt {retry+1} failed: {str(session_error)}")
                        
                        # Wait before retrying if we're not on the last attempt
                        if retry < len(retry_delays) - 1:
                            self.logger.info(f"Waiting {delay}s before next attempt...")
                            time.sleep(delay)
                    
                    if credentials and hasattr(credentials, 'access_key') and credentials.access_key:
                        break  # Successful credentials retrieval
                    
                    if retry < max_retries - 1:
                        # Wait and retry
                        progress_dialog.setLabelText(f"Waiting for credentials (attempt {retry+1}/{max_retries})...")
                        QApplication.processEvents()
                        time.sleep(retry_delay)
                except Exception as session_error:
                    self.logger.warning(f"Credential retrieval attempt {retry+1} failed: {str(session_error)}")
                    if retry < max_retries - 1:
                        time.sleep(retry_delay)
            
            if not credentials or not hasattr(credentials, 'access_key') or not credentials.access_key:
                progress_dialog.close()
                
                # Try to provide useful diagnostics for troubleshooting
                
                diagnostic_info = "Diagnostics not available"
                try:
                    # Check if profile exists
                    profile_check = subprocess.run(
                        ["aws", "configure", "list-profiles"],
                        capture_output=True,
                        text=True
                    )
                    profiles = profile_check.stdout.strip().split('\n')
                    has_profile = selected_profile in profiles
                    
                    # Try to get error from AWS CLI
                    cli_error = "Not available"
                    try:
                        cli_test = subprocess.run(
                            ["aws", "sts", "get-caller-identity", "--profile", selected_profile],
                            capture_output=True,
                            text=True
                        )
                        cli_error = cli_test.stderr or "No error (but still no credentials)"
                    except Exception:
                        pass
                        
                    diagnostic_info = (
                        f"Profile '{selected_profile}' exists: {has_profile}\n"
                        f"Profiles found: {', '.join(profiles)}\n"
                        f"AWS CLI error: {cli_error}"
                    )
                except Exception as diag_error:
                    diagnostic_info = f"Error getting diagnostics: {str(diag_error)}"
                
                # Report detailed error
                error_message = (
                    "Failed to obtain AWS credentials after successful browser login.\n\n"
                    "This could be due to:\n"
                    "1. SSO session not fully established\n"
                    "2. Profile configuration issues\n"
                    "3. Profile name mismatch\n\n"
                    f"Diagnostic information:\n{diagnostic_info}\n\n"
                    f"Please try running 'aws sts get-caller-identity --profile {selected_profile}' "
                    "in your terminal to verify credentials."
                )
                self.logger.error(error_message)
                QMessageBox.warning(parent_widget, "AWS SSO Error", error_message)
                return False
                
            # Verify credentials with a simple API call
            progress_dialog.setLabelText("Verifying credentials...")
            progress_dialog.setValue(80)
            QApplication.processEvents()
            
            try:
                sts = session.client('sts')
                caller_identity = sts.get_caller_identity()
                self.logger.info(f"AWS identity verified: {caller_identity['UserId']}")
            except Exception as verify_error:
                progress_dialog.close()
                error_message = f"Failed to verify AWS credentials:\n{str(verify_error)}"
                self.logger.error(error_message)
                QMessageBox.warning(parent_widget, "AWS SSO Error", error_message)
                return False
            
            # Set up session
            progress_dialog.setLabelText("Setting up authenticated session...")
            progress_dialog.setValue(90)
            QApplication.processEvents()
            
            self.is_authenticated = True
            self.auth_type = "aws_sso"
            self.auth_timestamp = datetime.datetime.now()
            self.user_id = caller_identity.get('UserId', 'unknown')
            
            # Store credentials
            self.session_token = credentials.token if hasattr(credentials, 'token') else None
            self.credentials = {
                'AccessKeyId': credentials.access_key,
                'SecretAccessKey': credentials.secret_key,
            }
            if self.session_token:
                self.credentials['SessionToken'] = self.session_token
                
            # Set expiration from credentials
            if hasattr(credentials, '_expiry_time') and credentials._expiry_time:
                self.expiration_time = credentials._expiry_time
            else:
                # Default to 8 hours if we can't determine the actual expiry
                self.expiration_time = datetime.datetime.now() + datetime.timedelta(hours=8)
                
            # Start session timer
            self.start_session_timer()
            
            # Set environment variables for processes
            os.environ['AWS_ACCESS_KEY_ID'] = credentials.access_key
            os.environ['AWS_SECRET_ACCESS_KEY'] = credentials.secret_key
            if self.session_token:
                os.environ['AWS_SESSION_TOKEN'] = self.session_token
            
            # Complete
            progress_dialog.setLabelText("AWS SSO authentication complete!")
            progress_dialog.setValue(100)
            QApplication.processEvents()
            
            # Slight delay before closing to show completion
            QTimer.singleShot(1000, progress_dialog.close)
            
            # Log success
            self.logger.info(f"AWS SSO authentication successful for user: {self.user_id}")
            self.logger.info(f"Credential expiration: {self.expiration_time}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"AWS SSO authentication error: {str(e)}")
            
            if 'progress_dialog' in locals():
                progress_dialog.close()
                
            if parent_widget:
                import traceback
                error_details = traceback.format_exc()
                self.logger.error(f"Detailed error: {error_details}")
                
                QMessageBox.warning(
                    parent_widget, 
                    "AWS SSO Error", 
                    f"Authentication error: {str(e)}\n\nPlease check the application logs for more details."
                )
                
            return False
        
    def _run_aws_sso_login(self, profile_name):
        """
        Run AWS SSO login process for the specified profile.
        """
        try:
            subprocess.run(
                ["aws", "sso", "login", "--profile", profile_name], 
                check=True,
                capture_output=True
            )
        except subprocess.CalledProcessError as e:
            raise ValueError(f"AWS SSO login failed: {e.stderr.decode()}")

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
                    "PowerUserAccess-817215275254"
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
            except subprocess.CalledProcessError:
                # Get credentials from AWS credentials file instead
                self.logger.info("Unable to get session token, retrieving credentials from AWS config")
                aws_credentials = self._get_aws_credentials_from_file()
                
                if aws_credentials:
                    self.is_authenticated = True
                    self.auth_type = "aws_sso"
                    self.auth_timestamp = datetime.datetime.now()
                    self.session_token = aws_credentials.get('SessionToken', '')
                    
                    # Set expiration to 8 hours from now if not available
                    self.expiration_time = datetime.datetime.now() + datetime.timedelta(hours=8)
                    
                    # Store the credentials
                    self.credentials = aws_credentials
                    
                    # Set environment variables
                    os.environ['AWS_ACCESS_KEY_ID'] = aws_credentials.get('AccessKeyId', '')
                    os.environ['AWS_SECRET_ACCESS_KEY'] = aws_credentials.get('SecretAccessKey', '')
                    if 'SessionToken' in aws_credentials:
                        os.environ['AWS_SESSION_TOKEN'] = aws_credentials.get('SessionToken', '')
                    
                    # Start the session timer
                    self.start_session_timer()
                    
                    # Log successful authentication
                    self._log_auth_event(True, "Using existing AWS credentials from file")
                    self.auth_success.emit("aws_sso")
                    return True
                
                return False
            
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

    def _get_aws_credentials_from_file(self) -> Optional[Dict[str, str]]:
        """
        Get AWS credentials from the credentials file.
        
        Returns:
            Optional[Dict[str, str]]: AWS credentials or None if not found
        """
        try:
            import configparser
            
            # Get profile
            profile = os.environ.get('AWS_PROFILE', 'default')
            if self.aws_profile:
                profile = self.aws_profile
            
            # Read credentials file
            credentials_file = os.path.expanduser("~/.aws/credentials")
            if not os.path.exists(credentials_file):
                self.logger.warning(f"AWS credentials file not found: {credentials_file}")
                return None
                
            config = configparser.ConfigParser()
            config.read(credentials_file)
            
            # Check if profile exists
            if profile not in config.sections():
                if not config.sections():
                    self.logger.warning(f"No profiles found in AWS credentials file")
                    return None
                    
                # Use first available profile
                profile = config.sections()[0]
                self.logger.info(f"Using AWS profile: {profile}")
            
            # Get credentials
            if profile in config.sections():
                credentials = {
                    'AccessKeyId': config[profile].get('aws_access_key_id', ''),
                    'SecretAccessKey': config[profile].get('aws_secret_access_key', '')
                }
                
                # Get session token if available
                if 'aws_session_token' in config[profile]:
                    credentials['SessionToken'] = config[profile].get('aws_session_token')
                    
                return credentials
            
            return None
        except Exception as e:
            self.logger.error(f"Error reading AWS credentials file: {str(e)}")
            return None


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
            log_dir = os.path.expanduser("~/.guard_config/logs")
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