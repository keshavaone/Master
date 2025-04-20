"""
Consolidated Authentication Service for GUARD application.

This module provides a simplified approach to authentication by consolidating
credentials management, session handling, and API authentication into a single service.
"""

import time
import logging
import requests
import webbrowser
import subprocess
import platform
import os
import threading
import json
from typing import Dict, Any, Tuple, Optional, Union, Callable
from datetime import datetime

import api.CONSTANTS as CONSTANTS

class AuthenticationService:
    """
    Authentication service that handles AWS SSO authentication
    and maintains session state for the application.
    """
    
    def __init__(self, parent=None):
        """
        Initialize the authentication service.
        
        Args:
            parent: Parent widget for dialog display
        """
        self.parent = parent
        self.api_base_url = CONSTANTS.API_BASE_URL
        self.token = None
        self.token_type = "bearer"
        self.token_expires_at = None
        self.user_id = None
        self.auth_type = None
        self.session_manager = None
        
        # Configure logging
        self.logger = logging.getLogger('AuthService')
        self.logger.setLevel(logging.INFO)
        
        # Set up handler if not already configured
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        
        self.logger.info("Authentication service initialized")
    
    def is_authenticated(self) -> bool:
        """
        Check if a user is currently authenticated with valid token.
        
        Returns:
            bool: True if authenticated and token is valid
        """
        if not self.token:
            return False
            
        # Check token expiration
        if self.token_expires_at and time.time() >= self.token_expires_at:
            self.logger.info("Token has expired")
            return False
            
        return True
    
    def start_aws_sso_login(self, callback: Optional[Callable[[bool, str], None]] = None) -> Tuple[bool, str]:
        """
        Start the AWS SSO login process by opening the login URL in a browser.
        
        Args:
            callback: Optional callback function to call when login is complete
            
        Returns:
            Tuple[bool, str]: (Success flag, message)
        """
        try:
            # Create session directory if needed
            session_dir = CONSTANTS.AWS_SSO_CONFIG_DIR
            if not os.path.exists(session_dir):
                os.makedirs(session_dir)
                self.logger.info(f"Created AWS SSO session directory: {session_dir}")
            
            # Prepare login URL
            login_url = CONSTANTS.AWS_LOGIN_URL
            self.logger.info(f"Opening AWS SSO login URL: {login_url}")
            
            # Start browser process
            try:
                webbrowser.open(login_url)
                self.logger.info("Opened AWS SSO login URL in browser")
                
                # Start a thread to monitor for SSO completion
                if callback:
                    threading.Thread(
                        target=self._monitor_sso_completion,
                        args=(callback,),
                        daemon=True
                    ).start()
                
                return True, "AWS SSO login started. Please authenticate in your browser."
            except Exception as e:
                error_msg = f"Failed to open browser: {str(e)}"
                self.logger.error(error_msg)
                return False, f"{error_msg}. Please manually visit {login_url}"
                
        except Exception as e:
            error_msg = f"Error starting AWS SSO login: {str(e)}"
            self.logger.error(error_msg)
            return False, error_msg
    
    def _monitor_sso_completion(self, callback: Callable[[bool, str], None]) -> None:
        """
        Monitor for AWS SSO login completion.
        
        Args:
            callback: Callback function to call when login is complete
        """
        try:
            # In a real implementation, this would use a local web server or other mechanism
            # to receive the callback from AWS SSO after the browser login completes.
            # For simplicity, we'll just poll the session directory for a credentials file.
            
            # This is a simplified implementation - in a real app, you would use proper
            # OAuth 2.0 flow with redirect URIs and state parameters.
            
            credentials_file = os.path.join(CONSTANTS.AWS_SSO_CONFIG_DIR, "sso_credentials.json")
            max_wait_time = 300  # 5 minutes
            poll_interval = 3  # 3 seconds
            elapsed_time = 0
            
            self.logger.info("Monitoring for AWS SSO login completion...")
            
            while elapsed_time < max_wait_time:
                if os.path.exists(credentials_file):
                    try:
                        with open(credentials_file, "r") as f:
                            credentials = json.load(f)
                            
                        if self._complete_aws_sso_login(credentials):
                            callback(True, "AWS SSO authentication successful")
                            return
                    except Exception as e:
                        self.logger.error(f"Error reading credentials file: {e}")
                
                # Sleep and increment elapsed time
                time.sleep(poll_interval)
                elapsed_time += poll_interval
            
            # Timeout
            self.logger.warning("AWS SSO login timed out")
            callback(False, "AWS SSO login timed out. Please try again.")
            
        except Exception as e:
            self.logger.error(f"Error monitoring SSO completion: {e}")
            callback(False, f"Error during AWS SSO login: {str(e)}")
    
    def _complete_aws_sso_login(self, credentials: Dict[str, Any]) -> bool:
        """
        Complete the AWS SSO login process with the obtained credentials.
        
        Args:
            credentials: AWS credentials
            
        Returns:
            bool: True if login completed successfully
        """
        try:
            # Extract credentials
            access_key = credentials.get('access_key') or credentials.get('AccessKeyId')
            secret_key = credentials.get('secret_key') or credentials.get('SecretAccessKey')
            session_token = credentials.get('session_token') or credentials.get('SessionToken')
            
            if not (access_key and secret_key):
                self.logger.error("Incomplete credentials for AWS SSO")
                return False
            
            # Set credentials in headers for API authentication
            headers = {
                "X-AWS-Access-Key-ID": access_key,
                "X-AWS-Secret-Access-Key": secret_key
            }
            
            if session_token:
                headers["X-AWS-Session-Token"] = session_token
            
            # Authenticate with the API
            self.logger.info(f"Authenticating with AWS SSO credentials to {self.api_base_url}")
            try:
                response = requests.post(
                    f"{self.api_base_url}/auth/aws-sso",
                    headers=headers,
                    timeout=30
                )
            except requests.RequestException as e:
                self.logger.error(f"API connection error: {str(e)}")
                return False
            
            if response.status_code != 200:
                self.logger.error(f"AWS SSO authentication failed: Status {response.status_code}")
                return False
            
            # Parse the response
            try:
                token_data = response.json()
            except ValueError:
                self.logger.error("Invalid JSON response from server")
                return False
                
            self.token = token_data.get("access_token")
            if not self.token:
                self.logger.error("No token returned from server")
                return False
                
            self.token_type = token_data.get("token_type", "bearer")
            self.user_id = token_data.get("user_id")
            self.auth_type = "aws_sso"
            
            # Calculate token expiration
            expires_in = token_data.get("expires_in", 3600)  # Default to 1 hour
            self.token_expires_at = time.time() + expires_in
            
            self.logger.info(f"Authenticated user {self.user_id} with AWS SSO")
            return True
            
        except Exception as e:
            self.logger.error(f"Error completing AWS SSO login: {str(e)}")
            return False
    
    def authenticate_with_aws_sso(self) -> Tuple[bool, str]:
        """
        Authenticate using AWS SSO credentials.
        
        Returns:
            Tuple[bool, str]: (Success flag, message)
        """
        try:
            if not self.session_manager:
                # Try the new SSO login flow
                return self.start_aws_sso_login()
                
            if not self.session_manager.is_authenticated:
                error_msg = "No active AWS SSO session"
                self.logger.error(error_msg)
                return False, error_msg
            
            # Get credentials from session manager
            credentials = self.session_manager.credentials
            if not credentials:
                error_msg = "No AWS credentials available from session manager"
                self.logger.error(error_msg)
                return False, error_msg
            
            # Extract credentials
            access_key = credentials.get('AccessKeyId')
            secret_key = credentials.get('SecretAccessKey')
            session_token = credentials.get('SessionToken')
            
            if not (access_key and secret_key):
                error_msg = "Incomplete credentials from AWS SSO session"
                self.logger.error(error_msg)
                return False, error_msg
            
            # Log the credential details (without exposing sensitive data)
            self.logger.info(f"Using AWS SSO credentials: AccessKeyId={access_key[:5]}*** SessionToken={session_token is not None}")
            
            # Set credentials in headers for API authentication
            headers = {
                "X-AWS-Access-Key-ID": access_key,
                "X-AWS-Secret-Access-Key": secret_key
            }
            
            if session_token:
                headers["X-AWS-Session-Token"] = session_token
            
            # Authenticate with the API
            self.logger.info(f"Authenticating with AWS SSO credentials to {self.api_base_url}")
            try:
                response = requests.post(
                    f"{self.api_base_url}/auth/aws-sso",
                    headers=headers,
                    timeout=30  # Add a reasonable timeout
                )
            except requests.RequestException as e:
                error_msg = f"API connection error: {str(e)}"
                self.logger.error(error_msg)
                return False, error_msg
            
            if response.status_code != 200:
                error_msg = f"AWS SSO authentication failed: Status {response.status_code} - {response.text}"
                self.logger.error(error_msg)
                return False, error_msg
            
            # Parse the response
            try:
                token_data = response.json()
            except ValueError:
                error_msg = "Invalid JSON response from server"
                self.logger.error(error_msg)
                return False, error_msg
                
            self.token = token_data.get("access_token")
            if not self.token:
                error_msg = "No token returned from server"
                self.logger.error(error_msg)
                return False, error_msg
                
            self.token_type = token_data.get("token_type", "bearer")
            self.user_id = token_data.get("user_id")
            self.auth_type = "aws_sso"
            
            # Calculate token expiration
            expires_in = token_data.get("expires_in", 28800)  # Default to 8 hours for SSO
            self.token_expires_at = time.time() + expires_in
            
            self.logger.info(f"Authenticated user {self.user_id} with AWS SSO")
            return True, "Authentication successful"
            
        except Exception as e:
            error_msg = f"AWS SSO authentication error: {str(e)}"
            self.logger.error(error_msg)
            return False, error_msg
    
    def set_session_manager(self, session_manager):
        """
        Set the session manager for AWS SSO authentication.
        
        Args:
            session_manager: Session manager with AWS SSO tokens
        """
        self.session_manager = session_manager
        self.logger.info("Session manager set")
    
    def refresh_token(self) -> bool:
        """
        Refresh the authentication token.
        
        Returns:
            bool: True if token was refreshed successfully
        """
        if not self.token:
            self.logger.error("No token to refresh")
            return False
        
        try:
            # For AWS SSO, we need to re-authenticate using session manager or SSO login
            if self.auth_type == "aws_sso":
                self.logger.info("Refreshing AWS SSO token")
                
                # First try with session manager if available
                if self.session_manager and self.session_manager.is_authenticated:
                    success, _ = self.authenticate_with_aws_sso()
                    if success:
                        return True
                
                # If session manager refresh failed, check for cached credentials
                credentials_file = os.path.join(CONSTANTS.AWS_SSO_CONFIG_DIR, "sso_credentials.json")
                if os.path.exists(credentials_file):
                    try:
                        with open(credentials_file, "r") as f:
                            credentials = json.load(f)
                        
                        if self._complete_aws_sso_login(credentials):
                            self.logger.info("Refreshed token using cached SSO credentials")
                            return True
                    except Exception as e:
                        self.logger.error(f"Error reading cached credentials: {e}")
                
                # If all refresh attempts failed, prompt for new login
                self.logger.warning("Could not refresh token automatically, need new SSO login")
                return False
            else:
                self.logger.error("Cannot refresh token: Unsupported auth type")
                return False
                
        except Exception as e:
            self.logger.error(f"Token refresh error: {str(e)}")
            return False
    
    def logout(self) -> bool:
        """
        Log out the current user by invalidating tokens and clearing state.
        
        Returns:
            bool: True if successful
        """
        try:
            if not self.token:
                self.logger.info("No active session to log out")
                return True
                
            try:
                # Call logout endpoint to invalidate the token
                headers = self.get_auth_headers()
                response = requests.post(
                    f"{self.api_base_url}/auth/logout",
                    headers=headers,
                    timeout=10  # Add a reasonable timeout
                )
                
                if response.status_code != 200:
                    self.logger.warning(f"API logout request failed: {response.status_code} - {response.text}")
                    # Continue with local logout
            except Exception as e:
                self.logger.warning(f"Error during API logout: {str(e)}")
                # Continue with local logout
                
            # Clear authentication state
            self.token = None
            self.token_expires_at = None
            self.user_id = None
            self.auth_type = None
            
            self.logger.info("User logged out successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Logout error: {str(e)}")
            return False
    
    def get_auth_headers(self) -> Dict[str, str]:
        """
        Get authorization headers for API requests.
        
        Returns:
            Dict[str, str]: Headers with authorization
        """
        if not self.token:
            return {}
        
        return {
            "Authorization": f"{self.token_type} {self.token}"
        }
    
    def get_session_info(self) -> Dict[str, Any]:
        """
        Get information about the current session.
        
        Returns:
            Dict[str, Any]: Session information
        """
        return {
            "is_authenticated": self.is_authenticated(),
            "user_id": self.user_id,
            "auth_type": self.auth_type,
            "token_expires_at": datetime.fromtimestamp(self.token_expires_at).isoformat() if self.token_expires_at else None,
            "remaining_seconds": int(self.token_expires_at - time.time()) if self.token_expires_at and self.token_expires_at > time.time() else None
        }
    
    def make_authenticated_request(self, method: str, endpoint: str, 
                                  data: Any = None, params: Dict[str, Any] = None) -> Tuple[bool, Any]:
        """
        Make an authenticated request to the API with automatic token refresh.
        
        Args:
            method (str): HTTP method (GET, POST, PUT, DELETE, etc.)
            endpoint (str): API endpoint path
            data (Any, optional): Request body data
            params (Dict[str, Any], optional): Query parameters
            
        Returns:
            Tuple[bool, Any]: (Success flag, response data or error)
        """
        if not self.is_authenticated():
            self.logger.error("Not authenticated for API request")
            return False, {"error": "Not authenticated"}
        
        try:
            # Prepare the request
            url = f"{self.api_base_url}/{endpoint.lstrip('/')}"
            headers = self.get_auth_headers()
            
            # Log request (without sensitive data)
            self.logger.info(f"Making {method.upper()} request to {url}")
            
            # Make the request
            response = requests.request(
                method=method.upper(),
                url=url,
                json=data,
                params=params,
                headers=headers,
                timeout=30  # Add a reasonable timeout
            )
            
            # Handle 401 Unauthorized by refreshing token and retrying once
            if response.status_code == 401:
                self.logger.info("Token expired, attempting to refresh")
                if self.refresh_token():
                    # Retry the request with new token
                    headers = self.get_auth_headers()
                    response = requests.request(
                        method=method.upper(),
                        url=url,
                        json=data,
                        params=params,
                        headers=headers,
                        timeout=30  # Add a reasonable timeout
                    )
                else:
                    self.logger.error("Token refresh failed")
                    return False, {"error": "Authentication expired and refresh failed"}
            
            # Process the response
            try:
                response_data = response.json()
            except ValueError:
                response_data = response.text
            
            # Check for success
            if 200 <= response.status_code < 300:
                return True, response_data
            else:
                error_msg = f"Request failed with status {response.status_code}"
                self.logger.error(f"{error_msg}: {response_data}")
                return False, response_data
                
        except requests.RequestException as e:
            error_msg = f"Request error: {str(e)}"
            self.logger.error(error_msg)
            return False, {"error": error_msg}
        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            self.logger.error(error_msg)
            return False, {"error": error_msg}
    
    # Alias for backward compatibility
    make_synchronous_request = make_authenticated_request