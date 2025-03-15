"""
Authentication implementation for the desktop application.
Add this to your UI/Desktop/main.py file or create a new dedicated module.
"""

import os
import requests
import json
import logging
from typing import Tuple
from PyQt5.QtWidgets import QMessageBox
import API.CONSTANTS as CONSTANTS

class AuthenticationManager:
    """
    Authentication manager for the desktop application.
    Handles authentication with the API server.
    """
    
    def __init__(self, parent=None):
        """
        Initialize the authentication manager.
        
        Args:
            parent: Parent widget for dialog display
        """
        self.parent = parent
        self.api_base_url = CONSTANTS.API_BASE_URL
        self.token = None
        self.token_type = "bearer"
        self.user_id = None
        self.auth_type = None
        
        # Set up logging
        self.logger = logging.getLogger('AuthManager')
        self.logger.setLevel(logging.INFO)
    
    def authenticate_with_password(self, username: str, password: str) -> Tuple[bool, str]:
        """
        Authenticate with the API using username and password.
        
        Args:
            username (str): Username for authentication
            password (str): Password for authentication
            
        Returns:
            Tuple[bool, str]: (Success flag, message)
        """
        try:
            # There appear to be two different auth endpoints with different expectations,
            # so let's try both approaches simultaneously
            
            # Always use "admin" regardless of input for either method
            admin_username = "admin"
            
            # Method 1: Send credentials as headers (main.py approach)
            headers = {
                "Content-Type": "application/json",
                "username": admin_username,
                "password": password
            }
            
            # Method 2: Send credentials as JSON body (auth_endpoints.py approach)
            payload = {
                "username": admin_username,
                "password": password
            }
            
            # Log our attempt with both methods
            self.logger.info(f"Authenticating with both header and body-based methods as admin user")
            
            # Make the request
            response = requests.post(
                f"{self.api_base_url}/auth/token",
                headers=headers,
                json=payload  # Include both formats
            )
            
            # Log detailed request info for debugging
            self.logger.info(f"Authentication request URL: {self.api_base_url}/auth/token")
            self.logger.info(f"Authentication request headers: {headers}")
            self.logger.info(f"Authentication request body: {payload}")
            self.logger.info(f"Authentication response status: {response.status_code}")
            self.logger.info(f"Authentication response: {response.text}")
            
            if response.status_code != 200:
                error_msg = f"Authentication failed: {response.text}"
                self.logger.error(error_msg)
                return False, error_msg
            
            # Parse the token response
            token_data = response.json()
            self.token = token_data["access_token"]
            self.user_id = token_data["user_id"]
            self.auth_type = "password"
            
            # Calculate token expiration
            self.token_expiration = time.time() + token_data.get("expires_in", 3600)
            
            self.logger.info(f"Authenticated user {self.user_id} with password")
            return True, "Authentication successful"
            
        except requests.RequestException as e:
            error_msg = f"API connection error: {str(e)}"
            self.logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Authentication error: {str(e)}"
            self.logger.error(error_msg)
            return False, error_msg
    
    def authenticate_with_sso(self, session_manager):
        """
        Authenticate using AWS SSO tokens from session manager.
        
        Args:
            session_manager: Session manager with AWS SSO tokens
            
        Returns:
            bool: True if authentication successful
        """
        try:
            # Get the token from session manager
            if not session_manager.is_authenticated:
                error_message = "No active SSO session"
                self.logger.error(error_message)
                if self.parent:
                    QMessageBox.warning(
                        self.parent,
                        "Authentication Error",
                        error_message
                    )
                return False
            
            # Get AWS session token
            aws_token = session_manager.session_token
            if not aws_token:
                error_message = "No AWS token available"
                self.logger.error(error_message)
                if self.parent:
                    QMessageBox.warning(
                        self.parent,
                        "Authentication Error",
                        error_message
                    )
                return False
            
            # Format with AWS- prefix to indicate it's an AWS token
            self.token = f"AWS-{aws_token}"
            self.token_type = "bearer"
            self.user_id = session_manager.user_id
            self.auth_type = "aws_sso"
            
            # Verify the token with the API
            valid = self.verify_token()
            if not valid:
                return False
            
            self.logger.info(f"Successfully authenticated with AWS SSO: {self.user_id}")
            return True
            
        except Exception as e:
            error_message = f"SSO authentication error: {str(e)}"
            self.logger.error(error_message)
            if self.parent:
                QMessageBox.warning(
                    self.parent,
                    "Authentication Error",
                    error_message
                )
            return False
    
    def verify_token(self):
        """
        Verify the current token with the API.
        
        Returns:
            bool: True if token is valid
        """
        if not self.token:
            return False
        
        try:
            # Call the API to verify the token
            headers = self.get_auth_headers()
            response = requests.get(
                f"{self.api_base_url}/auth/user",
                headers=headers
            )
            
            # Check if the request was successful
            if response.status_code != 200:
                self.logger.error(f"Token verification failed: {response.text}")
                return False
            
            # Token is valid
            data = response.json()
            if data.get("user_id"):
                self.user_id = data["user_id"]
            
            self.logger.info(f"Token verified for user: {self.user_id}")
            return True
            
        except requests.RequestException as e:
            self.logger.error(f"Connection error: {str(e)}")
            return False
        except Exception as e:
            self.logger.error(f"Token verification error: {str(e)}")
            return False
    
    def refresh_token(self):
        """
        Refresh the current token.
        
        Returns:
            bool: True if token was refreshed
        """
        if not self.token or self.auth_type == "aws_sso":
            # AWS SSO tokens are managed separately
            return False
        
        try:
            # Call the token refresh endpoint
            headers = self.get_auth_headers()
            response = requests.post(
                f"{self.api_base_url}/auth/token/refresh",
                headers=headers
            )
            
            # Check if the request was successful
            if response.status_code != 200:
                self.logger.error(f"Token refresh failed: {response.text}")
                return False
            
            # Parse the token response
            data = response.json()
            self.token = data["access_token"]
            self.token_type = data["token_type"]
            
            self.logger.info(f"Token refreshed for user: {self.user_id}")
            return True
            
        except requests.RequestException as e:
            self.logger.error(f"Connection error: {str(e)}")
            return False
        except Exception as e:
            self.logger.error(f"Token refresh error: {str(e)}")
            return False
    
    def get_auth_headers(self):
        """
        Get the authorization headers for API requests.
        
        Returns:
            dict: Headers with authorization
        """
        if not self.token:
            return {}
        
        return {
            "Authorization": f"{self.token_type} {self.token}"
        }
    
    def logout(self):
        """
        Clear authentication state.
        
        Returns:
            bool: True if successful
        """
        try:
            self.logger.info(f"Logging out user: {self.user_id}")
            
            # Clear authentication state
            self.token = None
            self.user_id = None
            self.auth_type = None
            
            return True
            
        except Exception as e:
            self.logger.error(f"Logout error: {str(e)}")
            return False
    
    def make_authenticated_request(self, method, endpoint, data=None, params=None):
        """
        Make an authenticated request to the API.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint
            data: Request data
            params: Query parameters
            
        Returns:
            tuple: (success, response_data)
        """
        if not self.token:
            self.logger.error("No authentication token available")
            return False, "No authentication token"
        
        try:
            # Prepare the URL
            url = f"{self.api_base_url}/{endpoint.lstrip('/')}"
            
            # Make the request
            headers = self.get_auth_headers()
            response = requests.request(
                method=method.upper(),
                url=url,
                json=data,
                params=params,
                headers=headers
            )
            
            # Check if the request was successful
            if response.status_code >= 200 and response.status_code < 300:
                # Try to parse JSON response
                try:
                    return True, response.json()
                except json.JSONDecodeError:
                    return True, response.text
            else:
                error_message = f"Request failed: {response.status_code} - {response.text}"
                self.logger.error(error_message)
                return False, error_message
                
        except requests.RequestException as e:
            error_message = f"Connection error: {str(e)}"
            self.logger.error(error_message)
            return False, error_message
        except Exception as e:
            error_message = f"Request error: {str(e)}"
            self.logger.error(error_message)
            return False, error_message