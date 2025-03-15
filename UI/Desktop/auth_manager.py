"""
Authentication implementation for the desktop application.
Add this to your UI/Desktop/main.py file or create a new dedicated module.
"""

import os
import requests
import json
import logging
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
    
    def authenticate_with_password(self, username, password):
        """
        Authenticate with the API using password.
        
        Args:
            username: Username for authentication
            password: Password for authentication
            
        Returns:
            bool: True if authentication successful
        """
        try:
            # Call the API token endpoint
            response = requests.post(
                f"{self.api_base_url}/auth/token",
                json={
                    "username": username,
                    "password": password
                }
            )
            
            # Check if the request was successful
            if response.status_code != 200:
                error_message = f"Authentication failed: {response.text}"
                self.logger.error(error_message)
                if self.parent:
                    QMessageBox.warning(
                        self.parent,
                        "Authentication Failed",
                        error_message
                    )
                return False
            
            # Parse the token response
            data = response.json()
            self.token = data["access_token"]
            self.token_type = data["token_type"]
            self.user_id = data["user_id"]
            self.auth_type = "password"
            
            self.logger.info(f"Successfully authenticated user: {self.user_id}")
            return True
            
        except requests.RequestException as e:
            error_message = f"Connection error: {str(e)}"
            self.logger.error(error_message)
            if self.parent:
                QMessageBox.warning(
                    self.parent,
                    "Connection Error",
                    error_message
                )
            return False
        except Exception as e:
            error_message = f"Authentication error: {str(e)}"
            self.logger.error(error_message)
            if self.parent:
                QMessageBox.warning(
                    self.parent,
                    "Authentication Error",
                    error_message
                )
            return False
    
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