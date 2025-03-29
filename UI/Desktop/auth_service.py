# UI/Desktop/auth_service.py
"""
Streamlined Authentication Service for GUARD application.

This module provides a standardized approach to authentication using AWS SSO
with proper credential handling and session management.
"""

import os
import time
import logging
import requests
from typing import Dict, Any, Tuple, Optional
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
        
        # Set up logging
        self.logger = logging.getLogger('AuthService')
        self.logger.setLevel(logging.INFO)
    
    def is_authenticated(self) -> bool:
        """
        Check if a user is currently authenticated.
        
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
    
    def authenticate_with_aws_sso(self) -> Tuple[bool, str]:
        """
        Authenticate using AWS SSO credentials.
        
        Returns:
            Tuple[bool, str]: (Success flag, message)
        """
        try:
            if not self.session_manager:
                error_msg = "No session manager available for AWS SSO authentication"
                self.logger.error(error_msg)
                return False, error_msg
                
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
            self.logger.info("Authenticating with AWS SSO credentials")
            response = requests.post(
                f"{self.api_base_url}/auth/aws-sso",
                headers=headers
            )
            
            if response.status_code != 200:
                error_msg = f"AWS SSO authentication failed: {response.text}"
                self.logger.error(error_msg)
                return False, error_msg
            
            # Parse the response
            token_data = response.json()
            self.token = token_data["access_token"]
            self.token_type = token_data.get("token_type", "bearer")
            self.user_id = token_data["user_id"]
            self.auth_type = "aws_sso"
            
            # Calculate token expiration
            expires_in = token_data.get("expires_in", 28800)  # Default to 8 hours for SSO
            self.token_expires_at = time.time() + expires_in
            
            self.logger.info(f"Authenticated user {self.user_id} with AWS SSO")
            return True, "Authentication successful"
            
        except requests.RequestException as e:
            error_msg = f"API connection error: {str(e)}"
            self.logger.error(error_msg)
            return False, error_msg
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
            # For AWS SSO, we need to re-authenticate using session manager
            if self.session_manager and self.session_manager.is_authenticated:
                success, _ = self.authenticate_with_aws_sso()
                return success
            else:
                self.logger.error("No active AWS SSO session for token refresh")
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
                    headers=headers
                )
                
                if response.status_code != 200:
                    self.logger.warning(f"API logout request failed: {response.text}")
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
            
            # Make the request
            response = requests.request(
                method=method.upper(),
                url=url,
                json=data,
                params=params,
                headers=headers
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
                        headers=headers
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