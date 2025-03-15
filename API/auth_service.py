"""
Authentication service for GUARD desktop application.

This module provides a service layer for handling authentication between
the desktop application and the API server, managing tokens and sessions.
"""

import os
import json
import time
import logging
import requests
from typing import Dict, Any, Optional, Tuple
from datetime import datetime
import boto3
from botocore.exceptions import ClientError


class AuthService:
    """
    Authentication service for desktop-to-API communication.
    
    Manages authentication tokens, AWS SSO integration, and secure
    communication with the API server.
    """
    
    def __init__(self, api_base_url: str, session_manager=None):
        """
        Initialize the authentication service.
        
        Args:
            api_base_url (str): Base URL for the API server
            session_manager: Optional session manager instance
        """
        self.api_base_url = api_base_url.rstrip('/')
        self.session_manager = session_manager
        self.token = None
        self.token_expiration = None
        self.user_id = None
        self.auth_type = None
        
        # Set up logging
        self.logger = logging.getLogger('AuthService')
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
        
        self.logger.info(f"Authentication service initialized for {api_base_url}")
    
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
            # Call the API token endpoint
            response = requests.post(
                f"{self.api_base_url}/auth/token",
                headers={
                    "username": username,
                    "password": password
                }
            )
            
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
    
    def authenticate_with_aws_sso(self) -> Tuple[bool, str]:
        """
        Authenticate with AWS SSO using the session manager.
        
        Returns:
            Tuple[bool, str]: (Success flag, message)
        """
        if not self.session_manager:
            return False, "Session manager not available"
        
        try:
            # Get the token from the session manager
            token = self.session_manager.get_auth_token()
            if not token:
                return False, "No valid token available from session manager"
            
            # Set the token with AWS- prefix to indicate it's an AWS token
            self.token = f"AWS-{token}"
            self.user_id = self.session_manager.user_id
            self.auth_type = "aws_sso"
            
            # Get expiration from session manager
            if self.session_manager.expiration_time:
                # Convert datetime to timestamp
                expiry = self.session_manager.expiration_time.timestamp()
                self.token_expiration = expiry
            else:
                # Default to 8 hours
                self.token_expiration = time.time() + (8 * 60 * 60)
            
            # Verify token with the API
            success, message = self.verify_token()
            if not success:
                return False, f"Token verification failed: {message}"
            
            self.logger.info(f"Authenticated user {self.user_id} with AWS SSO")
            return True, "Authentication successful"
            
        except Exception as e:
            error_msg = f"AWS SSO authentication error: {str(e)}"
            self.logger.error(error_msg)
            return False, error_msg
    
    def verify_token(self) -> Tuple[bool, str]:
        """
        Verify the current token with the API.
        
        Returns:
            Tuple[bool, str]: (Valid flag, message)
        """
        if not self.token:
            return False, "No token available"
        
        try:
            # Call the API user info endpoint
            response = requests.get(
                f"{self.api_base_url}/auth/user",
                headers=self.get_auth_headers()
            )
            
            if response.status_code != 200:
                error_msg = f"Token verification failed: {response.text}"
                self.logger.error(error_msg)
                return False, error_msg
            
            # Update user info from response
            user_data = response.json()
            if user_data.get("user_id"):
                self.user_id = user_data["user_id"]
            
            self.logger.info(f"Token verified for user {self.user_id}")
            return True, "Token valid"
            
        except requests.RequestException as e:
            error_msg = f"API connection error: {str(e)}"
            self.logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Token verification error: {str(e)}"
            self.logger.error(error_msg)
            return False, error_msg
    
    def is_token_valid(self) -> bool:
        """
        Check if the current token is valid and not expired.
        
        Returns:
            bool: True if token is valid
        """
        if not self.token or not self.token_expiration:
            return False
        
        # Check if token is expired
        if time.time() >= self.token_expiration:
            self.logger.info("Token has expired")
            return False
        
        return True
    
    def get_auth_headers(self) -> Dict[str, str]:
        """
        Get authentication headers for API requests.
        
        Returns:
            Dict[str, str]: Headers to include in API requests
        """
        headers = {}
        
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        
        return headers
    
    def make_authenticated_request(self, method: str, endpoint: str, 
                                  data: Any = None, params: Dict = None) -> Tuple[bool, Any]:
        """
        Make an authenticated request to the API.
        
        Args:
            method (str): HTTP method (GET, POST, etc.)
            endpoint (str): API endpoint path
            data (Any): Request body data
            params (Dict): Query parameters
            
        Returns:
            Tuple[bool, Any]: (Success flag, response data or error message)
        """
        if not self.is_token_valid():
            # Token is invalid or expired
            if self.session_manager and self.auth_type == "aws_sso":
                # Try to refresh with AWS SSO
                success, message = self.authenticate_with_aws_sso()
                if not success:
                    return False, f"Authentication failed: {message}"
            else:
                return False, "Authentication token expired"
        
        try:
            # Prepare the request
            url = f"{self.api_base_url}/{endpoint.lstrip('/')}"
            headers = self.get_auth_headers()
            
            # Make the request
            response = requests.request(
                method=method.upper(),
                url=url,
                headers=headers,
                json=data if data else None,
                params=params
            )
            
            # Handle response
            if response.status_code >= 200 and response.status_code < 300:
                try:
                    return True, response.json()
                except ValueError:
                    return True, response.text
            else:
                error_msg = f"API request failed: {response.status_code} - {response.text}"
                self.logger.error(error_msg)
                return False, error_msg
                
        except requests.RequestException as e:
            error_msg = f"API connection error: {str(e)}"
            self.logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Request error: {str(e)}"
            self.logger.error(error_msg)
            return False, error_msg
    
    def logout(self) -> Tuple[bool, str]:
        """
        Clear authentication state.
        
        Returns:
            Tuple[bool, str]: (Success flag, message)
        """
        try:
            # Clear token information
            self.token = None
            self.token_expiration = None
            
            # Log the logout
            if self.user_id:
                self.logger.info(f"Logged out user {self.user_id}")
            
            self.user_id = None
            self.auth_type = None
            
            return True, "Logged out successfully"
            
        except Exception as e:
            error_msg = f"Logout error: {str(e)}"
            self.logger.error(error_msg)
            return False, error_msg
    
    def get_user_info(self) -> Dict[str, Any]:
        """
        Get information about the authenticated user.
        
        Returns:
            Dict[str, Any]: User information
        """
        remaining_time = 0
        if self.token_expiration:
            remaining_time = max(0, self.token_expiration - time.time())
        
        return {
            "user_id": self.user_id,
            "auth_type": self.auth_type,
            "is_authenticated": self.is_token_valid(),
            "token_expires_in": int(remaining_time),
            "token_expires_at": datetime.fromtimestamp(self.token_expiration).isoformat() if self.token_expiration else None
        }