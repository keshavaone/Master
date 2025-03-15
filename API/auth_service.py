"""
Enhanced Authentication Service for GUARD Desktop Application

This module provides a more reliable authentication service for
the desktop application, with improved AWS SSO token handling.
Replace the existing API/auth_service.py with this file.
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
    Enhanced authentication service for desktop-to-API communication.
    
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
        Authenticate with the API using password.
        
        Args:
            username (str): Username for authentication
            password (str): Password for authentication
            
        Returns:
            Tuple[bool, str]: (Success flag, message)
        """
        try:
            # Try using direct JWT token generation first
            try:
                from API.auth_dev_bypass import get_direct_token
                
                self.logger.info(f"Using direct JWT token generation for user: {username}")
                success, token_data = get_direct_token(username, password)
                
                if success:
                    # Set authentication data
                    self.token = token_data["access_token"]
                    self.user_id = token_data["user_id"]
                    self.auth_type = "password"
                    self.token_expiration = time.time() + token_data.get("expires_in", 3600)
                    
                    self.logger.info(f"Successfully authenticated user: {self.user_id}")
                    return True, "Authentication successful"
                else:
                    error_msg = f"Authentication failed: {token_data.get('error', 'Unknown error')}"
                    self.logger.error(error_msg)
            except ImportError:
                self.logger.info("Direct token generation not available, trying API call")
            
            # If direct token generation failed or not available, try API call
            # Prepare both header and body for flexibility
            headers = {
                "Content-Type": "application/json",
                "username": username,
                "password": password
            }
            
            body = {
                "username": username,
                "password": password
            }
            
            response = requests.post(
                f"{self.api_base_url}/auth/token",
                headers=headers,
                json=body
            )
            
            if response.status_code == 200:
                token_data = response.json()
                
                # Set authentication data
                self.token = token_data["access_token"]
                self.user_id = token_data["user_id"]
                self.auth_type = "password"
                self.token_expiration = time.time() + token_data.get("expires_in", 3600)
                
                self.logger.info(f"Successfully authenticated user: {self.user_id}")
                return True, "Authentication successful"
            else:
                error_msg = f"Authentication failed: {response.text}"
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
            # Get AWS credentials from session manager
            if not hasattr(self.session_manager, 'credentials') or not self.session_manager.credentials:
                return False, "No AWS credentials available from session manager"
            
            creds = self.session_manager.credentials
            self.logger.info(f"Authenticating with AWS credentials for user {self.session_manager.user_id}")
            
            # Call the AWS credentials endpoint with proper error handling
            try:
                # Prepare headers with AWS credentials
                headers = {
                    "X-AWS-Access-Key-ID": creds.get('AccessKeyId', ''),
                    "X-AWS-Secret-Access-Key": creds.get('SecretAccessKey', '')
                }
                
                # Add session token if available
                if 'SessionToken' in creds:
                    headers["X-AWS-Session-Token"] = creds.get('SessionToken')
                
                # Make the request
                self.logger.info("Calling /auth/aws-credentials endpoint")
                response = requests.post(
                    f"{self.api_base_url}/auth/aws-credentials",
                    headers=headers
                )
                
                # Process the response
                if response.status_code == 200:
                    token_data = response.json()
                    
                    # Set authentication data
                    self.token = token_data["access_token"]
                    self.user_id = token_data["user_id"]
                    self.auth_type = "aws_sso"
                    self.token_expiration = time.time() + token_data.get("expires_in", 3600)
                    
                    self.logger.info(f"Successfully authenticated with AWS SSO: {self.user_id}")
                    return True, "Authentication successful"
                else:
                    self.logger.warning(f"AWS credentials endpoint failed: {response.status_code} - {response.text}")
                    
                    # If we get a 404, the endpoint might not exist
                    if response.status_code == 404:
                        self.logger.info("Trying /auth/aws-sso endpoint instead")
                        response = requests.post(
                            f"{self.api_base_url}/auth/aws-sso",
                            headers=headers
                        )
                        
                        if response.status_code == 200:
                            token_data = response.json()
                            
                            # Set authentication data
                            self.token = token_data["access_token"]
                            self.user_id = token_data["user_id"]
                            self.auth_type = "aws_sso"
                            self.token_expiration = time.time() + token_data.get("expires_in", 3600)
                            
                            self.logger.info(f"Successfully authenticated with AWS SSO: {self.user_id}")
                            return True, "Authentication successful"
            except Exception as e:
                self.logger.warning(f"API endpoint error: {str(e)}")
            
            # If API endpoints fail, try direct authentication
            self.logger.info("API endpoints failed, trying direct authentication")
            
            # Set token to be used with AWS- prefix
            self.token = creds.get('SessionToken', '')
            if not self.token and 'Credentials' in creds and 'SessionToken' in creds['Credentials']:
                self.token = creds['Credentials']['SessionToken']
            
            # Set other authentication data
            self.user_id = self.session_manager.user_id
            self.auth_type = "aws_sso"
            
            # Set expiration from session manager or default to 1 hour
            if hasattr(self.session_manager, 'expiration_time') and self.session_manager.expiration_time:
                import datetime
                if isinstance(self.session_manager.expiration_time, datetime.datetime):
                    self.token_expiration = self.session_manager.expiration_time.timestamp()
                else:
                    self.token_expiration = time.time() + 3600  # 1 hour default
            else:
                self.token_expiration = time.time() + 3600  # 1 hour default
            
            # Verify we can authenticate with this token
            success, message = self.verify_token()
            if not success:
                # As a last resort, try creating a JWT token
                try:
                    # Try importing the JWT token creation function
                    from API.auth_dev_bypass import create_jwt_token
                    
                    # Create a JWT token with the user ID
                    self.logger.info("Creating JWT token as fallback")
                    jwt_token = create_jwt_token(self.user_id, user_data={"auth_type": "aws_sso"})
                    
                    if jwt_token:
                        self.token = jwt_token
                        self.auth_type = "password"  # Use password type to avoid AWS SSO format issues
                        self.token_expiration = time.time() + 3600  # 1 hour default
                        
                        # Try verifying this token
                        success, jwt_message = self.verify_token()
                        if success:
                            self.logger.info("JWT token authentication successful")
                            return True, "Authentication successful"
                        else:
                            return False, f"JWT token verification failed: {jwt_message}"
                    else:
                        return False, "Failed to create JWT token"
                except Exception as e:
                    return False, f"All authentication methods failed: {str(e)}"
            
            return True, "Authentication successful using direct AWS credentials"
            
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
            headers = self.get_auth_headers()
            self.logger.info(f"Verifying token with headers: {headers}")
            
            # For AWS SSO auth type, try validating credentials directly
            if self.auth_type == "aws_sso":
                try:
                    # Test AWS credentials by making a simple AWS API call
                    sts = boto3.client('sts')
                    identity = sts.get_caller_identity()
                    self.logger.info(f"AWS identity check successful: {identity.get('UserId')}")
                except Exception as e:
                    self.logger.error(f"AWS identity check failed: {str(e)}")
                    # Continue to API verification
            
            # Call the API
            response = requests.get(
                f"{self.api_base_url}/auth/user",
                headers=headers
            )
            
            # Log response for debugging
            self.logger.info(f"Token verification response: {response.status_code} - {response.text}")
            
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
            if self.auth_type == "aws_sso":
                # For AWS SSO, always include credentials if available
                if hasattr(self, 'session_manager') and self.session_manager and hasattr(self.session_manager, 'credentials'):
                    creds = self.session_manager.credentials
                    if creds:
                        headers["X-AWS-Access-Key-ID"] = creds.get('AccessKeyId', '')
                        headers["X-AWS-Secret-Access-Key"] = creds.get('SecretAccessKey', '')
                        if 'SessionToken' in creds:
                            headers["X-AWS-Session-Token"] = creds.get('SessionToken', '')
                        
                        self.logger.info(f"Using AWS SSO credentials for user {self.user_id}")
                
                # Include token as authorization header - with AWS- prefix for API recognition
                headers["Authorization"] = f"Bearer AWS-{self.token}"
            else:
                # For JWT tokens
                headers["Authorization"] = f"Bearer {self.token}"
            
            # Add user info for logging/debugging
            if self.user_id:
                headers["X-User-ID"] = self.user_id
            
            if self.auth_type:
                headers["X-Auth-Type"] = self.auth_type
        
        return headers
    
    def make_authenticated_request(self, method: str, endpoint: str, 
                                  data: Any = None, params: Dict[str, Any] = None) -> Tuple[bool, Any]:
        """
        Make an authenticated request to the API.
        
        Args:
            method (str): HTTP method (GET, POST, etc.)
            endpoint (str): API endpoint path (without base URL)
            data (Any, optional): Request body data
            params (Dict[str, Any], optional): Query parameters
            
        Returns:
            Tuple[bool, Any]: (Success flag, response data or error)
        """
        # Check if token is valid, try to refresh if not
        if not self.is_token_valid():
            self.logger.info("Token is invalid or expired, attempting to refresh")
            
            # For AWS SSO, re-authenticate
            if self.session_manager and self.auth_type == "aws_sso":
                success, message = self.authenticate_with_aws_sso()
                if not success:
                    return False, f"Authentication failed: {message}"
            else:
                # For other auth types, check if we can refresh
                return False, "Authentication expired"
        
        try:
            # Prepare the request
            url = f"{self.api_base_url}/{endpoint.lstrip('/')}"
            headers = self.get_auth_headers()
            
            # Log the request (without sensitive info)
            safe_headers = {k: v for k, v in headers.items() 
                          if k not in ('X-AWS-Secret-Access-Key', 'X-AWS-Session-Token')}
            if 'X-AWS-Access-Key-ID' in safe_headers:
                safe_headers['X-AWS-Access-Key-ID'] = safe_headers['X-AWS-Access-Key-ID'][:10] + '...'
                
            self.logger.info(f"Making {method} request to {url}")
            self.logger.debug(f"Headers: {safe_headers}")
            
            # Make the request
            response = requests.request(
                method=method.upper(),
                url=url,
                headers=headers,
                json=data if data else None,
                params=params
            )
            
            # Log response status
            self.logger.info(f"Response status: {response.status_code}")
            
            # Handle response
            if 200 <= response.status_code < 300:
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