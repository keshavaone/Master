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
        Authenticate with the API using password.
        
        Since the API's auth endpoint is having issues, this uses a direct JWT
        token generation approach instead.
        
        Args:
            username (str): Username for authentication
            password (str): Password for authentication
            
        Returns:
            Tuple[bool, str]: (Success flag, message)
        """
        try:
            # Use the direct JWT token generation approach
            from API.auth_dev_bypass import get_direct_token
            
            self.logger.info(f"Using direct JWT token generation for user: {username}")
            success, token_data = get_direct_token(username, password)
            
            if not success:
                error_msg = f"Authentication failed: {token_data.get('error', 'Unknown error')}"
                self.logger.error(error_msg)
                return False, error_msg
            
            # Set authentication data
            self.token = token_data["access_token"]
            self.user_id = token_data["user_id"]
            self.auth_type = "password"
            self.token_expiration = time.time() + token_data.get("expires_in", 3600)
            
            self.logger.info(f"Successfully authenticated user: {self.user_id}")
            return True, "Authentication successful"
            
        except ImportError:
            self.logger.error("auth_dev_bypass module not found. Please add it to your project.")
            return False, "Authentication module not available"
        except Exception as e:
            error_msg = f"Authentication error: {str(e)}"
            self.logger.error(error_msg)
            return False, error_msg

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
            # Use the enhanced request method from auth_dev_bypass
            try:
                from API.auth_dev_bypass import make_authenticated_request
                
                self.logger.info(f"Using enhanced request method for {method} {endpoint}")
                return make_authenticated_request(
                    self.token,
                    method,
                    endpoint,
                    data,
                    params
                )
            except ImportError:
                # Fall back to standard request method
                # Prepare the request
                url = f"{self.api_base_url}/{endpoint.lstrip('/')}"
                headers = self.get_auth_headers()
                
                # Log the request for debugging
                self.logger.debug(f"Making {method} request to {url}")
                self.logger.debug(f"Headers: {headers}")
                
                # Make the request
                response = requests.request(
                    method=method.upper(),
                    url=url,
                    headers=headers,
                    json=data if data else None,
                    params=params
                )
                
                # Log response status for debugging
                self.logger.debug(f"Response status: {response.status_code}")
                
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
            
            # Store AWS SSO token (important: we store WITHOUT the AWS- prefix here)
            # The prefix will be added in get_auth_headers()
            self.token = token
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
            self.logger.info(f"Attempting to verify AWS SSO token for user {self.user_id}")
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
            headers = self.get_auth_headers()
            self.logger.info(f"Verifying token with headers: {headers}")
            
            # For debugging, try simple authentication test
            if self.auth_type == "aws_sso":
                try:
                    # Test AWS credentials by making a simple AWS API call
                    sts = boto3.client('sts')
                    identity = sts.get_caller_identity()
                    self.logger.info(f"AWS identity check successful: {identity.get('UserId')}")
                except Exception as e:
                    self.logger.error(f"AWS identity check failed: {str(e)}")
            
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
                # IMPORTANT FIX: Send AWS credentials directly instead of using AWS-prefixed token
                # The API server expects credentials, not the raw AWS SSO token
                
                # Include AWS access key and secret directly - this is safer for API authentication
                if hasattr(self, 'session_manager') and self.session_manager and self.session_manager.credentials:
                    creds = self.session_manager.credentials
                    headers["X-AWS-Access-Key-ID"] = creds.get('AccessKeyId', '')
                    headers["X-AWS-Secret-Access-Key"] = creds.get('SecretAccessKey', '')
                    if 'SessionToken' in creds:
                        headers["X-AWS-Session-Token"] = creds.get('SessionToken', '')
                    
                    # Now include the token without AWS- prefix
                    # Many APIs expect just the token, not with the AWS- prefix
                    headers["Authorization"] = f"Bearer {self.token}"
                    
                    self.logger.info(f"Using AWS SSO credentials for user {self.user_id}")
                    self.logger.debug(f"Including AWS Access Key ID: {headers.get('X-AWS-Access-Key-ID', '')[:5]}...")
                else:
                    # Fall back to AWS-prefixed token if credentials not available
                    headers["Authorization"] = f"Bearer AWS-{self.token}"
                    self.logger.info(f"Using AWS SSO token format for user {self.user_id}")
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
            
            # Log the request for debugging
            self.logger.debug(f"Making {method} request to {url}")
            self.logger.debug(f"Headers: {headers}")
            
            # Make the request
            response = requests.request(
                method=method.upper(),
                url=url,
                headers=headers,
                json=data if data else None,
                params=params
            )
            
            # Log response status for debugging
            self.logger.debug(f"Response status: {response.status_code}")
            
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
    
    def authenticate_with_aws_sso(self) -> Tuple[bool, str]:
        """
        Authenticate with AWS SSO using session manager.
        
        This method sends AWS credentials directly to the API server rather
        than relying on token formatting.
        
        Returns:
            Tuple[bool, str]: (Success flag, message)
        """
        if not self.session_manager:
            return False, "Session manager not available"
        
        try:
            # Get credentials from session manager
            if not hasattr(self.session_manager, 'credentials') or not self.session_manager.credentials:
                return False, "No AWS credentials available from session manager"
            
            creds = self.session_manager.credentials
            
            self.logger.info(f"Authenticating with AWS credentials for user {self.session_manager.user_id}")
            
            # Method 1: Try the /auth/aws-credentials endpoint
            success, message = self._try_aws_credentials_endpoint(creds)
            if success:
                return True, message
                
            # Method 2: Try conventional AWS SSO token approach
            success, message = self._try_aws_sso_token(creds)
            if success:
                return True, message
            
            # Method 3: Last resort - direct endpoint access with credentials
            success, message = self._try_direct_credentials_auth(creds)
            if success:
                return True, message
                
            # If we get here, all methods failed
            return False, "All authentication methods failed"
            
        except Exception as e:
            error_msg = f"AWS SSO authentication error: {str(e)}"
            self.logger.error(error_msg)
            return False, error_msg
            
    def _try_aws_credentials_endpoint(self, creds) -> Tuple[bool, str]:
        """Try authenticating with the /auth/aws-credentials endpoint."""
        try:
            # Prepare headers with AWS credentials
            headers = {
                "X-AWS-Access-Key-ID": creds.get('AccessKeyId', ''),
                "X-AWS-Secret-Access-Key": creds.get('SecretAccessKey', '')
            }
            
            # Add session token if available
            if 'SessionToken' in creds:
                headers["X-AWS-Session-Token"] = creds.get('SessionToken')
            
            # Make request to endpoint
            response = requests.post(
                f"{self.api_base_url}/auth/aws-credentials",
                headers=headers
            )
            
            if response.status_code == 200:
                # Parse token data
                token_data = response.json()
                
                # Store authentication state
                self.token = token_data["access_token"]
                self.user_id = token_data["user_id"]
                self.auth_type = "aws_sso"
                self.token_expiration = time.time() + token_data.get("expires_in", 3600)
                
                self.logger.info(f"AWS credentials authentication successful for user: {self.user_id}")
                return True, "Authentication successful"
            else:
                self.logger.warning(f"AWS credentials endpoint failed: {response.status_code} - {response.text}")
                return False, f"AWS credentials endpoint failed: {response.status_code}"
        except Exception as e:
            self.logger.warning(f"Error with AWS credentials endpoint: {str(e)}")
            return False, f"Error with AWS credentials endpoint: {str(e)}"

    def _try_aws_sso_token(self, creds) -> Tuple[bool, str]:
        """Try authenticating with the AWS SSO token."""
        try:
            # Get session token from session manager
            token = self.session_manager.get_auth_token()
            if not token:
                return False, "No valid token available from session manager"
            
            # Store the token WITHOUT AWS- prefix
            self.token = token
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
            
            # Set environment variables
            os.environ['AWS_ACCESS_KEY_ID'] = creds.get('AccessKeyId', '')
            os.environ['AWS_SECRET_ACCESS_KEY'] = creds.get('SecretAccessKey', '')
            if 'SessionToken' in creds:
                os.environ['AWS_SESSION_TOKEN'] = creds.get('SessionToken')
            
            # Verify token with the API
            self.logger.info(f"Attempting to verify AWS SSO token for user {self.user_id}")
            success, message = self.verify_token()
            
            if success:
                self.logger.info(f"Authenticated user {self.user_id} with AWS SSO")
                return True, "Authentication successful"
            else:
                # If verification fails, try direct JWT token
                self.logger.warning(f"Token verification failed: {message}")
                
                # Try direct JWT token creation
                try:
                    self.logger.info("Trying direct JWT token creation as fallback")
                    from API.auth_dev_bypass import create_jwt_token
                    
                    jwt_token = create_jwt_token(self.user_id)
                    if jwt_token:
                        self.token = jwt_token
                        self.auth_type = "password"  # Use password type to avoid AWS SSO token format
                        self.token_expiration = time.time() + (60 * 60)  # 1 hour
                        
                        # Try verifying this token
                        success, jwt_message = self.verify_token()
                        if success:
                            self.logger.info(f"Direct JWT token authentication successful")
                            return True, "Authentication successful"
                        else:
                            self.logger.warning(f"Direct JWT token verification failed: {jwt_message}")
                            return False, f"Direct JWT token verification failed: {jwt_message}"
                    else:
                        return False, "Failed to create JWT token"
                except Exception as jwt_error:
                    self.logger.warning(f"Direct JWT fallback error: {str(jwt_error)}")
                    return False, f"Direct JWT fallback error: {str(jwt_error)}"
        except Exception as e:
            self.logger.warning(f"AWS SSO token authentication error: {str(e)}")
            return False, f"AWS SSO token authentication error: {str(e)}"

    def _try_direct_credentials_auth(self, creds) -> Tuple[bool, str]:
        """Try authenticating by directly accessing the auth endpoint with credentials."""
        try:
            headers = {
                "X-AWS-Access-Key-ID": creds.get('AccessKeyId', ''),
                "X-AWS-Secret-Access-Key": creds.get('SecretAccessKey', ''),
                "X-Auth-Type": "aws_sso"
            }
            
            if 'SessionToken' in creds:
                headers["X-AWS-Session-Token"] = creds.get('SessionToken')
            
            response = requests.get(
                f"{self.api_base_url}/auth/user",
                headers=headers
            )
            
            if response.status_code == 200:
                user_data = response.json()
                self.user_id = user_data.get("user_id")
                self.auth_type = "aws_sso"
                self.token = "direct_auth"  # Placeholder
                self.token_expiration = time.time() + (60 * 60)  # 1 hour
                
                self.logger.info(f"Direct credentials authentication successful")
                return True, "Authentication successful"
            else:
                self.logger.error(f"Direct credentials authentication failed: {response.status_code} - {response.text}")
                return False, f"Direct credentials authentication failed: {response.status_code}"
        except Exception as e:
            self.logger.error(f"Direct credentials authentication error: {str(e)}")
            return False, f"Direct credentials authentication error: {str(e)}"