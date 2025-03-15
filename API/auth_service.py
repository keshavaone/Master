"""
Enhanced Authentication Service for GUARD Application

This service provides a unified authentication layer between frontend and API,
properly handling AWS SSO tokens and session TTLs.
"""

import os
import time
import json
import logging
import datetime
import boto3
from typing import Dict, Any, Optional, Tuple
from botocore.exceptions import ClientError, ProfileNotFound, NoCredentialsError

# Configure logging
logger = logging.getLogger("enhanced_auth_service")
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

class EnhancedAuthService:
    """
    Enhanced authentication service that properly manages AWS SSO sessions
    and supports multiple authentication methods with appropriate session TTLs.
    """
    
    def __init__(self, api_base_url: str, session_manager=None):
        """
        Initialize the authentication service.
        
        Args:
            api_base_url (str): Base URL for the API server
            session_manager: Optional session manager instance for UI integration
        """
        self.api_base_url = api_base_url.rstrip('/')
        self.session_manager = session_manager
        self.token = None
        self.token_expiration = None
        self.user_id = None
        self.auth_type = None
        self.aws_credentials = None
        self.aws_session = None
        
        # Default TTLs for different auth methods (in seconds)
        self.ttl_settings = {
            "password": 3600,        # 1 hour
            "aws_sso": 8 * 3600,     # 8 hours (typical AWS SSO default)
            "refresh_threshold": 300  # 5 minutes before expiry
        }
        
        logger.info(f"Enhanced authentication service initialized for {api_base_url}")
    
    def authenticate_with_password(self, username: str, password: str) -> Tuple[bool, str]:
        """
        Authenticate with username and password.
        
        Args:
            username (str): Username for authentication
            password (str): Password for authentication
            
        Returns:
            Tuple[bool, str]: (Success flag, message)
        """
        try:
            import requests
            
            # Prepare request with multiple auth formats for compatibility
            headers = {
                "Content-Type": "application/json",
                "username": username,
                "password": password
            }
            
            body = {
                "username": username,
                "password": password
            }
            
            logger.info(f"Authenticating user {username} with password")
            
            # Make the API request
            response = requests.post(
                f"{self.api_base_url}/auth/token",
                headers=headers,
                json=body,
                timeout=10  # Add timeout for security
            )
            
            if response.status_code == 200:
                token_data = response.json()
                
                # Set authentication state
                self.token = token_data["access_token"]
                self.user_id = token_data["user_id"]
                self.auth_type = "password"
                
                # Set expiration time - use provided value or default
                expires_in = token_data.get("expires_in", self.ttl_settings["password"])
                self.token_expiration = time.time() + expires_in
                
                logger.info(f"Successfully authenticated user {self.user_id} with password")
                
                # Sync with session manager if available
                self._sync_with_session_manager()
                
                return True, "Authentication successful"
            else:
                error_msg = f"Authentication failed: {response.status_code} - {response.text}"
                logger.error(error_msg)
                return False, error_msg
                
        except Exception as e:
            error_msg = f"Authentication error: {str(e)}"
            logger.error(error_msg)
            return False, error_msg

    def authenticate_with_aws_sso(self) -> Tuple[bool, str]:
        """
        Authenticate with AWS SSO using the session manager or environment credentials.
        
        Returns:
            Tuple[bool, str]: (Success flag, message)
        """
        try:
            # First try to get credentials from session manager
            if self.session_manager and hasattr(self.session_manager, 'credentials'):
                credentials = self.session_manager.credentials
                logger.info("Using AWS credentials from session manager")
            else:
                # Fall back to boto3 session
                try:
                    session = boto3.Session()
                    credentials = session.get_credentials()
                    
                    if not credentials or not credentials.access_key:
                        logger.warning("No AWS credentials available from boto3 session")
                        return False, "No AWS credentials available"
                        
                    # Convert to dictionary format
                    credentials = {
                        'AccessKeyId': credentials.access_key,
                        'SecretAccessKey': credentials.secret_key
                    }
                    
                    if hasattr(credentials, 'token') and credentials.token:
                        credentials['SessionToken'] = credentials.token
                        
                    logger.info("Using AWS credentials from boto3 session")
                except (NoCredentialsError, Exception) as e:
                    logger.error(f"Failed to get AWS credentials: {str(e)}")
                    return False, f"AWS credential error: {str(e)}"
            
            # Store credentials for later use
            self.aws_credentials = credentials
            
            # Try to authenticate with the API using AWS credentials
            try:
                import requests
                
                # Prepare headers with AWS credentials
                headers = {
                    "X-AWS-Access-Key-ID": credentials.get('AccessKeyId', ''),
                    "X-AWS-Secret-Access-Key": credentials.get('SecretAccessKey', '')
                }
                
                # Add session token if available
                if 'SessionToken' in credentials:
                    headers["X-AWS-Session-Token"] = credentials.get('SessionToken')
                
                # Try the auth endpoint
                logger.info("Authenticating with AWS credentials via API")
                response = requests.post(
                    f"{self.api_base_url}/auth/aws-sso",
                    headers=headers,
                    timeout=10
                )
                
                if response.status_code == 200:
                    token_data = response.json()
                    
                    # Set authentication state
                    self.token = token_data["access_token"]
                    self.user_id = token_data["user_id"]
                    self.auth_type = "aws_sso"
                    
                    # Set expiration based on token TTL or default AWS SSO TTL
                    expires_in = token_data.get("expires_in", self.ttl_settings["aws_sso"])
                    self.token_expiration = time.time() + expires_in
                    
                    logger.info(f"API authentication successful for AWS SSO user {self.user_id}")
                    
                    # Sync with session manager
                    self._sync_with_session_manager()
                    
                    return True, "AWS SSO authentication successful"
                else:
                    # API authentication failed - try direct AWS authentication
                    logger.warning(f"API AWS SSO authentication failed: {response.status_code} - {response.text}")
            except Exception as api_error:
                logger.warning(f"API AWS SSO authentication error: {str(api_error)}")
            
            # Fall back to direct AWS authentication
            try:
                # Create AWS session with credentials
                self.aws_session = boto3.Session(
                    aws_access_key_id=credentials.get('AccessKeyId'),
                    aws_secret_access_key=credentials.get('SecretAccessKey'),
                    aws_session_token=credentials.get('SessionToken')
                )
                
                # Verify credentials by making a test call
                sts = self.aws_session.client('sts')
                identity = sts.get_caller_identity()
                
                # Set authentication state
                self.token = credentials.get('SessionToken', 'direct-aws-auth')
                self.user_id = identity.get('UserId', 'aws-user')
                self.auth_type = "aws_sso"
                
                # Set expiration based on session manager or default
                if self.session_manager and hasattr(self.session_manager, 'expiration_time'):
                    # Convert to timestamp if datetime
                    expiration = self.session_manager.expiration_time
                    if isinstance(expiration, datetime.datetime):
                        self.token_expiration = expiration.timestamp()
                    else:
                        self.token_expiration = time.time() + self.ttl_settings["aws_sso"]
                else:
                    # Default expiration
                    self.token_expiration = time.time() + self.ttl_settings["aws_sso"]
                
                logger.info(f"Direct AWS authentication successful for user {self.user_id}")
                
                # Sync with session manager
                self._sync_with_session_manager()
                
                return True, "AWS SSO authentication successful (direct)"
            except Exception as aws_error:
                logger.error(f"Direct AWS authentication error: {str(aws_error)}")
                return False, f"AWS authentication failed: {str(aws_error)}"
        except Exception as e:
            error_msg = f"AWS SSO authentication error: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
            
    def _sync_with_session_manager(self):
        """Sync authentication state with the session manager if available."""
        if not self.session_manager:
            return
            
        try:
            # Update session manager properties if they exist
            if hasattr(self.session_manager, 'user_id'):
                self.session_manager.user_id = self.user_id
                
            if hasattr(self.session_manager, 'auth_type'):
                self.session_manager.auth_type = self.auth_type
                
            if hasattr(self.session_manager, 'token_expiration') and self.token_expiration:
                # Convert to datetime if needed
                if isinstance(self.session_manager.expiration_time, datetime.datetime):
                    self.session_manager.expiration_time = datetime.datetime.fromtimestamp(
                        self.token_expiration
                    )
                else:
                    self.session_manager.token_expiration = self.token_expiration
                
            if hasattr(self.session_manager, 'is_authenticated'):
                self.session_manager.is_authenticated = True
                
            if hasattr(self.session_manager, 'session_token') and self.token:
                self.session_manager.session_token = self.token
                
            logger.info("Synchronized authentication state with session manager")
        except Exception as e:
            logger.warning(f"Error syncing with session manager: {str(e)}")
    
    def is_authenticated(self) -> bool:
        """
        Check if the user is authenticated.
        
        Returns:
            bool: True if authenticated
        """
        if not self.token or not self.token_expiration:
            return False
            
        # Check if token is expired
        return time.time() < self.token_expiration
    
    def requires_refresh(self) -> bool:
        """
        Check if the token requires refresh.
        
        Returns:
            bool: True if token needs refresh
        """
        if not self.is_authenticated():
            return False
            
        # Check if we're within the refresh threshold
        time_remaining = self.token_expiration - time.time()
        return time_remaining < self.ttl_settings["refresh_threshold"]
    
    async def refresh_token(self) -> bool:
        """
        Refresh the authentication token.
        
        Returns:
            bool: True if refresh was successful
        """
        if not self.is_authenticated():
            logger.warning("Cannot refresh token: not authenticated")
            return False
            
        try:
            # Different refresh strategies based on auth type
            if self.auth_type == "aws_sso":
                # For AWS SSO, re-authenticate using saved credentials
                if self.aws_credentials:
                    # Re-verify AWS credentials with STS
                    if self.aws_session:
                        try:
                            sts = self.aws_session.client('sts')
                            sts.get_caller_identity()
                            
                            # Still valid, extend token expiration
                            self.token_expiration = time.time() + self.ttl_settings["aws_sso"]
                            
                            # Sync with session manager
                            self._sync_with_session_manager()
                            
                            logger.info(f"Extended AWS SSO token expiration to {self.token_expiration}")
                            return True
                        except Exception as e:
                            logger.warning(f"AWS credential verification failed: {str(e)}")
                    
                    # Fall back to re-authentication
                    success, _ = self.authenticate_with_aws_sso()
                    return success
                else:
                    logger.warning("No AWS credentials available for refresh")
                    return False
            else:
                # For password auth, call the refresh endpoint
                import requests
                
                headers = self.get_auth_headers()
                response = requests.post(
                    f"{self.api_base_url}/auth/token/refresh",
                    headers=headers,
                    timeout=10
                )
                
                if response.status_code == 200:
                    token_data = response.json()
                    
                    # Update token and expiration
                    self.token = token_data["access_token"]
                    expires_in = token_data.get("expires_in", self.ttl_settings["password"])
                    self.token_expiration = time.time() + expires_in
                    
                    # Sync with session manager
                    self._sync_with_session_manager()
                    
                    logger.info(f"Token refreshed for user {self.user_id}")
                    return True
                else:
                    logger.error(f"Token refresh failed: {response.status_code} - {response.text}")
                    return False
        except Exception as e:
            logger.error(f"Token refresh error: {str(e)}")
            return False
    
    def get_auth_headers(self) -> Dict[str, str]:
        """
        Get authentication headers for API requests.
        
        Returns:
            Dict[str, str]: Headers for authentication
        """
        headers = {}
        
        if not self.token:
            return headers
            
        # Add standard authorization header with token
        if self.auth_type == "aws_sso" and self.aws_credentials:
            # For AWS SSO, include the AWS credentials for direct verification
            if 'AccessKeyId' in self.aws_credentials:
                headers["X-AWS-Access-Key-ID"] = self.aws_credentials['AccessKeyId']
            if 'SecretAccessKey' in self.aws_credentials:
                headers["X-AWS-Secret-Access-Key"] = self.aws_credentials['SecretAccessKey']
            if 'SessionToken' in self.aws_credentials:
                headers["X-AWS-Session-Token"] = self.aws_credentials['SessionToken']
        
        # Always include the token
        prefix = "AWS-" if self.auth_type == "aws_sso" else ""
        headers["Authorization"] = f"Bearer {prefix}{self.token}"
        
        return headers
    
    def make_synchronous_request(self, method, endpoint, data=None, params=None):
        """
        Synchronous version of make_authenticated_request.
        
        Args:
            method (str): HTTP method (GET, POST, etc.)
            endpoint (str): API endpoint path
            data: Request body data
            params: Query parameters
            
        Returns:
            tuple: (success, response_data)
        """
        import asyncio
        
        # Create and run a new event loop
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(
                self.make_authenticated_request(method, endpoint, data, params)
            )
        finally:
            loop.close()
            
    async def make_authenticated_request(self, method: str, endpoint: str, 
                                     data: Any = None, params: Dict = None) -> Tuple[bool, Any]:
        """
        Make an authenticated request to the API.
        
        Args:
            method (str): HTTP method (GET, POST, etc.)
            endpoint (str): API endpoint path (without base URL)
            data (Any, optional): Request data
            params (Dict, optional): Query parameters
            
        Returns:
            Tuple[bool, Any]: (Success flag, response data or error)
        """
        # Check authentication
        if not self.is_authenticated():
            logger.warning("Cannot make request: not authenticated")
            return False, {"error": "Not authenticated"}
        
        # Check if token needs refresh
        if self.requires_refresh():
            logger.info("Token requires refresh before request")
            refresh_success = await self.refresh_token()
            
            if not refresh_success:
                logger.warning("Token refresh failed")
                # Continue with the current token if it's still valid
                if not self.is_authenticated():
                    return False, {"error": "Authentication expired and refresh failed"}
        
        try:
            import requests
            
            # Prepare the URL
            url = f"{self.api_base_url}/{endpoint.lstrip('/')}"
            
            # Get authentication headers
            headers = self.get_auth_headers()
            
            # Extra security logging
            method_log = method.upper()
            url_log = url.split('?')[0]  # Remove query params for logging
            logger.info(f"Making {method_log} request to {url_log}")
            
            # Make the request
            response = requests.request(
                method=method.upper(),
                url=url,
                json=data,
                params=params,
                headers=headers,
                timeout=30  # Add reasonable timeout
            )
            
            # Log response code
            logger.info(f"Response status: {response.status_code}")
            
            # Handle response
            if response.status_code >= 200 and response.status_code < 300:
                # Success - try to parse as JSON first
                try:
                    return True, response.json()
                except ValueError:
                    # Not JSON, return as text
                    return True, response.text
            elif response.status_code == 401:
                # Token may have expired during request
                logger.warning("Request returned 401 Unauthorized")
                
                # Try to refresh token and retry once
                refresh_success = await self.refresh_token()
                if refresh_success:
                    logger.info("Token refreshed, retrying request")
                    
                    # Get fresh headers after refresh
                    headers = self.get_auth_headers()
                    
                    # Retry the request
                    retry_response = requests.request(
                        method=method.upper(),
                        url=url,
                        json=data,
                        params=params,
                        headers=headers,
                        timeout=30
                    )
                    
                    if retry_response.status_code >= 200 and retry_response.status_code < 300:
                        try:
                            return True, retry_response.json()
                        except ValueError:
                            return True, retry_response.text
                
                # If we get here, both attempts failed
                error_msg = f"Authentication failed for request: {response.status_code} - {response.text}"
                logger.error(error_msg)
                return False, {"error": error_msg}
            else:
                # Other error status code
                error_msg = f"Request failed: {response.status_code} - {response.text}"
                logger.error(error_msg)
                return False, {"error": error_msg}
                
        except Exception as e:
            error_msg = f"Request error: {str(e)}"
            logger.error(error_msg)
            return False, {"error": error_msg}
            
    def logout(self) -> bool:
        """
        Perform logout operations.
        
        Returns:
            bool: True if successful
        """
        try:
            prev_user = self.user_id
            
            # Clear auth state
            self.token = None
            self.token_expiration = None
            self.user_id = None
            self.auth_type = None
            self.aws_credentials = None
            self.aws_session = None
            
            # Sync with session manager
            if self.session_manager and hasattr(self.session_manager, 'logout'):
                try:
                    self.session_manager.logout()
                except Exception as e:
                    logger.warning(f"Error in session manager logout: {str(e)}")
            
            logger.info(f"Logged out user: {prev_user}")
            return True
        except Exception as e:
            logger.error(f"Logout error: {str(e)}")
            return False
    
    def get_session_info(self) -> Dict[str, Any]:
        """
        Get information about the current session.
        
        Returns:
            Dict[str, Any]: Session information
        """
        remaining_seconds = None
        if self.is_authenticated() and self.token_expiration:
            remaining_seconds = max(0, int(self.token_expiration - time.time()))
        
        return {
            "is_authenticated": self.is_authenticated(),
            "auth_type": self.auth_type,
            "user_id": self.user_id,
            "token_expires_at": datetime.datetime.fromtimestamp(self.token_expiration).isoformat() if self.token_expiration else None,
            "remaining_seconds": remaining_seconds,
            "remaining_formatted": self._format_time_remaining(remaining_seconds) if remaining_seconds else None,
            "has_aws_session": self.aws_session is not None
        }
    
    def _format_time_remaining(self, seconds: int) -> str:
        """
        Format seconds into a human-readable duration.
        
        Args:
            seconds (int): Time in seconds
            
        Returns:
            str: Formatted time string
        """
        if seconds is None:
            return "--:--"
            
        minutes, seconds = divmod(seconds, 60)
        hours, minutes = divmod(minutes, 60)
        
        if hours > 0:
            return f"{hours}h {minutes}m"
        else:
            return f"{minutes}m {seconds}s"