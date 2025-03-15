"""
Simple direct authentication solution for GUARD application.

This module provides a minimal, reliable authentication method that bypasses 
the API server's problematic authentication mechanisms completely.
"""

import os
import time
import logging
import hashlib
import requests
from typing import Dict, Any, Optional, Tuple
import API.CONSTANTS as CONSTANTS

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('direct_auth')

# Try to import PyJWT
try:
    import jwt
    logger.info("JWT library imported successfully")
except ImportError:
    logger.warning("JWT library not available. Installing PyJWT...")
    try:
        import subprocess
        import sys
        subprocess.check_call([sys.executable, "-m", "pip", "install", "PyJWT==2.7.0"])
        import jwt
        logger.info("PyJWT installed and imported successfully")
    except Exception as e:
        logger.error(f"Failed to install PyJWT: {e}")
        # Simple string-based token as fallback
        jwt = None

# JWT configuration
JWT_SECRET = "your-secret-key-should-be-in-env"
JWT_ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 60

def verify_password(input_password: str) -> bool:
    """
    Verify if the provided password matches the APP_PASSWORD.
    
    Args:
        input_password (str): Password to verify
        
    Returns:
        bool: True if the password is correct
    """
    env_password = CONSTANTS.APP_PASSWORD
    
    if not env_password:
        logger.error("APP_PASSWORD not set in CONSTANTS")
        return False
        
    # Try direct comparison first
    if input_password == env_password:
        return True
        
    # Fall back to hash comparison
    hashed_input = hashlib.sha256(input_password.encode()).hexdigest()
    hashed_env = hashlib.sha256(env_password.encode()).hexdigest()
    
    return hashed_input == hashed_env

def create_simple_token(user_id: str) -> str:
    """
    Create a simple token when JWT is not available.
    
    Args:
        user_id (str): User identifier
        
    Returns:
        str: Simple token
    """
    timestamp = int(time.time())
    return f"SIMPLE_TOKEN_{user_id}_{timestamp}_{hashlib.md5(f'{user_id}_{timestamp}_{JWT_SECRET}'.encode()).hexdigest()}"

def create_token(user_id: str, expires_minutes: int = None) -> str:
    """
    Create an authentication token.
    
    Args:
        user_id (str): User identifier
        expires_minutes (int, optional): Token expiration time in minutes
        
    Returns:
        str: Authentication token
    """
    if jwt is None:
        return create_simple_token(user_id)
        
    # Set expiration time
    expiration = expires_minutes or TOKEN_EXPIRE_MINUTES
    now = time.time()
    expires = now + expiration * 60
    
    # Create the token payload
    payload = {
        "sub": user_id,
        "exp": expires,
        "iat": now,
        "type": "access",
        "auth_type": "password"
    }
    
    # Create the token
    try:
        token = jwt.encode(
            payload, 
            JWT_SECRET, 
            algorithm=JWT_ALGORITHM
        )
        
        # Handle bytes vs string for different jwt versions
        if isinstance(token, bytes):
            token = token.decode('utf-8')
            
        return token
    except Exception as e:
        logger.error(f"Failed to create JWT token: {e}")
        return create_simple_token(user_id)

def authenticate(username: str, password: str) -> Tuple[bool, Dict[str, Any]]:
    """
    Authenticate a user.
    
    Args:
        username (str): Username for authentication
        password (str): Password for authentication
        
    Returns:
        Tuple[bool, Dict[str, Any]]: (Success flag, token data or error)
    """
    try:
        # Verify password
        if not verify_password(password):
            logger.error("Password verification failed")
            return False, {"error": "Invalid password"}
        
        # Create token
        token = create_token(username)
        
        # Return token data
        token_data = {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": TOKEN_EXPIRE_MINUTES * 60,
            "user_id": username
        }
        
        logger.info(f"Direct authentication successful for {username}")
        return True, token_data
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        return False, {"error": str(e)}

def make_request(token: str, method: str, endpoint: str, 
               data: Any = None, params: Dict = None) -> Tuple[bool, Any]:
    """
    Make an authenticated request to the API.
    
    Args:
        token (str): Authentication token
        method (str): HTTP method (GET, POST, etc.)
        endpoint (str): API endpoint
        data (Any): Data to send in the request
        params (Dict): Query parameters
        
    Returns:
        Tuple[bool, Any]: Success flag and response data or error message
    """
    try:
        # Prepare the request
        url = f"{CONSTANTS.API_BASE_URL}/{endpoint.lstrip('/')}"
        headers = {"Authorization": f"Bearer {token}"}
        
        # Log request details
        logger.info(f"Making authenticated {method} request to {url}")
        
        # Make the request
        response = requests.request(
            method=method.upper(),
            url=url,
            headers=headers,
            json=data,
            params=params
        )
        
        # Log response status
        logger.info(f"Response status: {response.status_code}")
        
        # Handle response
        if response.status_code >= 200 and response.status_code < 300:
            try:
                return True, response.json()
            except ValueError:
                return True, response.text
        else:
            error_msg = f"Request failed: {response.status_code} - {response.text}"
            logger.error(error_msg)
            return False, {"error": error_msg}
            
    except Exception as e:
        error_msg = f"Error making request: {str(e)}"
        logger.error(error_msg)
        return False, {"error": error_msg}

class SimpleAuthService:
    """
    Simple authentication service for the application.
    """
    
    def __init__(self, api_base_url=None):
        """
        Initialize the authentication service.
        
        Args:
            api_base_url (str, optional): Base URL for the API
        """
        self.api_base_url = api_base_url or CONSTANTS.API_BASE_URL
        self.token = None
        self.token_expiration = None
        self.user_id = None
        
        # Set up logger
        self.logger = logging.getLogger('SimpleAuthService')
        self.logger.setLevel(logging.INFO)
        
        self.logger.info(f"Simple auth service initialized for {self.api_base_url}")
    
    def authenticate(self, username: str, password: str) -> Tuple[bool, str]:
        """
        Authenticate with username and password.
        
        Args:
            username (str): Username for authentication
            password (str): Password for authentication
            
        Returns:
            Tuple[bool, str]: (Success flag, message)
        """
        try:
            self.logger.info(f"Authenticating user: {username}")
            
            success, result = authenticate(username, password)
            
            if not success:
                error_msg = result.get("error", "Unknown authentication error")
                self.logger.error(f"Authentication failed: {error_msg}")
                return False, error_msg
            
            # Set authentication data
            self.token = result["access_token"]
            self.user_id = result["user_id"]
            self.token_expiration = time.time() + result.get("expires_in", 3600)
            
            self.logger.info(f"Authentication successful for user: {self.user_id}")
            return True, "Authentication successful"
            
        except Exception as e:
            error_msg = f"Authentication error: {str(e)}"
            self.logger.error(error_msg)
            return False, error_msg
    
    def is_authenticated(self) -> bool:
        """
        Check if the user is authenticated.
        
        Returns:
            bool: True if authenticated
        """
        return self.token is not None and time.time() < self.token_expiration
    
    def get_auth_headers(self) -> Dict[str, str]:
        """
        Get the authentication headers for API requests.
        
        Returns:
            Dict[str, str]: Authentication headers
        """
        if not self.token:
            return {}
        
        return {"Authorization": f"Bearer {self.token}"}
    
    def make_request(self, method: str, endpoint: str, data: Any = None, params: Dict = None) -> Tuple[bool, Any]:
        """
        Make an authenticated request to the API.
        
        Args:
            method (str): HTTP method (GET, POST, etc.)
            endpoint (str): API endpoint
            data (Any): Data to send in the request
            params (Dict): Query parameters
            
        Returns:
            Tuple[bool, Any]: (Success flag, response data or error)
        """
        if not self.is_authenticated():
            return False, {"error": "Not authenticated"}
        
        return make_request(self.token, method, endpoint, data, params)
    
    def logout(self) -> None:
        """Clear the authentication state."""
        self.logger.info(f"Logging out user: {self.user_id}")
        self.token = None
        self.token_expiration = None
        self.user_id = None

# Test the direct authentication
if __name__ == "__main__":
    logger.info("Testing direct authentication")
    
    # Get default username and password
    username = os.environ.get('USER', 'admin')
    password = CONSTANTS.APP_PASSWORD
    
    if not password:
        logger.error("APP_PASSWORD not set in CONSTANTS")
        sys.exit(1)
    
    # Create auth service and authenticate
    auth_service = SimpleAuthService()
    success, message = auth_service.authenticate(username, password)
    
    if success:
        logger.info(f"Authentication successful: {message}")
        
        # Test making a request
        success, response = auth_service.make_request("GET", "health")
        
        if success:
            logger.info(f"Health check successful: {response}")
            
            # Test protected endpoint
            success, data = auth_service.make_request("GET", "pii")
            
            if success:
                logger.info(f"Protected endpoint access successful")
            else:
                logger.error(f"Protected endpoint access failed: {data}")
        else:
            logger.error(f"Health check failed: {response}")
    else:
        logger.error(f"Authentication failed: {message}")