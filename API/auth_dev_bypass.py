"""
Development authentication bypass that creates JWT tokens directly.

This module provides a direct method for creating valid JWT tokens
without calling the API's authentication endpoint, which is useful
when the API's authentication endpoint is not working properly.

IMPORTANT: This is for development and testing purposes only.
"""

import os
import time
import json
import logging
import hashlib
import requests
from typing import Dict, Any, Optional, Tuple
import API.CONSTANTS as CONSTANTS

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('auth_dev_bypass')

# JWT configuration - should match what's in auth_middleware.py
JWT_SECRET = os.environ.get("AUTH_JWT_SECRET", "default_secret")  # Default value from auth_middleware.py
JWT_ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 60

# Try to import the correct PyJWT library
try:
    import jwt as pyjwt
    # Test if this is the right PyJWT library
    if not hasattr(pyjwt, 'encode'):
        logger.warning("The imported jwt module doesn't have encode method. Trying PyJWT...")
        # Explicitly try to import PyJWT
        import PyJWT as pyjwt
        logger.info("Successfully imported PyJWT")
except ImportError:
    logger.warning("JWT module not found. Trying to install PyJWT...")
    try:
        import subprocess
        import sys
        subprocess.check_call([sys.executable, "-m", "pip", "install", "PyJWT"])
        import PyJWT as pyjwt
        logger.info("Successfully installed and imported PyJWT")
    except Exception as e:
        logger.error(f"Failed to install PyJWT: {e}")
        # Provide a fallback implementation that logs error
        class DummyJWT:
            @staticmethod
            def encode(*args, **kwargs):
                logger.error("JWT encode failed: PyJWT not available")
                return "INVALID_TOKEN_JWT_MISSING"
        pyjwt = DummyJWT()

def create_jwt_token(user_id: str, user_data: Dict[str, Any] = None, expires_minutes: int = None) -> str:
    """
    Create a JWT token directly without using the API's auth endpoint.
    
    This function creates a token with the same format as the API would create,
    but without making an API call.
    
    Args:
        user_id (str): User identifier
        user_data (Dict[str, Any], optional): Additional user data
        expires_minutes (int, optional): Token expiration in minutes
        
    Returns:
        str: JWT token
    """
    # Set expiration time
    expiration = expires_minutes or TOKEN_EXPIRE_MINUTES
    now = time.time()
    expires = now + expiration * 60
    
    # Create the token payload
    payload = {
        "sub": user_id,  # JWT subject claim (user ID)
        "exp": expires,
        "iat": now,
        "nbf": now,  # Not valid before current time
        "type": "access",
        "auth_type": "password"
    }
    
    # Add additional user data if provided
    if user_data:
        payload.update(user_data)
    
    # Try to create the token
    try:
        # Check which encode method is available
        if hasattr(pyjwt, 'encode'):
            token = pyjwt.encode(
                payload, 
                JWT_SECRET, 
                algorithm=JWT_ALGORITHM
            )
            
            # Handle bytes vs string for different jwt versions
            if isinstance(token, bytes):
                token = token.decode('utf-8')
                
            return token
        else:
            raise AttributeError("No encode method available in jwt module")
            
    except Exception as e:
        logger.error(f"Failed to create JWT token: {e}")
        # Fall back to a temporary token - useful for testing but won't work for real auth
        return f"DUMMY_TOKEN_{user_id}_{int(now)}"

def verify_app_password(input_password: str) -> bool:
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
        
    # Hash both passwords for comparison
    hashed_input = hashlib.sha256(input_password.encode()).hexdigest()
    hashed_env = hashlib.sha256(env_password.encode()).hexdigest()
    
    return hashed_input == hashed_env

def get_direct_token(username: str, password: str) -> Tuple[bool, Dict[str, Any]]:
    """
    Get a token directly without using the API's auth endpoint.
    
    Args:
        username (str): Username for authentication
        password (str): Password for authentication
        
    Returns:
        Tuple[bool, Dict]: Success flag and token data or error message
    """
    try:
        # Verify password
        if not verify_app_password(password):
            logger.error("Password verification failed")
            return False, {"error": "Invalid password"}
        
        # Create token directly
        token = create_jwt_token(username)
        
        # Return token data in the same format as the API would
        token_data = {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": TOKEN_EXPIRE_MINUTES * 60,
            "user_id": username
        }
        
        logger.info(f"Created direct JWT token for user: {username}")
        return True, token_data
        
    except Exception as e:
        error_msg = f"Error creating direct token: {str(e)}"
        logger.error(error_msg)
        return False, {"error": error_msg}

def make_authenticated_request(token: str, method: str, endpoint: str, 
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
        logger.info(f"Making {method} request to {url}")
        logger.info(f"Headers: {headers}")
        if data:
            logger.info(f"Data: {data}")
        
        # Make the request
        response = requests.request(
            method=method.upper(),
            url=url,
            headers=headers,
            json=data,
            params=params
        )
        
        # Log response details
        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Response: {response.text[:100]}...")
        
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

def test_bypassed_auth():
    """Test the authentication bypass functionality."""
    username = "admin"
    password = CONSTANTS.APP_PASSWORD
    
    if not password:
        logger.error("APP_PASSWORD not set in CONSTANTS")
        return
    
    # Get token directly
    success, token_data = get_direct_token(username, password)
    
    if success:
        logger.info(f"Authentication successful for user: {username}")
        logger.info(f"Token: {token_data['access_token'][:20]}...")
        logger.info(f"Expires in: {token_data['expires_in']} seconds")
        
        # Test a protected endpoint (start with health check)
        success, data = make_authenticated_request(
            token_data['access_token'],
            "GET",
            "health"
        )
        
        if success:
            logger.info(f"Health check succeeded: {data}")
            
            # Now try a protected endpoint
            success, user_data = make_authenticated_request(
                token_data['access_token'],
                "GET",
                "auth/user"
            )
            
            if success:
                logger.info(f"Protected endpoint access succeeded: {user_data}")
            else:
                logger.error(f"Protected endpoint access failed: {user_data}")
        else:
            logger.error(f"Health check failed: {data}")
    else:
        logger.error(f"Authentication failed: {token_data}")

if __name__ == "__main__":
    # Run test when module is executed directly
    test_bypassed_auth()