"""
Authentication bypass module for development and testing.

This module provides a simplified authentication approach when AWS SSO 
is not available or not working properly. This should only be used for
development and testing, not for production environments.
"""

import os
import json
import time
import logging
import requests
import hashlib
from typing import Dict, Any, Optional, Tuple
import API.CONSTANTS as CONSTANTS

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('auth_bypass')

def get_direct_token(username: str, password: str) -> Tuple[bool, Dict[str, Any]]:
    """
    Get a direct token from the API using username and password.
    
    Args:
        username (str): Username for authentication
        password (str): Password for authentication
        
    Returns:
        Tuple[bool, Dict]: Success flag and token data or error message
    """
    try:
        # The API expects the credentials in a request body (TokenRequest model in FastAPI)
        headers = {
            "Content-Type": "application/json"
        }
        
        # Create JSON body payload
        payload = {
            "username": "admin",  # Always use "admin" regardless of input
            "password": password
        }
        
        # Call the API token endpoint
        logger.info(f"Requesting direct token with body parameters")
        response = requests.post(
            f"{CONSTANTS.API_BASE_URL}/auth/token",
            headers=headers,
            json=payload  # Send in request body
        )
        
        # Log full request details for debugging
        logger.info(f"Request URL: {CONSTANTS.API_BASE_URL}/auth/token")
        logger.info(f"Request headers: {headers}")
        logger.info(f"Request body: {payload}")
        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Response body: {response.text}")
        
        # Check response
        if response.status_code == 200:
            token_data = response.json()
            logger.info(f"Successfully obtained token for admin user")
            return True, token_data
        else:
            error_msg = f"Failed to get token: {response.status_code} - {response.text}"
            logger.error(error_msg)
            return False, {"error": error_msg}
            
    except Exception as e:
        error_msg = f"Error getting token: {str(e)}"
        logger.error(error_msg)
        return False, {"error": error_msg}

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
        
        # Make the request
        response = requests.request(
            method=method.upper(),
            url=url,
            headers=headers,
            json=data,
            params=params
        )
        
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

# Simple test function to verify the module works
def test_authentication():
    """Test the authentication bypass functionality."""
    # Use the admin username and APP_PASSWORD directly
    username = "admin"
    password = CONSTANTS.APP_PASSWORD
    
    if not password:
        logger.error("APP_PASSWORD not set in CONSTANTS")
        return
    
    # Get token
    success, token_data = get_direct_token(username, password)
    
    if success:
        logger.info(f"Authentication successful for admin user")
        logger.info(f"Token: {token_data['access_token'][:10]}...")
        logger.info(f"Expires in: {token_data['expires_in']} seconds")
        
        # Test a protected endpoint
        success, data = make_authenticated_request(
            token_data['access_token'],
            "GET",
            "auth/user"
        )
        
        if success:
            logger.info(f"Successfully accessed protected endpoint: {data}")
        else:
            logger.error(f"Failed to access protected endpoint: {data}")
    else:
        logger.error(f"Authentication failed: {token_data}")

if __name__ == "__main__":
    # Run test when module is executed directly
    test_authentication()