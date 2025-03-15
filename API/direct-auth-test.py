#!/usr/bin/env python3
"""
Direct authentication test script to diagnose API authentication issues.

This script directly tests authentication with the API server using 
different approaches to determine which method works.
"""

import os
import sys
import json
import requests
import logging
import hashlib
import API.CONSTANTS as CONSTANTS

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('auth_test')

# API URL
API_URL = CONSTANTS.API_BASE_URL or "http://localhost:8000"
APP_PASSWORD = CONSTANTS.APP_PASSWORD

def try_header_auth():
    """Try authentication using header-based approach."""
    try:
        logger.info("Testing header-based authentication...")
        
        # Create headers
        headers = {
            "username": "admin",
            "password": APP_PASSWORD
        }
        
        # Make request
        response = requests.post(
            f"{API_URL}/auth/token",
            headers=headers
        )
        
        # Log results
        logger.info(f"Header auth - Status code: {response.status_code}")
        logger.info(f"Header auth - Response: {response.text}")
        
        return response.status_code == 200, response.text
    except Exception as e:
        logger.error(f"Header auth error: {e}")
        return False, str(e)

def try_body_auth():
    """Try authentication using body-based approach."""
    try:
        logger.info("Testing body-based authentication...")
        
        # Create JSON body
        payload = {
            "username": "admin",
            "password": APP_PASSWORD
        }
        
        # Make request
        response = requests.post(
            f"{API_URL}/auth/token",
            json=payload
        )
        
        # Log results
        logger.info(f"Body auth - Status code: {response.status_code}")
        logger.info(f"Body auth - Response: {response.text}")
        
        return response.status_code == 200, response.text
    except Exception as e:
        logger.error(f"Body auth error: {e}")
        return False, str(e)

def try_form_auth():
    """Try authentication using form-based approach."""
    try:
        logger.info("Testing form-based authentication...")
        
        # Create form data
        data = {
            "username": "admin",
            "password": APP_PASSWORD
        }
        
        # Make request
        response = requests.post(
            f"{API_URL}/auth/token",
            data=data
        )
        
        # Log results
        logger.info(f"Form auth - Status code: {response.status_code}")
        logger.info(f"Form auth - Response: {response.text}")
        
        return response.status_code == 200, response.text
    except Exception as e:
        logger.error(f"Form auth error: {e}")
        return False, str(e)

def try_combined_auth():
    """Try authentication using combined approach."""
    try:
        logger.info("Testing combined authentication method...")
        
        # Create headers and body
        headers = {
            "Content-Type": "application/json",
            "username": "admin",
            "password": APP_PASSWORD
        }
        
        payload = {
            "username": "admin",
            "password": APP_PASSWORD
        }
        
        # Make request
        response = requests.post(
            f"{API_URL}/auth/token",
            headers=headers,
            json=payload
        )
        
        # Log results
        logger.info(f"Combined auth - Status code: {response.status_code}")
        logger.info(f"Combined auth - Response: {response.text}")
        
        return response.status_code == 200, response.text
    except Exception as e:
        logger.error(f"Combined auth error: {e}")
        return False, str(e)

def test_api_endpoint(path="/health"):
    """Test that the API is reachable and running."""
    try:
        logger.info(f"Testing API connectivity at {API_URL}{path}...")
        
        response = requests.get(f"{API_URL}{path}")
        
        logger.info(f"API connectivity test - Status code: {response.status_code}")
        
        if response.status_code == 200:
            logger.info("API is reachable and running")
            return True
        else:
            logger.error(f"API returned non-200 status: {response.status_code}")
            return False
    except Exception as e:
        logger.error(f"API connectivity error: {e}")
        return False

def main():
    """Run all authentication tests."""
    logger.info(f"Starting API authentication tests against {API_URL}")
    
    # First verify the API is reachable
    if not test_api_endpoint():
        logger.error("API is not reachable. Please check if the server is running.")
        return False
    
    # Check if we have the APP_PASSWORD
    if not APP_PASSWORD:
        logger.error("APP_PASSWORD is not set in CONSTANTS. Cannot proceed with tests.")
        return False
    
    logger.info(f"Using admin user and APP_PASSWORD (masked: ****) for tests")
    
    # Try all authentication methods
    methods = [
        ("Header auth", try_header_auth),
        ("Body auth", try_body_auth),
        ("Form auth", try_form_auth),
        ("Combined auth", try_combined_auth)
    ]
    
    success = False
    for name, method in methods:
        logger.info(f"Trying {name} method...")
        result, response = method()
        
        if result:
            logger.info(f"✅ SUCCESS! {name} method works!")
            success = True
        else:
            logger.info(f"❌ FAILED! {name} method doesn't work.")
    
    if success:
        logger.info("Authentication test succeeded with at least one method.")
        return True
    else:
        logger.error("All authentication methods failed.")
        return False

if __name__ == "__main__":
    result = main()
    sys.exit(0 if result else 1)