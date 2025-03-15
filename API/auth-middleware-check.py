#!/usr/bin/env python3
"""
Authentication test script to diagnose AWS SSO token validation issues.

This script helps identify and troubleshoot issues with the authentication
middleware by directly testing AWS SSO token handling.
"""

import os
import sys
import json
import boto3
import requests
import logging
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('auth_test')

# API URL - update with your actual URL
API_URL = "http://localhost:8000"

def check_middleware_version():
    """Check the version of the auth middleware being used."""
    try:
        from API.auth_middleware import AuthDependency, auth_required
        logger.info(f"Auth middleware module found. Checking implementation...")
        
        # Inspect how tokens are validated
        token_validation_code = getattr(AuthDependency, '_validate_aws_token', None)
        if token_validation_code:
            logger.info("Auth middleware has AWS SSO token validation method")
        else:
            logger.error("Auth middleware does NOT have AWS SSO token validation method")
            
        return True
    except ImportError:
        logger.error("Could not import auth_middleware module")
        return False

def get_aws_sso_token():
    """Get an AWS SSO token from the current environment."""
    try:
        # First check if we have AWS credentials in the environment
        logger.info("Checking for AWS credentials in environment...")
        required_vars = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN']
        
        if all(var in os.environ for var in required_vars):
            logger.info("AWS credentials found in environment variables")
            
            # Test the credentials by making a simple AWS API call
            try:
                sts = boto3.client('sts')
                identity = sts.get_caller_identity()
                logger.info(f"AWS identity check successful: {identity.get('UserId')}")
                
                # Return the session token as our AWS SSO token
                return os.environ['AWS_SESSION_TOKEN']
            except Exception as e:
                logger.error(f"AWS identity check failed: {str(e)}")
                return None
        else:
            logger.warning("AWS credentials not found in environment variables")
            return None
    except Exception as e:
        logger.error(f"Error getting AWS token: {str(e)}")
        return None

def test_auth_middleware(aws_token):
    """Test the auth middleware with an AWS SSO token."""
    try:
        logger.info(f"Testing API auth with AWS SSO token...")
        
        # First try with the expected "AWS-" prefix
        headers = {"Authorization": f"Bearer AWS-{aws_token}"}
        
        logger.info(f"Making request to {API_URL}/auth/user with AWS- prefix")
        response = requests.get(f"{API_URL}/auth/user", headers=headers)
        
        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Response body: {response.text}")
        
        if response.status_code == 200:
            logger.info("Authentication successful with AWS- prefix!")
            return True
        else:
            logger.warning("Authentication failed with AWS- prefix")
            
            # Try without the prefix as a test
            headers = {"Authorization": f"Bearer {aws_token}"}
            
            logger.info(f"Making request to {API_URL}/auth/user without AWS- prefix")
            response = requests.get(f"{API_URL}/auth/user", headers=headers)
            
            logger.info(f"Response status: {response.status_code}")
            logger.info(f"Response body: {response.text}")
            
            if response.status_code == 200:
                logger.info("Authentication successful without AWS- prefix!")
                return True
            else:
                logger.error("Authentication failed with both formats")
                return False
    except Exception as e:
        logger.error(f"Error testing auth middleware: {str(e)}")
        return False

def check_api_health():
    """Check if the API is healthy and running."""
    try:
        logger.info(f"Checking API health at {API_URL}/health")
        response = requests.get(f"{API_URL}/health")
        
        if response.status_code == 200:
            logger.info(f"API is healthy: {response.json()}")
            return True
        else:
            logger.error(f"API health check failed: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        logger.error(f"API appears to be down or unreachable: {str(e)}")
        return False

def main():
    """Main test function."""
    logger.info("Starting AWS SSO authentication test")
    
    # First check API health
    if not check_api_health():
        logger.error("API is not available. Please start the API server first.")
        return False
    
    # Check middleware code
    check_middleware_version()
    
    # Get an AWS SSO token
    aws_token = get_aws_sso_token()
    if not aws_token:
        logger.error("Could not get AWS SSO token. Please configure AWS SSO.")
        return False
    
    # Test the auth middleware
    success = test_auth_middleware(aws_token)
    
    if success:
        logger.info("Authentication test successful!")
        return True
    else:
        logger.error("Authentication test failed!")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)