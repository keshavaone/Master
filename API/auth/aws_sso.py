
# api/auth/aws_sso.py
"""
AWS SSO authentication functionality.
This module provides utilities for AWS SSO authentication.
"""

import logging
import os
import json
import time
import webbrowser
from typing import Dict, Any, Optional, Tuple

import boto3
import requests
from botocore.exceptions import ClientError

from api.auth.core import AuthSettings, AuthResult
from api.auth.jwt_handler import create_access_token
from api.CONSTANTS import AWS_LOGIN_URL, AWS_SSO_CONFIG_DIR

# Configure logging
logger = logging.getLogger("api.auth.aws_sso")
logger.setLevel(logging.INFO)


def get_caller_identity(
    access_key: str,
    secret_key: str,
    session_token: Optional[str] = None
) -> Tuple[bool, Dict[str, Any]]:
    """
    Get AWS caller identity using provided credentials.

    Args:
        access_key: AWS access key ID
        secret_key: AWS secret access key
        session_token: Optional AWS session token

    Returns:
        Tuple[bool, Dict[str, Any]]: Success flag and identity information
    """
    # For testing environments, bypass actual AWS validation
    if AuthSettings.BYPASS_AWS_SDK_VALIDATION:
        logger.info("AWS SDK validation bypassed (for testing only)")
        return True, {
            "UserId": "MyVirtualUser",
            "Arn": "arn:aws:iam::817215275254:user/MyVirtualUser",
            "Account": "817215275254"
        }

    try:
        # Set up AWS client with the provided credentials
        sts_kwargs = {
            'aws_access_key_id': access_key,
            'aws_secret_access_key': secret_key,
            'region_name': AuthSettings.AWS_REGION
        }

        if session_token:
            sts_kwargs['aws_session_token'] = session_token

        # Create STS client with the credentials
        sts = boto3.client('sts', **sts_kwargs)

        # Get caller identity
        identity = sts.get_caller_identity()
        return True, identity
    except ClientError as e:
        logger.error(f"AWS STS validation error: {e}")
        return False, {"error": str(e)}
    except Exception as e:
        logger.error(f"Unexpected error validating AWS credentials: {e}")
        return False, {"error": str(e)}


def init_sso_session_directory():
    """
    Initialize the SSO session directory for storing cached credentials.

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        if not os.path.exists(AWS_SSO_CONFIG_DIR):
            os.makedirs(AWS_SSO_CONFIG_DIR)
            logger.info(
                f"Created AWS SSO config directory: {AWS_SSO_CONFIG_DIR}")
        return True
    except Exception as e:
        logger.error(f"Failed to create AWS SSO config directory: {e}")
        return False


def check_cached_sso_credentials() -> Optional[Dict[str, Any]]:
    """
    Check for cached SSO credentials.

    Returns:
        Optional[Dict[str, Any]]: Cached credentials if valid, None otherwise
    """
    try:
        cache_file = os.path.join(AWS_SSO_CONFIG_DIR, "sso_credentials.json")
        if not os.path.exists(cache_file):
            return None

        with open(cache_file, "r") as f:
            cached_data = json.load(f)

        # Check if credentials are expired
        if cached_data.get("expires_at", 0) < time.time():
            logger.info("Cached SSO credentials have expired")
            return None

        return cached_data
    except Exception as e:
        logger.error(f"Error reading cached SSO credentials: {e}")
        return None


def save_sso_credentials(credentials: Dict[str, Any]):
    """
    Save SSO credentials to cache.

    Args:
        credentials: AWS credentials to cache
    """
    try:
        cache_file = os.path.join(AWS_SSO_CONFIG_DIR, "sso_credentials.json")

        with open(cache_file, "w") as f:
            json.dump(credentials, f)

        logger.info("Saved SSO credentials to cache")
    except Exception as e:
        logger.error(f"Error saving SSO credentials to cache: {e}")


def start_aws_sso_login(redirect_url: Optional[str] = None) -> Dict[str, Any]:
    """
    Start the AWS SSO login process.

    Args:
        redirect_url: Optional URL to redirect after login

    Returns:
        Dict[str, Any]: Login information including URL
    """
    # Initialize session directory
    init_sso_session_directory()

    # Check for cached credentials first
    cached_creds = check_cached_sso_credentials()
    if cached_creds:
        logger.info("Using cached AWS SSO credentials")
        return {
            "success": True,
            "message": "Using cached AWS SSO credentials",
            "credentials": cached_creds,
            "cached": True
        }

    # Generate all potential URLs for SSO login
    # Base domain for the SSO portal
    base_sso_domain = AWS_LOGIN_URL.split('/start')[0]
    
    # Direct access portal login URL (primary target)
    login_url = f"{base_sso_domain}/login"
    
    # Base domain without any path (for root access)
    portal_url = base_sso_domain
    
    # Start URL for the SSO journey (original flow)
    start_url = f"{base_sso_domain}/start"
    
    # Alternative hardcoded URLs (fallbacks)
    alternative_urls = [
        "https://d-9067c603c9.awsapps.com/login",  # Direct login portal
        "https://d-9067c603c9.awsapps.com",        # Root domain
        "https://d-9067c603c9.awsapps.com/start"   # Start URL
    ]

    # Log available URLs
    logger.info(f"AWS SSO login URL options:")
    logger.info(f"1. Direct access portal URL: {login_url}")
    logger.info(f"2. Portal root URL: {portal_url}")
    logger.info(f"3. SSO start URL: {start_url}")
    logger.info(f"4. Original URL: {AWS_LOGIN_URL}")
    
    # Log alternative URLs
    for i, url in enumerate(alternative_urls):
        logger.info(f"Alt {i+1}: {url}")

    if redirect_url:
        logger.info(f"Client redirect URL (will be handled after login): {redirect_url}")

    # Don't try to open browser from server-side anymore
    # Let the frontend handle the browser navigation
    
    # Return all potential URLs for the client to try (prioritizing direct access portal)
    return {
        "success": True,
        "message": "Please login using the AWS SSO login portal",
        "login_url": login_url,              # Direct access portal (priority 1)
        "portal_url": portal_url,            # Root domain (priority 2)
        "start_url": start_url,              # Traditional start URL (priority 3)
        "original_url": AWS_LOGIN_URL,       # Original URL for reference
        "alternative_urls": alternative_urls, # Fallback URLs
        "instructions": "After logging in through the AWS access portal, return to the application to complete authentication"
    }


def complete_aws_sso_login(sso_code: str) -> AuthResult:
    """
    Complete the AWS SSO login process with the code received after browser login.

    Args:
        sso_code: The code received from AWS SSO login

    Returns:
        AuthResult: The authentication result
    """
    try:
        # In a real implementation, this would exchange the SSO code for tokens
        # with the AWS SSO token endpoint

        # For this example, we'll simulate success and create credentials
        # that would normally come from AWS SSO

        # Create simulated credentials
        credentials = {
            "access_key": f"ASIA{os.urandom(8).hex()}",
            "secret_key": os.urandom(32).hex(),
            "session_token": os.urandom(64).hex(),
            "expires_at": time.time() + 3600,  # 1 hour expiry
            "sso_user": f"user-{os.urandom(4).hex()}@example.com"
        }

        # Save credentials to cache
        save_sso_credentials(credentials)

        # Validate the credentials with AWS STS
        success, identity = get_caller_identity(
            credentials["access_key"],
            credentials["secret_key"],
            credentials["session_token"]
        )

        if not success:
            return AuthResult(
                success=False,
                error=f"AWS credentials validation failed: {identity.get('error', 'Unknown error')}"
            )

        # Get the user ID from the identity
        user_id = identity.get(
            "UserId", credentials.get("sso_user", "aws-user"))

        # Create user data for the token
        user_data = {
            "arn": identity.get("Arn", ""),
            "account": identity.get("Account", ""),
            "auth_type": "aws_sso",
            "login_method": "aws_sso_browser"
        }

        # Create a JWT token
        token, expires_at = create_access_token(
            user_id=user_id,
            user_data=user_data,
            expires_minutes=60  # 1 hour by default
        )

        if not token:
            return AuthResult(
                success=False,
                error="Failed to create token"
            )

        return AuthResult(
            success=True,
            user_id=user_id,
            token=token,
            expires_at=expires_at,
            auth_type="aws_sso",
            user_info=user_data
        )
    except Exception as e:
        logger.error(f"Unexpected error during AWS SSO authentication: {e}")
        return AuthResult(
            success=False,
            error=f"Authentication error: {str(e)}"
        )


def authenticate_with_aws_credentials(
    access_key: str,
    secret_key: str,
    session_token: Optional[str] = None
) -> AuthResult:
    """
    Authenticate with AWS credentials.

    Args:
        access_key: AWS access key ID
        secret_key: AWS secret access key
        session_token: Optional AWS session token

    Returns:
        AuthResult: Result of the authentication
    """
    try:
        # Validate credentials with AWS STS
        success, identity = get_caller_identity(
            access_key, secret_key, session_token)

        if not success:
            return AuthResult(
                success=False,
                error=f"AWS credentials validation failed: {identity.get('error', 'Unknown error')}"
            )

        # Get the user ID from the identity
        user_id = identity.get("UserId", "aws-user")
        # Create user data for the token
        user_data = {
            "arn": identity.get("Arn", ""),
            "account": identity.get("Account", ""),
            "auth_type": "aws_sso"
        }
        # Create a JWT token
        token, expires_at = create_access_token(
            user_id=user_id,
            user_data=user_data,
            expires_minutes=60  # 1 hour by default
        )

        if not token:
            return AuthResult(
                success=False,
                error="Failed to create token"
            )

        return AuthResult(
            success=True,
            user_id=user_id,
            token=token,
            expires_at=expires_at,
            auth_type="aws_sso",
            user_info=user_data
        )
    except Exception as e:
        logger.error(f"Unexpected error during AWS authentication: {e}")
        return AuthResult(
            success=False,
            error=f"Authentication error: {str(e)}"
        )
