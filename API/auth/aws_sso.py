
# api/auth/aws_sso.py
"""
AWS SSO authentication functionality.
This module provides utilities for AWS SSO authentication.
"""

import logging
from typing import Dict, Any, Optional, Tuple

import boto3
from botocore.exceptions import ClientError

from api.auth.core import AuthSettings, AuthResult
from api.auth.jwt_handler import create_token

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
        success, identity = get_caller_identity(access_key, secret_key, session_token)
        
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
        token, expires_at = create_token(
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