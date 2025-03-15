"""
AWS SSO Authentication Endpoint for GUARD API

This module provides improved endpoints for handling AWS SSO authentication.
Add these endpoints to your main.py file.
"""

from fastapi import APIRouter, Header, Request, HTTPException, status
from typing import Optional, Dict, Any
from pydantic import BaseModel
import boto3
import logging
import time
import jwt
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger("api.auth.aws_sso")
logger.setLevel(logging.INFO)

# Create a router for AWS SSO endpoints
router = APIRouter(prefix="/auth", tags=["Authentication"])

# Models for request/response
class AwsSsoAuthResponse(BaseModel):
    """Model for AWS SSO authentication response."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: str


@router.post("/aws-credentials", response_model=AwsSsoAuthResponse)
async def auth_with_aws_credentials(
    request: Request,
    access_key: str = Header(..., alias="X-AWS-Access-Key-ID"),
    secret_key: str = Header(..., alias="X-AWS-Secret-Access-Key"),
    session_token: Optional[str] = Header(None, alias="X-AWS-Session-Token")
):
    """
    Authenticate with AWS credentials directly.
    
    This endpoint handles AWS SSO authentication by validating the provided
    AWS credentials and returning a JWT token for use with other API endpoints.
    """
    try:
        # Create the AWS client with the provided credentials
        sts_kwargs = {
            'aws_access_key_id': access_key,
            'aws_secret_access_key': secret_key
        }
        
        if session_token:
            sts_kwargs['aws_session_token'] = session_token
            
        # Create STS client with the credentials
        sts = boto3.client('sts', **sts_kwargs)
        
        # Validate the credentials by getting the caller identity
        identity = sts.get_caller_identity()
        user_id = identity.get('UserId', 'aws-user')
        
        # Create a JWT token with the identity information
        from auth_middleware import AuthSettings
        
        # Set token expiration (1 hour)
        expires_minutes = 60
        expiration = time.time() + (expires_minutes * 60)
        
        # Create the token payload
        payload = {
            "sub": user_id,
            "arn": identity.get("Arn", ""),
            "account": identity.get("Account", ""),
            "auth_type": "aws_sso",
            "exp": expiration,
            "iat": time.time(),
            "nbf": time.time()
        }
        
        # Create the JWT token
        token = jwt.encode(
            payload,
            AuthSettings.JWT_SECRET,
            algorithm=AuthSettings.JWT_ALGORITHM
        )
        
        # Return the token response
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": expires_minutes * 60,
            "user_id": user_id
        }
        
    except ClientError as e:
        logger.error(f"AWS credentials validation error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"AWS credentials validation failed: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        logger.error(f"Unexpected error during AWS authentication: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Authentication error: {str(e)}",
        )


@router.post("/aws-sso", response_model=AwsSsoAuthResponse)
async def auth_with_aws_sso(
    request: Request,
    access_key: str = Header(..., alias="X-AWS-Access-Key-ID"),
    secret_key: str = Header(..., alias="X-AWS-Secret-Access-Key"),
    session_token: Optional[str] = Header(None, alias="X-AWS-Session-Token")
):
    """
    Authenticate with AWS SSO.
    
    This endpoint is an alias for /aws-credentials to maintain compatibility.
    """
    return await auth_with_aws_credentials(request, access_key, secret_key, session_token)


# Export the router to include in main.py
aws_sso_router = router