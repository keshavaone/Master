# api/auth/middleware.py
"""
FastAPI middleware for authentication.
This module provides middleware for FastAPI applications.
"""

import logging
import time
from typing import Dict, Any, Optional

from fastapi import Request, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from api.auth.core import AuthSettings
from api.auth.jwt_handler import verify_token
from api.auth.aws_sso import get_caller_identity

# Configure logging
logger = logging.getLogger("api.auth.middleware")
logger.setLevel(logging.INFO)

class AuthDependency(HTTPBearer):
    """
    FastAPI dependency for handling authentication.
    
    This class provides a dependency that can be used with FastAPI
    to handle authentication for API endpoints.
    """
    
    def __init__(self, auto_error: bool = True):
        """
        Initialize the authentication dependency.
        
        Args:
            auto_error: Whether to automatically raise an error for authentication failures
        """
        super().__init__(auto_error=auto_error)
        
    async def __call__(self, request: Request) -> Optional[Dict[str, Any]]:
        """
        Process and validate the authentication token.
        
        Args:
            request: The incoming request
            
        Returns:
            Dict containing user information from token
            
        Raises:
            HTTPException: If authentication fails
        """
        if not AuthSettings.REQUIRE_AUTH:
            # Skip auth if disabled (for development only)
            logger.warning("Authentication is disabled. This should not be used in production.")
            return {"sub": "anonymous", "auth_type": "none"}
        
        # Store the request for use in token validation
        self.request = request
            
        credentials: HTTPAuthorizationCredentials = await super().__call__(request)
        
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        # Extract the token
        token = credentials.credentials
        user_info = None
        
        # Check for AWS credentials in headers (highest priority)
        aws_access_key = request.headers.get('X-AWS-Access-Key-ID')
        aws_secret_key = request.headers.get('X-AWS-Secret-Access-Key')
        
        if aws_access_key and aws_secret_key:
            logger.info("Found AWS credentials in headers, validating...")
            aws_session_token = request.headers.get('X-AWS-Session-Token')
            
            # Validate AWS credentials
            success, identity = get_caller_identity(
                aws_access_key, aws_secret_key, aws_session_token
            )
            
            if success:
                # Create user info from the identity data
                user_info = {
                    "sub": identity.get("UserId", "aws-user"),
                    "arn": identity.get("Arn", ""),
                    "account": identity.get("Account", ""),
                    "auth_type": "aws_sso",
                    "exp": time.time() + 3600,  # 1 hour expiration
                    "token": token  # Add the token to user_info
                }
                
                logger.info(f"Successfully authenticated with AWS credentials for user {user_info.get('sub', 'unknown')}")
                
                # Store token info in request state for logging
                request.state.user_id = user_info.get("sub", "unknown")
                request.state.auth_type = user_info.get("auth_type", "aws_sso")
                return user_info
            
            logger.warning("AWS credentials validation failed, continuing to other auth methods")
        
        # Check token type and validate
        if token.startswith("AWS-"):
            # AWS SSO token - validate with AWS STS
            aws_token = token.replace("AWS-", "")
            
            try:
                # Here, we would typically validate the token with AWS STS
                # For this example, we're just checking a placeholder token for testing
                if AuthSettings.BYPASS_AWS_SDK_VALIDATION or aws_token == "BYPASS_TEST_TOKEN":
                    user_info = {
                        "sub": "aws-user",
                        "auth_type": "aws_sso",
                        "exp": time.time() + 3600,  # 1 hour expiration
                        "token": token  # Add the token to user_info
                    }
                else:
                    # Try to validate the token with AWS STS
                    # This would be a real implementation in a production system
                    pass
                    
            except Exception as e:
                logger.error(f"Error validating AWS SSO token: {e}")
                # Continue to JWT validation
        else:
            # JWT token
            success, payload = verify_token(token)
            if success and payload:
                user_info = payload
                user_info["token"] = token  # Add the token to user_info
                
        if not user_info:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token or expired token",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        # Store token info in request state for logging
        request.state.user_id = user_info.get("sub", "unknown")
        request.state.auth_type = user_info.get("auth_type", "unknown")
        
        return user_info

# Create an instance of the auth dependency
auth_required = AuthDependency()