"""
Authentication endpoints for the GUARD API.

This module provides API endpoints for user authentication, token
generation, verification, and management.
"""

import os
import time
import hashlib
import logging
from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Header, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

# Import JWT utilities
from API.jwt_utils import create_user_token, verify_user_token, jwt_manager
import API.CONSTANTS as CONSTANTS

# Configure logging
logger = logging.getLogger("api.auth")
logger.setLevel(logging.INFO)

# Create router
router = APIRouter(prefix="/auth", tags=["Authentication"])

# Models for request/response
class TokenRequest(BaseModel):
    """Model for token request."""
    username: str
    password: str

class TokenResponse(BaseModel):
    """Model for token response."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: str

class TokenVerifyRequest(BaseModel):
    """Model for token verification request."""
    token: str

class TokenVerifyResponse(BaseModel):
    """Model for token verification response."""
    valid: bool
    user_id: Optional[str] = None
    expires_in: Optional[int] = None

class UserInfoResponse(BaseModel):
    """Model for user info response."""
    user_id: str
    auth_type: str
    authenticated: bool = True


# Security scheme for protected endpoints
security = HTTPBearer()


@router.post("/token", response_model=TokenResponse)
async def login_for_token(request: TokenRequest):
    """
    Authenticate user and generate a JWT token.
    
    Args:
        request: Authentication request with username and password
        
    Returns:
        TokenResponse: JWT token information
        
    Raises:
        HTTPException: If authentication fails
    """
    # Verify credentials
    authenticated = verify_credentials(request.username, request.password)
    
    if not authenticated:
        logger.warning(f"Failed login attempt for user: {request.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Generate token with user info
    user_data = {
        "name": request.username,
        "auth_type": "password"
    }
    
    # Default expiration from settings
    expires_minutes = CONSTANTS.AUTH_TOKEN_EXPIRE_MINUTES
    
    # Create token
    token = create_user_token(request.username, user_data, expires_minutes)
    
    logger.info(f"Generated token for user: {request.username}")
    
    # Return token response
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": expires_minutes * 60,  # Convert to seconds
        "user_id": request.username
    }


@router.post("/token/verify", response_model=TokenVerifyResponse)
async def verify_token(request: TokenVerifyRequest):
    """
    Verify if a token is valid.
    
    Args:
        request: Token verification request
        
    Returns:
        TokenVerifyResponse: Token validity information
    """
    valid, payload = verify_user_token(request.token)
    
    if valid and payload:
        # Calculate remaining time
        expires_at = payload.get("exp", 0)
        current_time = time.time()
        expires_in = max(0, int(expires_at - current_time))
        
        return {
            "valid": True,
            "user_id": payload.get("sub"),
            "expires_in": expires_in
        }
    else:
        return {
            "valid": False
        }


@router.post("/token/refresh", response_model=TokenResponse)
async def refresh_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Refresh an existing token.
    
    Args:
        credentials: Authorization credentials with the current token
        
    Returns:
        TokenResponse: New JWT token information
        
    Raises:
        HTTPException: If token is invalid or expired
    """
    token = credentials.credentials
    
    # Verify the current token
    valid, payload = verify_user_token(token)
    
    if not valid or not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Get user ID from token
    user_id = payload.get("sub")
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create a new token
    user_data = {k: v for k, v in payload.items() if k not in ['exp', 'iat', 'nbf']}
    expires_minutes = CONSTANTS.AUTH_TOKEN_EXPIRE_MINUTES
    
    new_token = create_user_token(user_id, user_data, expires_minutes)
    
    logger.info(f"Refreshed token for user: {user_id}")
    
    # Return token response
    return {
        "access_token": new_token,
        "token_type": "bearer",
        "expires_in": expires_minutes * 60,  # Convert to seconds
        "user_id": user_id
    }


@router.get("/user", response_model=UserInfoResponse)
async def get_user_info(request: Request, credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Get information about the authenticated user.
    
    Args:
        request: The HTTP request
        credentials: Authorization credentials
        
    Returns:
        UserInfoResponse: User information
        
    Raises:
        HTTPException: If token is invalid
    """
    token = credentials.credentials
    
    # Handle AWS SSO token format
    if token.startswith("AWS-"):
        # For AWS SSO tokens, we would validate differently
        # This is a simplified example - in production you'd verify with AWS
        try:
            # Extract user info from request state (set by middleware)
            user_id = getattr(request.state, "user_id", None)
            
            if not user_id:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid AWS SSO token",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            return {
                "user_id": user_id,
                "auth_type": "aws_sso",
                "authenticated": True
            }
        except Exception as e:
            logger.error(f"Error validating AWS SSO token: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid AWS SSO token",
                headers={"WWW-Authenticate": "Bearer"},
            )
    
    # For JWT tokens
    valid, payload = verify_user_token(token)
    
    if not valid or not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Extract user information
    user_id = payload.get("sub")
    auth_type = payload.get("auth_type", "password")
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return {
        "user_id": user_id,
        "auth_type": auth_type,
        "authenticated": True
    }


# Helper function to verify credentials
def verify_credentials(username: str, password: str) -> bool:
    """
    Verify user credentials.
    
    Args:
        username: Username to verify
        password: Password to verify
        
    Returns:
        bool: True if credentials are valid
    """
    # In a real system, you'd check against a database
    # This is a simplified example using the app password
    
    # Get the app password from constants
    app_password = CONSTANTS.APP_PASSWORD
    
    if not app_password:
        logger.warning("No APP_PASSWORD defined in constants")
        return False
    
    # Only allow specific usernames
    allowed_users = ["admin", "guard_user", os.environ.get('USER', '')]
    if username not in allowed_users:
        return False
    
    # Hash the password and compare
    hashed_input = hashlib.sha256(password.encode()).hexdigest()
    hashed_stored = hashlib.sha256(app_password.encode()).hexdigest()
    
    return hashed_input == hashed_stored