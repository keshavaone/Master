# api/controllers/auth_enhanced_controller.py
"""
Enhanced authentication controller with React UI support.

This module provides authentication endpoints that support the GUARD React interface.
"""

import logging
import time
from typing import Dict, Any, Optional
from fastapi import APIRouter, Header, Request, HTTPException, status, Depends, Body, Query
from pydantic import BaseModel, Field

from api.auth.jwt_handler import (
    verify_token, blacklist_token, extract_user_id_from_token,
    authenticate_with_credentials
)
from api.auth.aws_sso import authenticate_with_aws_credentials
from api.auth.middleware import auth_required

# Configure logging
logger = logging.getLogger("api.controllers.auth_enhanced")
logger.setLevel(logging.INFO)

# Create router
router = APIRouter(prefix="/auth", tags=["Authentication"])

# Models for credentials authentication
class LoginCredentials(BaseModel):
    username: str = Field(..., description="Username for authentication")
    password: str = Field(..., description="Password for authentication")

class RefreshTokenRequest(BaseModel):
    refresh_token: str = Field(..., description="Refresh token to use for getting new access token")

@router.post("/aws-sso", response_model=Dict[str, Any])
async def auth_with_aws_sso(
    request: Request,
    access_key: str = Header(..., alias="X-AWS-Access-Key-ID"),
    secret_key: str = Header(..., alias="X-AWS-Secret-Access-Key"),
    session_token: Optional[str] = Header(None, alias="X-AWS-Session-Token")
):
    """
    Authenticate with AWS SSO credentials.
    
    This endpoint allows clients to authenticate using their AWS SSO credentials,
    supporting the React login interface.
    """
    client_ip = request.client.host if request.client else "unknown"
    logger.info(f"AWS SSO auth request from {client_ip}")
    
    result = authenticate_with_aws_credentials(access_key, secret_key, session_token)
    
    if not result.success:
        logger.warning(f"AWS SSO auth failed: {result.error}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=result.error,
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Add user profile information for UI
    user_info = result.user_info or {}
    
    # Extract user-friendly name from ARN if available
    user_name = "User"
    if "arn" in user_info:
        arn = user_info["arn"]
        # Try to extract username from ARN
        import re
        name_match = re.search(r"/([^/]+)$", arn)
        if name_match:
            user_name = name_match.group(1)
    
    # Add profile info to response
    response_data = result.to_dict()
    response_data["profile"] = {
        "name": user_name,
        "role": user_info.get("role", "User"),
        "picture": None  # AWS SSO doesn't provide pictures
    }
    
    logger.info(f"AWS SSO auth successful for user {result.user_id}")
    return response_data

@router.post("/login")
async def login_with_credentials(
    request: Request,
    credentials: LoginCredentials
):
    """
    Authenticate with username and password.
    
    This endpoint allows clients to authenticate using traditional credentials,
    supporting the React login interface.
    """
    client_ip = request.client.host if request.client else "unknown"
    logger.info(f"Password auth request from {client_ip}")
    
    # Check credentials (this would normally validate against a database)
    # In this implementation, we're using placeholder validation
    # In production, you'd use a secure password verification system
    
    from api.auth.core import AuthSettings
    from hashlib import sha256
    import os
    
    # For demo purposes - in production use a proper user store
    # This is just a placeholder implementation
    username = credentials.username
    password = credentials.password
    
    # Check if username exists
    valid_users = {
        "admin": {
            "password_hash": sha256(f"admin123{os.environ.get('AUTH_SALT', '')}".encode()).hexdigest(),
            "name": "Admin User",
            "role": "Administrator"
        },
        "user": {
            "password_hash": sha256(f"user123{os.environ.get('AUTH_SALT', '')}".encode()).hexdigest(),
            "name": "Regular User",
            "role": "User"
        }
    }
    
    if username not in valid_users:
        logger.warning(f"Login attempt with unknown username: {username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Check password
    user_record = valid_users[username]
    password_hash = sha256(f"{password}{os.environ.get('AUTH_SALT', '')}".encode()).hexdigest()
    
    if password_hash != user_record["password_hash"]:
        logger.warning(f"Failed login attempt for user: {username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Authentication successful - create tokens
    result = authenticate_with_credentials(
        user_id=username,
        additional_data={
            "name": user_record["name"],
            "role": user_record["role"],
            "auth_type": "password"
        }
    )
    
    if not result.success:
        logger.error(f"Failed to create token for user {username}: {result.error}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication error"
        )
    
    # Add user profile information for UI
    response_data = result.to_dict()
    response_data["profile"] = {
        "name": user_record["name"],
        "role": user_record["role"],
        "picture": None  # No pictures in this simple implementation
    }
    
    logger.info(f"Password auth successful for user {username}")
    return response_data

@router.post("/refresh")
async def refresh_auth_token(
    request: Request,
    refresh_data: RefreshTokenRequest
):
    """
    Refresh an authentication token using a refresh token.
    
    This endpoint allows clients to get a new access token without re-authenticating,
    supporting the React application's session management.
    """
    client_ip = request.client.host if request.client else "unknown"
    logger.info(f"Token refresh request from {client_ip}")
    
    from api.auth.jwt_handler import refresh_with_token
    
    # Refresh the token
    result = refresh_with_token(refresh_data.refresh_token)
    
    if not result.success:
        logger.warning(f"Token refresh failed: {result.error}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=result.error,
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    logger.info(f"Token refreshed successfully for user {result.user_id}")
    return result.to_dict()

@router.get("/user", response_model=Dict[str, Any])
async def get_user_info(user_info: Dict[str, Any] = Depends(auth_required)):
    """
    Get information about the currently authenticated user.
    
    This endpoint allows clients to get user profile information,
    supporting the React dashboard's user display.
    """
    # Remove sensitive information
    safe_user_info = {
        k: v for k, v in user_info.items() 
        if not k.lower() in ["password", "secret", "key", "token"]
    }
    
    # Format user information for UI
    user_id = safe_user_info.get("sub")
    auth_type = safe_user_info.get("auth_type", "unknown")
    
    # Extract name from user info
    name = safe_user_info.get("name", user_id)
    
    # Get role information if available
    role = safe_user_info.get("role", "User")
    
    # Create profile object
    profile = {
        "user_id": user_id,
        "name": name,
        "role": role,
        "auth_type": auth_type,
        "authenticated": True,
        "picture": None  # We don't have pictures in this implementation
    }
    
    return {
        "user_id": user_id,
        "auth_type": auth_type,
        "authenticated": True,
        "profile": profile,
        **safe_user_info
    }

@router.post("/logout")
async def logout(
    request: Request,
    user_info: Dict[str, Any] = Depends(auth_required)
):
    """
    Logout the current user by invalidating all their tokens.
    
    This endpoint automatically invalidates all tokens for the authenticated user,
    supporting the React dashboard's logout functionality.
    """
    try:
        # Get user details
        user_id = user_info.get("sub")
        auth_type = user_info.get("auth_type")
        client_ip = request.client.host if request.client else "unknown"
        
        logger.info(f"Processing logout for user {user_id} ({auth_type}) from {client_ip}")
        
        # Get the token from the authorization header
        auth_header = request.headers.get('Authorization', '')
        token = None
        if auth_header.startswith('Bearer '):
            token = auth_header.replace('Bearer ', '')
        
        # If we have a token, blacklist it immediately
        tokens_invalidated = 0
        if token:
            if blacklist_token(token):
                tokens_invalidated += 1
                logger.info(f"Current token invalidated for user {user_id}")
        
        # For JWT auth type, invalidate all tokens for this user
        if auth_type == "jwt":
            from api.auth.jwt_handler import blacklist_all_user_tokens
            additional_tokens = blacklist_all_user_tokens(user_id)
            tokens_invalidated += additional_tokens
            logger.info(f"Invalidated {additional_tokens} additional tokens for user {user_id}")
        
        # For AWS SSO, we can't invalidate session tokens directly from our API
        # We should inform the user to close their browser or log out from AWS Console
        aws_sso_message = ""
        if auth_type == "aws_sso":
            aws_sso_message = "For complete AWS SSO logout, please also log out from your AWS Console session."
        
        return {
            "success": True,
            "message": f"Logout successful. {tokens_invalidated} tokens invalidated. {aws_sso_message}".strip(),
            "user_id": user_id,
            "tokens_invalidated": tokens_invalidated
        }
    except Exception as e:
        logger.error(f"Error during logout: {e}")
        
        # Even if there's an error, try to blacklist the current token
        try:
            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                token = auth_header.replace('Bearer ', '')
                blacklist_token(token)
        except Exception:
            pass
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error processing logout"
        )