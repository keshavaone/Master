# api/auth/endpoints.py
"""
Authentication API endpoints.
This module provides FastAPI endpoints for authentication.
"""

import logging
from typing import Dict, Any, Optional

from fastapi import APIRouter, Header, Request, HTTPException, status, Depends, Body

from api.auth.jwt_handler import (
    verify_token, blacklist_token, blacklist_all_user_tokens, extract_user_id_from_token
)
from api.auth.aws_sso import authenticate_with_aws_credentials
from api.auth.middleware import auth_required

# Configure logging
logger = logging.getLogger("api.auth.endpoints")
logger.setLevel(logging.INFO)

# Create a router for authentication endpoints
router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/aws-sso")
async def auth_with_aws_sso(
    request: Request,
    access_key: str = Header(..., alias="X-AWS-Access-Key-ID"),
    secret_key: str = Header(..., alias="X-AWS-Secret-Access-Key"),
    session_token: Optional[str] = Header(None, alias="X-AWS-Session-Token")
):
    """
    Authenticate with AWS SSO credentials.
    
    This endpoint allows clients to authenticate using their AWS SSO credentials.
    """
    result = authenticate_with_aws_credentials(access_key, secret_key, session_token)
    # print(result.success)
    if not result.success:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=result.error,
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    return result.to_dict()


@router.get("/user", response_model=Dict[str, Any])
async def get_user_info(user_info: Dict[str, Any] = Depends(auth_required)):
    """
    Get information about the currently authenticated user.
    
    This endpoint allows clients to get information about the currently authenticated user.
    """
    # Remove sensitive information
    safe_user_info = {
        k: v for k, v in user_info.items() 
        if not k.lower() in ["password", "secret", "key"]
    }
    
    return {
        "user_id": safe_user_info.get("sub"),
        "auth_type": safe_user_info.get("auth_type"),
        "authenticated": True,
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
    preventing their future use.
    
    Returns:
        Dict: Logout result
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