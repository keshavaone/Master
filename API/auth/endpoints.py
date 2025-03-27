
# api/auth/endpoints.py
"""
Authentication API endpoints.
This module provides FastAPI endpoints for authentication.
"""

from typing import Dict, Any, Optional

from fastapi import APIRouter, Header, Request, HTTPException, status, Depends, Body

from api.auth.jwt_handler import verify_token, blacklist_token
from api.auth.aws_sso import authenticate_with_aws_credentials
from api.auth.middleware import auth_required

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

@router.post("/logout",tags=['Yet to Complete'])
async def logout(
    request: Request,
    authorization: str = Header(None),
    refresh_token: str = Body(None, embed=True)
):
    """
    Logout the current user by invalidating their tokens.
    
    This endpoint invalidates the access token and optionally the refresh token
    to prevent their future use.
    
    Args:
        authorization: The authorization header containing the access token
        refresh_token: The refresh token to invalidate (optional)
        
    Returns:
        Dict: Logout result
    """
    client_ip = request.client.host if request.client else "unknown"
    user_id = "unknown"
    tokens_revoked = 0
    
    # Extract the access token from the authorization header
    access_token = None
    if authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            access_token = parts[1]
    
    # Invalidate the access token if provided
    if access_token:
        # Validate the token to get the user ID
        success, payload = verify_token(access_token)
        if success and payload:
            user_id = payload.get("sub", "unknown")
            
        # Blacklist the token regardless of validation result
        if blacklist_token(access_token):
            tokens_revoked += 1
            # logger.info(f"Access token revoked for user {user_id} from {client_ip}")
    
    # Invalidate the refresh token if provided
    if refresh_token:
        # Validate the refresh token to confirm user ID
        success, payload = verify_token(refresh_token)
        if success and payload:
            token_user_id = payload.get("sub")
            if token_user_id:
                user_id = token_user_id
        
        # Blacklist the refresh token
        if blacklist_token(refresh_token):
            tokens_revoked += 1
            # logger.info(f"Refresh token revoked for user {user_id} from {client_ip}")
    
    return {
        "success": True,
        "message": "Logout successful",
        "user_id": user_id,
        "tokens_revoked": tokens_revoked
    }

