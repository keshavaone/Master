
# api/auth/endpoints.py
"""
Authentication API endpoints.
This module provides FastAPI endpoints for authentication.
"""

from typing import Dict, Any, Optional

from fastapi import APIRouter, Header, Request, HTTPException, status, Depends

from api.auth.jwt_handler import refresh_token
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

@router.post("/token/refresh")
async def refresh_auth_token(user_info: Dict[str, Any] = Depends(auth_required)):
    """
    Refresh an authentication token.
    
    This endpoint allows clients to refresh their authentication token.
    """
    # Get the token from the request
    token = user_info.get("token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No token provided"
        )
        
    # Refresh the token
    result = refresh_token(token)
    
    if not result.success:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=result.error,
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    return result.to_dict()

@router.get("/user")
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
async def logout(user_info: Dict[str, Any] = Depends(auth_required)):
    """
    Logout the current user.
    
    This endpoint allows clients to logout.
    """
    return {
        "message": "Logout successful",
        "user_id": user_info.get("sub"),
    }

