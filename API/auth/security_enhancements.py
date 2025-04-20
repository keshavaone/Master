"""
Enhanced security features for the API.
This module provides additional security features like rate limiting and token management.
"""

import time
import logging
import os
import webbrowser
from typing import Dict, Any, Set, Optional, Union
from datetime import datetime, timedelta

from fastapi import Request, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError

from api.CONSTANTS import AWS_LOGIN_URL, AWS_SSO_ENABLED, AUTH_TOKEN_EXPIRE_MINUTES
from api.auth.aws_sso import start_aws_sso_login

# Configure logging
logger = logging.getLogger("api.auth.security")
logger.setLevel(logging.INFO)

# OAuth2 password bearer for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

# Token blacklist for logout functionality
token_blacklist: Set[str] = set()

# Rate limiting configuration
rate_limit_store: Dict[str, Dict[str, Any]] = {}
rate_limit_window = 60  # 1 minute window
rate_limit_max_requests = 100  # 100 requests per minute

async def verify_token(token: str) -> Dict[str, Any]:
    """
    Verify JWT token and return decoded payload.
    """
    try:
        # Check if token is blacklisted
        if token in token_blacklist:
            logger.warning(f"Attempt to use blacklisted token")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked"
            )
            
        # Verify and decode the token
        payload = jwt.decode(
            token,
            os.environ.get("JWT_SECRET", "secret"),
            algorithms=[os.environ.get("JWT_ALGORITHM", "HS256")]
        )
        
        # Check if token has expired
        if 'exp' in payload and payload['exp'] < time.time():
            logger.warning(f"Expired token used")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired"
            )
            
        return payload
    except JWTError as e:
        logger.error(f"JWT error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )

async def apply_rate_limit(request: Request) -> None:
    """
    Apply rate limiting logic to incoming requests.
    
    Args:
        request: The incoming request
        
    Raises:
        HTTPException: If rate limit is exceeded
    """
    client_ip = request.client.host
    current_time = time.time()
    
    # Initialize or update rate limit tracking for this IP
    if client_ip not in rate_limit_store:
        rate_limit_store[client_ip] = {
            'count': 0,
            'window_start': current_time
        }
    
    # Reset counter if window has expired
    if current_time - rate_limit_store[client_ip]['window_start'] > rate_limit_window:
        rate_limit_store[client_ip] = {
            'count': 0,
            'window_start': current_time
        }
    
    # Increment request counter
    rate_limit_store[client_ip]['count'] += 1
    
    # Check if rate limit exceeded
    if rate_limit_store[client_ip]['count'] > rate_limit_max_requests:
        logger.warning(f"Rate limit exceeded for IP: {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded"
        )

async def blacklist_token(token: str) -> bool:
    """
    Add a token to the blacklist (for logout functionality)
    
    Args:
        token: The token to blacklist
        
    Returns:
        bool: True if token was blacklisted
    """
    token_blacklist.add(token)
    logger.info(f"Token blacklisted")
    
    # Clean up blacklist if it gets too large (keep most recent 10000 tokens)
    if len(token_blacklist) > 10000:
        logger.warning("Token blacklist is getting large, cleaning up")
        # In a production system, you would want a more sophisticated approach
        # This simple approach just keeps the most recent tokens
        temp_list = list(token_blacklist)
        token_blacklist.clear()
        token_blacklist.update(temp_list[-10000:])
        
    return True

async def oauth2_auth(token: str = Depends(oauth2_scheme)) -> Dict[str, Any]:
    """
    Authenticate using OAuth2 password bearer flow.
    
    Args:
        token: The OAuth2 token
        
    Returns:
        Dict containing user info
        
    Raises:
        HTTPException: If authentication fails
    """
    try:
        return await verify_token(token)
    except HTTPException as e:
        logger.error(f"OAuth2 authentication failed: {e.detail}")
        raise

def get_secure_headers() -> Dict[str, str]:
    """
    Get recommended security headers for API responses.
    
    Returns:
        Dict of security headers
    """
    return {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Cache-Control": "no-store",
        "Pragma": "no-cache"
    }

async def start_aws_sso_auth_flow(redirect_url: Optional[str] = None) -> Dict[str, Any]:
    """
    Start the AWS SSO authentication flow.
    
    Args:
        redirect_url: Optional URL to redirect to after SSO authentication
        
    Returns:
        Dict with login URL and instructions
    """
    if not AWS_SSO_ENABLED:
        logger.warning("AWS SSO authentication is disabled")
        return {
            "success": False,
            "message": "AWS SSO authentication is disabled",
            "login_url": None
        }
        
    try:
        # Initialize the AWS SSO login process
        result = start_aws_sso_login(redirect_url)
        logger.info("Started AWS SSO authentication flow")
        return result
    except Exception as e:
        logger.error(f"Error starting AWS SSO authentication: {e}")
        return {
            "success": False,
            "message": f"Failed to start AWS SSO authentication: {str(e)}",
            "login_url": AWS_LOGIN_URL
        }

def get_token_expiry_info(expires_at: Union[float, datetime]) -> Dict[str, Any]:
    """
    Get information about token expiry.
    
    Args:
        expires_at: Token expiration timestamp or datetime
        
    Returns:
        Dict with expiry information
    """
    if not expires_at:
        return {
            "expired": True,
            "expires_in_seconds": 0,
            "expires_in_minutes": 0,
            "expires_at_iso": None
        }
        
    # Convert datetime to timestamp if needed
    if isinstance(expires_at, datetime):
        expiration_ts = expires_at.timestamp()
        expiration_dt = expires_at
    else:
        expiration_ts = expires_at
        expiration_dt = datetime.fromtimestamp(expires_at)
        
    # Calculate time until expiry
    now = time.time()
    expires_in_seconds = max(0, int(expiration_ts - now))
    expires_in_minutes = expires_in_seconds // 60
    
    return {
        "expired": now >= expiration_ts,
        "expires_in_seconds": expires_in_seconds,
        "expires_in_minutes": expires_in_minutes,
        "expires_at_iso": expiration_dt.isoformat()
    }
    
def should_refresh_token(expires_at: Union[float, datetime], 
                         refresh_threshold_seconds: int = 300) -> bool:
    """
    Determine if a token should be refreshed based on expiry time.
    
    Args:
        expires_at: Token expiration timestamp or datetime
        refresh_threshold_seconds: Seconds before expiry to refresh (default: 5 minutes)
        
    Returns:
        bool: True if token should be refreshed
    """
    if not expires_at:
        return True
        
    # Convert datetime to timestamp if needed
    if isinstance(expires_at, datetime):
        expiration = expires_at.timestamp()
    else:
        expiration = expires_at
        
    # Check if current time is close to expiration
    return (expiration - time.time()) < refresh_threshold_seconds