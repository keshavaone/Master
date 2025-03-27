
# api/auth/jwt_handler.py
"""
JWT token handling functionality.
This module provides utilities for working with JWT tokens.
"""

import os
import time
import secrets
import logging
import datetime
from typing import Dict, Any, Optional, Tuple, Union

try:
    import jwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False
    logging.getLogger("api.auth.jwt").warning(
        "PyJWT not installed. JWT functionality will be limited."
    )

from api.auth.core import AuthSettings, AuthResult

# Configure logging
logger = logging.getLogger("api.auth.jwt")
logger.setLevel(logging.INFO)

def generate_jwt_secret():
    """
    Generate a secure JWT secret key.
    
    Returns:
        str: A secure random secret key
    """
    return secrets.token_hex(32)

def create_token(
    user_id: str,
    user_data: Dict[str, Any] = None,
    expires_minutes: int = None
) -> Tuple[str, float]:
    """
    Create a new JWT token.
    
    Args:
        user_id: User identifier
        user_data: Additional data to include in the token
        expires_minutes: Token expiration time in minutes
        
    Returns:
        Tuple[str, float]: The token and its expiration timestamp
    """
    if not JWT_AVAILABLE:
        logger.error("PyJWT not available. Cannot create token.")
        return None, None
        
    # Ensure we have a JWT secret
    jwt_secret = AuthSettings.JWT_SECRET
    if not jwt_secret:
        logger.error("JWT_SECRET not configured. Cannot create token.")
        return None, None
    
    # Set expiration time
    expiration_minutes = expires_minutes or AuthSettings.TOKEN_EXPIRE_MINUTES
    now = time.time()
    expires_at = now + (expiration_minutes * 60)
    
    # Create the token payload
    payload = {
        "sub": user_id,  # JWT subject claim (user ID)
        "exp": expires_at,  # Expiration time
        "iat": now,  # Issued at time
        "nbf": now,  # Not valid before time
        "type": "access"  # Token type
    }
    
    # Add additional user data if provided
    if user_data:
        # Filter out any sensitive data
        safe_user_data = {
            k: v for k, v in user_data.items() 
            if not k.lower() in ["password", "secret", "key"]
        }
        payload.update(safe_user_data)
    
    # Create the token
    try:
        token = jwt.encode(
            payload,
            jwt_secret,
            algorithm=AuthSettings.JWT_ALGORITHM
        )
        
        # Handle bytes vs string for different jwt versions
        if isinstance(token, bytes):
            token = token.decode('utf-8')
            
        return token, expires_at
    except Exception as e:
        logger.error(f"Error creating JWT token: {e}")
        return None, None

def verify_token(token: str) -> Tuple[bool, Dict[str, Any]]:
    """
    Verify and decode a JWT token.
    
    Args:
        token: JWT token to verify
        
    Returns:
        Tuple[bool, Dict[str, Any]]: Success flag and decoded payload or None
    """
    if not JWT_AVAILABLE:
        logger.error("PyJWT not available. Cannot verify token.")
        return False, None
        
    # Ensure we have a JWT secret
    jwt_secret = AuthSettings.JWT_SECRET
    if not jwt_secret:
        logger.error("JWT_SECRET not configured. Cannot verify token.")
        return False, None
        
    try:
        # Decode and verify the token
        payload = jwt.decode(
            token,
            jwt_secret,
            algorithms=[AuthSettings.JWT_ALGORITHM]
        )
        
        # Check if the token has expired
        if "exp" in payload and payload["exp"] < time.time():
            logger.warning("Token has expired")
            return False, None
            
        return True, payload
    except jwt.ExpiredSignatureError:
        logger.warning("Token has expired")
        return False, None
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid token: {e}")
        return False, None
    except Exception as e:
        logger.error(f"Unexpected error verifying token: {e}")
        return False, None

def refresh_token(token: str, expires_minutes: int = None) -> AuthResult:
    """
    Refresh a JWT token with a new expiration time.
    
    Args:
        token: Current token to refresh
        expires_minutes: New expiration time in minutes
        
    Returns:
        AuthResult: Result of the refresh operation
    """
    # Verify the current token
    success, payload = verify_token(token)
    if not success or not payload:
        return AuthResult(
            success=False,
            error="Invalid or expired token"
        )
        
    # Get the user ID from the token
    user_id = payload.get("sub")
    if not user_id:
        return AuthResult(
            success=False,
            error="Token missing user ID"
        )
        
    # Create a new token with the existing payload
    new_token, expires_at = create_token(
        user_id=user_id,
        user_data=payload,
        expires_minutes=expires_minutes
    )
    
    if not new_token:
        return AuthResult(
            success=False,
            error="Failed to create new token"
        )
        
    return AuthResult(
        success=True,
        user_id=user_id,
        token=new_token,
        expires_at=expires_at,
        auth_type="jwt"
    )

def authenticate_with_token(token: str) -> AuthResult:
    """
    Authenticate with an existing JWT token.
    
    Args:
        token: JWT token to authenticate with
        
    Returns:
        AuthResult: Result of the authentication
    """
    # Verify the token
    success, payload = verify_token(token)
    if not success or not payload:
        return AuthResult(
            success=False,
            error="Invalid or expired token"
        )
        
    # Get the user ID from the token
    user_id = payload.get("sub")
    if not user_id:
        return AuthResult(
            success=False,
            error="Token missing user ID"
        )
        
    # Get token expiration
    expires_at = payload.get("exp")
    
    return AuthResult(
        success=True,
        user_id=user_id,
        token=token,
        expires_at=expires_at,
        auth_type=payload.get("auth_type", "jwt"),
        user_info=payload
    )