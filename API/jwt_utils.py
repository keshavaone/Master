"""
JWT utilities for GUARD application.

This module handles JWT token generation, validation, and management.
"""

import os
import datetime
import logging
import secrets
import jwt
from typing import Dict, Any, Optional, Tuple

# Configure logging
logger = logging.getLogger("jwt.utils")
logger.setLevel(logging.INFO)

# Default values - will be overridden by environment variables
DEFAULT_SECRET = None
DEFAULT_ALGORITHM = "HS256"
DEFAULT_EXPIRE_MINUTES = 60

class JWTManager:
    """Manager for JWT token operations."""
    
    def __init__(self, secret_key=None, algorithm=None, token_expire_minutes=None):
        """
        Initialize the JWT Manager.
        
        Args:
            secret_key: JWT signing secret (defaults to env var AUTH_JWT_SECRET)
            algorithm: JWT algorithm (defaults to HS256)
            token_expire_minutes: Token expiration in minutes (defaults to 60)
        """
        # Set up the JWT parameters
        self.secret_key = secret_key or os.environ.get("AUTH_JWT_SECRET", DEFAULT_SECRET)
        self.algorithm = algorithm or os.environ.get("AUTH_JWT_ALGORITHM", DEFAULT_ALGORITHM)
        
        # Convert expire_minutes to int with fallbacks
        try:
            env_expire = os.environ.get("AUTH_TOKEN_EXPIRE_MINUTES")
            self.token_expire_minutes = token_expire_minutes or (
                int(env_expire) if env_expire else DEFAULT_EXPIRE_MINUTES
            )
        except (TypeError, ValueError):
            self.token_expire_minutes = DEFAULT_EXPIRE_MINUTES
            
        # Validate configuration
        self._validate_config()
        
    def _validate_config(self):
        """Validate the JWT configuration."""
        if not self.secret_key:
            # If no secret is provided, generate one for this session
            # NOTE: This should only happen in development and is not secure for production
            logger.warning(
                "No JWT secret key provided! Generating a random one for this session. "
                "This is not secure for production use."
            )
            self.secret_key = secrets.token_hex(32)
            
        if self.token_expire_minutes <= 0:
            logger.warning("Invalid token expiration! Defaulting to 60 minutes.")
            self.token_expire_minutes = 60
            
    def create_token(self, data: Dict[str, Any], expires_minutes: Optional[int] = None) -> str:
        """
        Create a new JWT token.
        
        Args:
            data: Data to encode in the token
            expires_minutes: Override token expiration in minutes
            
        Returns:
            str: Encoded JWT token
        """
        expiration = expires_minutes or self.token_expire_minutes
        
        # Create a copy of the data to avoid modifying the original
        payload = data.copy()
        
        # Add standard claims
        now = datetime.datetime.utcnow()
        payload.update({
            "exp": now + datetime.timedelta(minutes=expiration),
            "iat": now,
            "nbf": now,  # Not valid before current time
        })
        
        # Encode and return the token
        token = jwt.encode(
            payload, 
            self.secret_key, 
            algorithm=self.algorithm
        )
        
        return token
        
    def verify_token(self, token: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Verify and decode a JWT token.
        
        Args:
            token: JWT token to verify
            
        Returns:
            Tuple[bool, Optional[Dict]]: Success flag and decoded payload or None
        """
        try:
            payload = jwt.decode(
                token, 
                self.secret_key, 
                algorithms=[self.algorithm]
            )
            return True, payload
        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
            return False, None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {str(e)}")
            return False, None
        except Exception as e:
            logger.error(f"Unexpected error verifying token: {str(e)}")
            return False, None
            
    def refresh_token(self, token: str, expires_minutes: Optional[int] = None) -> Tuple[bool, Optional[str]]:
        """
        Refresh a JWT token with a new expiration time.
        
        Args:
            token: Current token to refresh
            expires_minutes: New expiration time in minutes
            
        Returns:
            Tuple[bool, Optional[str]]: Success flag and new token or None
        """
        # First verify the token
        success, payload = self.verify_token(token)
        if not success or not payload:
            return False, None
            
        # Remove standard JWT claims that will be re-added
        for claim in ['exp', 'iat', 'nbf']:
            if claim in payload:
                del payload[claim]
                
        # Create a new token with the existing payload
        new_token = self.create_token(payload, expires_minutes)
        return True, new_token

    def generate_secret_key():
        """
        Generate a secure random secret key for JWT signing.
        
        Returns:
            str: A secure random key
        """
        return secrets.token_hex(32)


# Create a singleton instance for easy import
jwt_manager = JWTManager()


def create_user_token(user_id: str, user_data: Dict[str, Any] = None, expires_minutes: int = None) -> str:
    """
    Create a JWT token for a user.
    
    Args:
        user_id: User identifier
        user_data: Additional user data to include in token
        expires_minutes: Token expiration in minutes
        
    Returns:
        str: JWT token
    """
    # Create the token payload
    payload = {
        "sub": user_id,  # JWT subject claim (user ID)
        "type": "access"
    }
    
    # Add additional user data if provided
    if user_data:
        payload.update(user_data)
        
    # Create and return the token
    return jwt_manager.create_token(payload, expires_minutes)


def verify_user_token(token: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """
    Verify a user JWT token.
    
    Args:
        token: JWT token to verify
        
    Returns:
        Tuple[bool, Dict]: Success flag and payload or None
    """
    return jwt_manager.verify_token(token)