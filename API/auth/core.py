# api/auth/core.py
"""
Core authentication functionality.
This module provides the foundation for the authentication system.
"""

import os
import time
import logging
import datetime
from typing import Dict, Any, Optional, Tuple, Union

# Configure logging
logger = logging.getLogger("api.auth.core")
logger.setLevel(logging.INFO)

class AuthSettings:
    """Configuration settings for authentication."""
    JWT_SECRET = os.environ.get("AUTH_JWT_SECRET")
    JWT_ALGORITHM = os.environ.get("AUTH_JWT_ALGORITHM", "HS256")
    TOKEN_EXPIRE_MINUTES = int(os.environ.get("AUTH_TOKEN_EXPIRE_MINUTES", "60"))
    REQUIRE_AUTH = os.environ.get("REQUIRE_AUTH", "true").lower() == "true"
    
    # AWS SSO settings
    AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
    BYPASS_AWS_SDK_VALIDATION = os.environ.get("BYPASS_AWS_SDK_VALIDATION", "false").lower() == "true"
    
    @classmethod
    def validate_settings(cls) -> bool:
        """
        Validate that required settings are configured.
        
        Returns:
            bool: True if all required settings are present
        """
        if not cls.JWT_SECRET and not cls.BYPASS_AWS_SDK_VALIDATION:
            logger.warning("JWT_SECRET environment variable not set!")
            # In production, this should fail, but we'll allow it for development
            if os.environ.get("ENVIRONMENT", "development") == "production":
                return False
        
        return True
class AuthResult:
    """
    Class representing the result of an authentication operation.
    """
    def __init__(
        self, 
        success: bool = False, 
        user_id: str = None,
        token: str = None,
        expires_at: float = None,
        refresh_token: str = None,
        refresh_expires_at: float = None,
        error: str = None,
        auth_type: str = None,
        user_info: Dict[str, Any] = None
    ):
        self.success = success
        self.user_id = user_id
        self.token = token
        self.expires_at = expires_at
        self.refresh_token = refresh_token
        self.refresh_expires_at = refresh_expires_at
        self.error = error
        self.auth_type = auth_type
        self.user_info = user_info or {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        result = {
            "success": self.success,
            "user_id": self.user_id,
            "auth_type": self.auth_type
        }
        
        if self.token:
            # Calculate expires_in for client (in seconds)
            expires_in = int(self.expires_at - time.time()) if self.expires_at else None
            
            result.update({
                "access_token": self.token,
                "token_type": "bearer",
                "expires_in": expires_in
            })
        
        if self.refresh_token:
            # Calculate refresh_expires_in for client (in seconds)
            refresh_expires_in = int(self.refresh_expires_at - time.time()) if self.refresh_expires_at else None
            
            result.update({
                "refresh_token": self.refresh_token,
                "refresh_expires_in": refresh_expires_in
            })
        
        if self.error:
            result["error"] = self.error
            
        # Add additional user info but exclude sensitive data
        if self.user_info:
            for key, value in self.user_info.items():
                if key not in result and not key.lower() in ["password", "secret", "key"]:
                    result[key] = value
                    
        return result    

def get_auth_headers(token: str, auth_type: str = None) -> Dict[str, str]:
    """
    Get authentication headers for API requests.
    
    Args:
        token (str): Authentication token
        auth_type (str, optional): Authentication type
        
    Returns:
        Dict[str, str]: Headers for authentication
    """
    if not token:
        return {}
        
    # Add prefix for AWS SSO tokens
    prefix = "AWS-" if auth_type == "aws_sso" else ""
    return {"Authorization": f"Bearer {prefix}{token}"}

def is_token_expired(expires_at: Union[float, datetime.datetime]) -> bool:
    """
    Check if a token is expired.
    
    Args:
        expires_at: Expiration timestamp or datetime
        
    Returns:
        bool: True if token is expired
    """
    if not expires_at:
        return True
        
    # Convert datetime to timestamp if needed
    if isinstance(expires_at, datetime.datetime):
        expiration = expires_at.timestamp()
    else:
        expiration = expires_at
        
    # Check if current time is past expiration
    return time.time() >= expiration

# Placeholder for initialization - to be called at application startup
def init_auth_system():
    """Initialize the authentication system."""
    if not AuthSettings.validate_settings():
        logger.error("Authentication system initialization failed: Invalid settings")
        # In a real application, we might want to exit here in production
        # but for development we'll just log a warning
        if os.environ.get("ENVIRONMENT", "development") == "production":
            raise ValueError("Authentication system initialization failed: Invalid settings")
    else:
        logger.info("Authentication system initialized successfully")
