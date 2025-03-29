# api/auth/__init__.py
"""
Authentication module for the API.
This module provides authentication functionality for the API.
"""

from api.auth.core import AuthSettings, AuthResult, init_auth_system
from api.auth.jwt_handler import (
    create_token, verify_token, refresh_token,
    create_access_token, create_refresh_token, 
    refresh_with_token, blacklist_token, is_token_blacklisted
)
from api.auth.blacklist_handler import token_blacklist, extract_jti_from_token
from api.auth.aws_sso import authenticate_with_aws_credentials
from api.auth.middleware import auth_required
from api.auth.endpoints import router as auth_router

__all__ = [
    # Core
    "AuthSettings",
    "AuthResult",
    "init_auth_system",
    
    # JWT Handlers
    "create_token",
    "verify_token",
    "refresh_token",
    "create_access_token", 
    "create_refresh_token",
    "refresh_with_token",
    "blacklist_token",
    "is_token_blacklisted",
    
    # Blacklist
    "token_blacklist",
    "extract_jti_from_token",
    
    # AWS SSO
    "authenticate_with_aws_credentials",
    
    # Middleware and Endpoints
    "auth_required",
    "auth_router"
]