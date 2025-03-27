
# api/auth/__init__.py
"""
Authentication module for the API.
This module provides authentication functionality for the API.
"""

from api.auth.core import AuthSettings, AuthResult, init_auth_system
from api.auth.jwt_handler import create_token, verify_token, refresh_token
from api.auth.aws_sso import authenticate_with_aws_credentials
from api.auth.middleware import auth_required
from api.auth.endpoints import router as auth_router

__all__ = [
    "AuthSettings",
    "AuthResult",
    "init_auth_system",
    "create_token",
    "verify_token",
    "refresh_token",
    "authenticate_with_aws_credentials",
    "auth_required",
    "auth_router"
]