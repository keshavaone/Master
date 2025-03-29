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
from typing import Dict, Any, Optional, Tuple, Union, List, Set

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

# Token blacklist data structures
# In-memory token blacklist - JTI based
_token_blacklist = set()
# User-to-token mapping - to track all tokens for a user
_user_tokens = {}


def generate_jwt_secret():
    """
    Generate a secure JWT secret key.

    Returns:
        str: A secure random secret key
    """
    return secrets.token_hex(32)


def _validate_jwt_configuration() -> bool:
    """
    Validate that JWT is properly configured.

    Returns:
        bool: True if JWT is properly configured
    """
    if not JWT_AVAILABLE:
        logger.error("PyJWT not available. Cannot use JWT functionality.")
        return False

    # Ensure we have a JWT secret
    jwt_secret = AuthSettings.JWT_SECRET
    if not jwt_secret:
        logger.error("JWT_SECRET not configured. Cannot create token.")
        return False

    return True


def create_access_token(
    user_id: str,
    user_data: Dict[str, Any] = None,
    expires_minutes: int = None
) -> Tuple[Optional[str], Optional[float]]:
    """
    Create a new JWT access token.

    Args:
        user_id: User identifier
        user_data: Additional data to include in the token
        expires_minutes: Token expiration time in minutes (shorter for access tokens)

    Returns:
        Tuple[str, float]: The token and its expiration timestamp, or (None, None) if creation fails
    """
    if not _validate_jwt_configuration():
        return None, None

    # Set a shorter expiration time for access tokens
    # Default to 15 minutes
    expiration_minutes = expires_minutes or AuthSettings.TOKEN_EXPIRE_MINUTES or 15

    # Create the token payload
    now = time.time()
    expires_at = now + (expiration_minutes * 60)
    
    # Generate a unique token ID
    jti = secrets.token_hex(8)

    payload = {
        "sub": user_id,                  # JWT subject claim (user ID)
        "exp": expires_at,               # Expiration time
        "iat": now,                      # Issued at time
        "nbf": now,                      # Not valid before time
        "type": "access",                # Token type
        "jti": jti                       # Unique token ID
    }

    # Add additional user data if provided
    if user_data:
        # Filter out any sensitive or reserved claims
        safe_user_data = {
            k: v for k, v in user_data.items()
            if not k.lower() in ["password", "secret", "key", "exp", "iat", "nbf", "type", "jti"]
        }
        payload.update(safe_user_data)

    # Create the token
    try:
        token = jwt.encode(
            payload,
            AuthSettings.JWT_SECRET,
            algorithm=AuthSettings.JWT_ALGORITHM
        )

        # Handle bytes vs string for different jwt versions
        if isinstance(token, bytes):
            token = token.decode('utf-8')

        # Track the token for this user
        _track_user_token(user_id, jti, expires_at)

        logger.info(
            f"Created access token for user {user_id} (expires in {expiration_minutes} minutes)")
        return token, expires_at
    except Exception as e:
        logger.error(f"Error creating access token: {e}")
        return None, None


def create_refresh_token(
    user_id: str,
    token_id: str = None,
    expires_days: int = 7
) -> Tuple[Optional[str], Optional[float]]:
    """
    Create a new JWT refresh token.

    Args:
        user_id: User identifier
        token_id: Optional existing token ID for tracking
        expires_days: Token expiration time in days (longer for refresh tokens)

    Returns:
        Tuple[str, float]: The refresh token and its expiration timestamp, or (None, None) if creation fails
    """
    if not _validate_jwt_configuration():
        return None, None

    # Set a longer expiration time for refresh tokens
    expiration_seconds = expires_days * 24 * 60 * 60  # Convert days to seconds
    now = time.time()
    expires_at = now + expiration_seconds

    # Create a unique token ID if not provided
    jti = token_id or secrets.token_hex(16)

    # Create the token payload (minimal for security)
    payload = {
        "sub": user_id,          # JWT subject claim (user ID)
        "exp": expires_at,       # Expiration time
        "iat": now,              # Issued at time
        "nbf": now,              # Not valid before time
        "type": "refresh",       # Token type
        "jti": jti               # Unique token ID
    }

    # Create the token
    try:
        token = jwt.encode(
            payload,
            AuthSettings.JWT_SECRET,
            algorithm=AuthSettings.JWT_ALGORITHM
        )

        # Handle bytes vs string for different jwt versions
        if isinstance(token, bytes):
            token = token.decode('utf-8')

        # Track the token for this user
        _track_user_token(user_id, jti, expires_at)

        logger.info(
            f"Created refresh token for user {user_id} (expires in {expires_days} days)")
        return token, expires_at
    except Exception as e:
        logger.error(f"Error creating refresh token: {e}")
        return None, None


def verify_token(token: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """
    Verify and decode a JWT token.

    Args:
        token: JWT token to verify

    Returns:
        Tuple[bool, Dict[str, Any]]: Success flag and decoded payload or (False, None) if verification fails
    """
    if not _validate_jwt_configuration():
        return False, None

    try:
        # Check if token is blacklisted
        try:
            decoded = jwt.decode(
                token,
                options={"verify_signature": False}
            )
            token_jti = decoded.get("jti")
            if token_jti and token_jti in _token_blacklist:
                logger.warning(f"Token with JTI {token_jti} is blacklisted")
                return False, None
        except Exception:
            # If we can't decode without verification, continue to regular verification
            pass

        # Decode and verify the token
        payload = jwt.decode(
            token,
            AuthSettings.JWT_SECRET,
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


def refresh_with_token(refresh_token: str, rotate: bool = True) -> AuthResult:
    """
    Use a refresh token to get a new access token.

    Args:
        refresh_token: The refresh token
        rotate: Whether to rotate the refresh token (issue a new one)

    Returns:
        AuthResult: Result containing new access token and optionally a new refresh token
    """
    # Verify the refresh token
    success, payload = verify_token(refresh_token)
    if not success or not payload:
        logger.error("Refresh token verification failed")
        return AuthResult(
            success=False,
            error="Invalid or expired refresh token"
        )

    # Verify this is actually a refresh token
    if payload.get("type") != "refresh":
        logger.error("Token is not a refresh token")
        return AuthResult(
            success=False,
            error="Not a valid refresh token"
        )

    # Get the user ID from the token
    user_id = payload.get("sub")
    if not user_id:
        logger.error("Refresh token missing user ID")
        return AuthResult(
            success=False,
            error="Token missing user ID"
        )
 
    # Get the token ID for tracking
    jti = payload.get("jti")

    # Create a new access token
    access_token, access_expires = create_access_token(
        user_id=user_id,
        user_data={"refresh_jti": jti}
    )

    if not access_token:
        logger.error("Failed to create new access token")
        return AuthResult(
            success=False,
            error="Failed to create new access token"
        )

    result = AuthResult(
        success=True,
        user_id=user_id,
        token=access_token,
        expires_at=access_expires,
        auth_type="jwt"
    )

    # Optionally rotate the refresh token
    if rotate:
        # Add the current refresh token to the blacklist
        if jti:
            blacklist_token_jti(jti)

        # Create a new refresh token
        new_refresh_token, refresh_expires = create_refresh_token(
            user_id=user_id
        )

        if new_refresh_token:
            result.refresh_token = new_refresh_token
            result.refresh_expires_at = refresh_expires
        else:
            logger.warning("Failed to rotate refresh token")

    logger.info(f"Successfully refreshed tokens for user {user_id}")
    return result


def authenticate_with_credentials(user_id: str, additional_data: Dict[str, Any] = None) -> AuthResult:
    """
    Authenticate a user with their credentials and issue tokens.

    Args:
        user_id: User identifier
        additional_data: Additional data to include in the access token

    Returns:
        AuthResult: Authentication result with tokens
    """
    # Create an access token
    access_token, access_expires = create_access_token(
        user_id=user_id,
        user_data=additional_data
    )

    if not access_token:
        return AuthResult(
            success=False,
            error="Failed to create access token"
        )

    # Create a refresh token
    refresh_token, refresh_expires = create_refresh_token(
        user_id=user_id
    )

    if not refresh_token:
        return AuthResult(
            success=False,
            error="Failed to create refresh token"
        )

    # Return both tokens
    return AuthResult(
        success=True,
        user_id=user_id,
        token=access_token,
        expires_at=access_expires,
        refresh_token=refresh_token,
        refresh_expires_at=refresh_expires,
        auth_type="jwt",
        user_info=additional_data
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

    # Get token type
    token_type = payload.get("type", "access")
    if token_type != "access":
        return AuthResult(
            success=False,
            error=f"Token of type '{token_type}' cannot be used for authentication"
        )

    # Get token expiration
    expires_at = payload.get("exp")

    return AuthResult(
        success=True,
        user_id=user_id,
        token=token,
        expires_at=expires_at,
        auth_type="jwt",
        user_info=payload
    )


def _track_user_token(user_id: str, jti: str, expires_at: float) -> None:
    """
    Track a token for a specific user.

    Args:
        user_id: User ID
        jti: JWT ID
        expires_at: Token expiration timestamp
    """
    if not user_id or not jti:
        return
    
    # Initialize user tokens set if it doesn't exist
    if user_id not in _user_tokens:
        _user_tokens[user_id] = set()
    
    # Add this token's JTI to the user's tokens
    _user_tokens[user_id].add(jti)
    
    # Auto-cleanup: We could periodically clean up expired tokens
    # but for simplicity, we'll leave that for future enhancement


def blacklist_token_jti(jti: str) -> bool:
    """
    Add a token ID to the blacklist.

    Args:
        jti: Token ID to blacklist

    Returns:
        bool: True if successful
    """
    if not jti:
        return False

    _token_blacklist.add(jti)
    logger.info(f"Token with JTI {jti} added to blacklist")
    return True


def blacklist_token(token: str) -> bool:
    """
    Blacklist a token to prevent its future use.

    Args:
        token: Token to blacklist

    Returns:
        bool: True if successful
    """
    try:
        # Decode the token without verification to get the JTI
        decoded = jwt.decode(
            token,
            options={"verify_signature": False}
        )

        # Get the token ID
        jti = decoded.get("jti")
        if not jti:
            logger.warning("Token has no JTI, cannot blacklist")
            return False

        # Add the token ID to the blacklist
        _token_blacklist.add(jti)
        logger.info(f"Token with JTI {jti} added to blacklist")
        return True
    except Exception as e:
        logger.error(f"Error blacklisting token: {e}")
        return False


def blacklist_all_user_tokens(user_id: str) -> int:
    """
    Blacklist all tokens for a specific user.

    Args:
        user_id: User ID to blacklist tokens for

    Returns:
        int: Number of tokens blacklisted
    """
    if not user_id or user_id not in _user_tokens:
        logger.warning(f"No tokens found for user {user_id}")
        return 0
    
    # Get all tokens for this user
    user_token_jtis = _user_tokens.get(user_id, set())
    
    # Add all tokens to the blacklist
    count = 0
    for jti in user_token_jtis:
        _token_blacklist.add(jti)
        count += 1
    
    # Clear the user's token set
    _user_tokens[user_id] = set()
    
    logger.info(f"Blacklisted {count} tokens for user {user_id}")
    return count


def extract_user_id_from_token(token: str) -> Optional[str]:
    """
    Extract the user ID from a token.

    Args:
        token: Token to extract user ID from

    Returns:
        Optional[str]: User ID or None if the token is invalid
    """
    try:
        # Decode the token without verification to get the user ID
        decoded = jwt.decode(
            token,
            options={"verify_signature": False}
        )
        
        # Return the user ID
        return decoded.get("sub")
    except Exception:
        return None


def clear_blacklist() -> int:
    """
    Clear the token blacklist.

    Returns:
        int: Number of tokens cleared
    """
    count = len(_token_blacklist)
    _token_blacklist.clear()
    _user_tokens.clear()
    logger.info(f"Cleared {count} tokens from blacklist and user token tracking")
    return count


def is_token_blacklisted(token: str) -> bool:
    """
    Check if a token is blacklisted.

    Args:
        token: Token to check

    Returns:
        bool: True if blacklisted
    """
    try:
        # Decode the token without verification to get the JTI
        decoded = jwt.decode(
            token,
            options={"verify_signature": False}
        )

        # Get the token ID
        jti = decoded.get("jti")
        if not jti:
            return False

        # Check if the token ID is in the blacklist
        return jti in _token_blacklist
    except Exception:
        return False


# For backward compatibility (legacy function)
def refresh_token(token: str, expires_minutes: int = None) -> AuthResult:
    """
    Legacy function to refresh a JWT token with a new expiration time.

    This function is maintained for backward compatibility.
    New code should use refresh_with_token() instead.

    Args:
        token: Current token to refresh
        expires_minutes: New expiration time in minutes

    Returns:
        AuthResult: Result of the refresh operation
    """
    logger.warning(
        "Using legacy refresh_token() function. Consider upgrading to refresh_with_token()")

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

    # Create a modified payload for the new token
    # Remove dynamic fields that should be regenerated
    new_payload = {k: v for k, v in payload.items(
    ) if k not in ('exp', 'iat', 'nbf')}

    # Add refresh timestamp to ensure token uniqueness
    new_payload['refresh_timestamp'] = time.time()

    # Create a new token with the modified payload
    new_token, expires_at = create_access_token(
        user_id=user_id,
        user_data=new_payload,
        expires_minutes=expires_minutes
    )

    if not new_token:
        return AuthResult(
            success=False,
            error="Failed to create new token"
        )

    # Verify the tokens are different
    if new_token == token:
        logger.warning(
            "New token matches old token - indicates potential issue with token generation")

    return AuthResult(
        success=True,
        user_id=user_id,
        token=new_token,
        expires_at=expires_at,
        auth_type=payload.get("auth_type", "jwt")
    )


# For backward compatibility (legacy function)
def create_token(
    user_id: str,
    user_data: Dict[str, Any] = None,
    expires_minutes: int = None
) -> Tuple[Optional[str], Optional[float]]:
    """
    Legacy function to create a token.

    This function is maintained for backward compatibility.
    New code should use create_access_token() or create_refresh_token() instead.

    Args:
        user_id: User identifier
        user_data: Additional data to include in the token
        expires_minutes: Token expiration time in minutes

    Returns:
        Tuple[str, float]: The token and its expiration timestamp
    """
    logger.warning(
        "Using legacy create_token() function. Consider upgrading to create_access_token()")
    return create_access_token(user_id, user_data, expires_minutes)