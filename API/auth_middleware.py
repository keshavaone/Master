"""
Authentication middleware for the GUARD API.

This module provides secure authentication validation for API endpoints,
supporting both JWT token-based authentication and AWS SSO tokens.
"""

import os
import time
import json
import logging
from typing import Optional, Dict, Any, Callable
from fastapi import Request, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import boto3
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger("api.auth")
logger.setLevel(logging.INFO)

# Try to import jwt with proper error handling
try:
    import jwt
    # Check if this is PyJWT or another JWT implementation
    has_pyjwt_error = hasattr(jwt, 'PyJWTError')
    # Define the exception to catch based on what's available
    if has_pyjwt_error:
        # Using PyJWT
        jwt_decode_error = jwt.PyJWTError
        logger.info("Using PyJWT library")
    else:
        # Using another JWT implementation
        jwt_decode_error = Exception
        logger.warning("Using alternative JWT library without PyJWTError")
except ImportError:
    # JWT not installed
    logger.error("JWT library not installed. Authentication will fail.")
    jwt = None
    jwt_decode_error = Exception


class AuthSettings:
    """Settings for authentication configuration."""
    JWT_SECRET = os.environ.get("JWT_SECRET", "your-secret-key-should-be-in-env")
    JWT_ALGORITHM = "HS256"
    TOKEN_EXPIRE_MINUTES = 60
    REQUIRE_AUTH = os.environ.get("REQUIRE_AUTH", "true").lower() == "true"
    

class AuthDependency(HTTPBearer):
    """Dependency for handling authentication."""
    def __init__(self, auto_error: bool = True):
        super().__init__(auto_error=auto_error)
        
    async def __call__(self, request: Request) -> Optional[Dict[str, Any]]:
        """
        Process and validate the authentication token.
        
        Args:
            request: The incoming request
            
        Returns:
            Dict containing user information from token
            
        Raises:
            HTTPException: If authentication fails
        """
        if not AuthSettings.REQUIRE_AUTH:
            # Skip auth if disabled (for development only)
            logger.warning("Authentication is disabled. This should not be used in production.")
            return {"sub": "anonymous", "auth_type": "none"}
            
        credentials: HTTPAuthorizationCredentials = await super().__call__(request)
        
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        # Check token type and validate accordingly
        token = credentials.credentials
        user_info = None
        
        if token.startswith("AWS-"):
            # AWS SSO token
            user_info = self._validate_aws_token(token.replace("AWS-", ""))
        else:
            # JWT token
            user_info = self._validate_jwt_token(token)
            
        if not user_info:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token or expired token",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        # Store token info in request state for logging
        request.state.user_id = user_info.get("sub", "unknown")
        request.state.auth_type = user_info.get("auth_type", "unknown")
        
        return user_info
        
    def _validate_jwt_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Validate a JWT token.
        
        Args:
            token: The JWT token
            
        Returns:
            Dict containing user information from token or None if invalid
        """
        try:
            if jwt is None:
                logger.error("JWT library not available")
                return None
                
            payload = jwt.decode(
                token,
                AuthSettings.JWT_SECRET,
                algorithms=[AuthSettings.JWT_ALGORITHM]
            )
            
            # Check token expiration
            if "exp" in payload and payload["exp"] < time.time():
                logger.warning(f"Expired token for user {payload.get('sub', 'unknown')}")
                return None
                
            # Ensure token has required fields
            if "sub" not in payload:
                logger.warning("Token missing 'sub' claim")
                return None
                
            # Add auth type for logging
            payload["auth_type"] = "jwt"
            
            return payload
            
        except jwt_decode_error as e:
            logger.error(f"JWT validation error: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error validating JWT: {str(e)}")
            return None
            
    def _validate_aws_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Validate an AWS SSO token.
        
        Args:
            token: The AWS SSO session token
            
        Returns:
            Dict containing user information or None if invalid
        """
        try:
            # Get AWS credentials from environment - these should be set by the client
            # during the AWS SSO authentication process
            aws_access_key = os.environ.get('AWS_ACCESS_KEY_ID', '')
            aws_secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY', '')
            
            # When running in different processes, the environment variables 
            # might not be shared properly
            if not aws_access_key or not aws_secret_key:
                logger.warning("AWS credentials environment variables not set properly")
                # Try to get credentials from request headers instead
                request = getattr(self, 'request', None)
                if request:
                    aws_access_key = request.headers.get('X-AWS-Access-Key-ID', '')
                    aws_secret_key = request.headers.get('X-AWS-Secret-Access-Key', '')
                    # We already have the token from the Authorization header
            
            # Log available credentials for debugging (mask secrets)
            logger.debug(f"Using AWS Access Key: {aws_access_key[:4]}{'*' * 12 if aws_access_key else ''}")
            logger.debug(f"Has AWS Secret Key: {bool(aws_secret_key)}")
            
            # Create STS client with the token and credentials if available
            if aws_access_key and aws_secret_key:
                # Use both provided credentials and token
                sts = boto3.client(
                    'sts',
                    aws_access_key_id=aws_access_key,
                    aws_secret_access_key=aws_secret_key,
                    aws_session_token=token
                )
            else:
                # Fall back to using only the token (less likely to work)
                sts = boto3.client(
                    'sts',
                    aws_session_token=token
                )
            
            # Check token validity by making a lightweight API call
            response = sts.get_caller_identity()
            
            # Create user info from AWS response
            user_info = {
                "sub": response.get("UserId", "unknown"),
                "arn": response.get("Arn", ""),
                "account": response.get("Account", ""),
                "auth_type": "aws_sso"
            }
            
            logger.info(f"Successfully validated AWS SSO token for user {user_info['sub']}")
            return user_info
            
        except ClientError as e:
            logger.error(f"AWS token validation error: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error validating AWS token: {str(e)}")
            return None


# Create dependency instance for routes
auth_required = AuthDependency()


async def get_current_user(credentials = Depends(auth_required)) -> Dict[str, Any]:
    """
    Dependency that returns the current authenticated user information.
    
    Args:
        credentials: The validated credentials from auth_required
        
    Returns:
        Dict with user information
    """
    return credentials


# Optional auth decorator for routes that should work with or without auth
class OptionalAuthDependency(HTTPBearer):
    """Dependency for optional authentication."""
    def __init__(self):
        super().__init__(auto_error=False)
        
    async def __call__(self, request: Request) -> Optional[Dict[str, Any]]:
        """
        Process authentication if present, but don't require it.
        
        Args:
            request: The incoming request
            
        Returns:
            Dict with user info or None if no auth
        """
        try:
            auth_header = request.headers.get("Authorization")
            if not auth_header:
                return None
                
            if not auth_header.startswith("Bearer "):
                return None
                
            token = auth_header.replace("Bearer ", "")
            
            # Try standard auth dependency
            auth_dep = AuthDependency(auto_error=False)
            return await auth_dep.__call__(request)
            
        except Exception as e:
            logger.debug(f"Optional auth failed: {str(e)}")
            return None


# Create optional auth dependency instance
optional_auth = OptionalAuthDependency()


# Audit logging middleware
async def audit_log_middleware(request: Request, call_next):
    """
    Middleware to log API calls with authentication info.
    
    Args:
        request: The incoming request
        call_next: The next middleware or route handler
        
    Returns:
        Response from the next handler
    """
    start_time = time.time()
    
    # Process the request
    response = await call_next(request)
    
    # Extract user info if available
    user_id = getattr(request.state, "user_id", "anonymous")
    auth_type = getattr(request.state, "auth_type", "none")
    
    # Log the request with auth info
    process_time = time.time() - start_time
    logger.info(
        f"Request: {request.method} {request.url.path} "
        f"| User: {user_id} | Auth: {auth_type} "
        f"| Status: {response.status_code} | Time: {process_time:.3f}s"
    )
    
    # Log to audit trail if modifying endpoints
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        try:
            # Create audit log entry
            client_host = request.client.host if request.client else "unknown"
            
            audit_entry = {
                "timestamp": time.time(),
                "user_id": user_id,
                "auth_type": auth_type,
                "client_ip": client_host,
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code
            }
            
            # Log the audit entry
            logger.info(f"AUDIT: {json.dumps(audit_entry)}")
            
            # In a production system, you might want to save this to a database
            # or send it to a dedicated audit logging system
            
        except Exception as e:
            logger.error(f"Failed to create audit log: {str(e)}")
    
    return response


# Helper function to generate JWT tokens
def create_jwt_token(user_id: str, expires_minutes: int = AuthSettings.TOKEN_EXPIRE_MINUTES) -> str:
    """
    Create a new JWT token for a user.
    
    Args:
        user_id: User identifier to encode in token
        expires_minutes: Token expiration time in minutes
        
    Returns:
        str: Encoded JWT token
    """
    if jwt is None:
        logger.error("JWT library not available")
        return "INVALID_TOKEN_JWT_MISSING"
        
    expires = time.time() + expires_minutes * 60
    
    payload = {
        "sub": user_id,
        "exp": expires,
        "iat": time.time(),
        "type": "access"
    }
    
    try:
        token = jwt.encode(payload, AuthSettings.JWT_SECRET, algorithm=AuthSettings.JWT_ALGORITHM)
        # Handle bytes vs string return value
        if isinstance(token, bytes):
            token = token.decode('utf-8')
        return token
    except Exception as e:
        logger.error(f"Error creating JWT token: {e}")
        return "INVALID_TOKEN_ERROR"