# api/auth/blacklist_handler.py
"""
Token blacklist handling functionality.
This module provides utilities for managing token blacklists.
"""

import time
import logging
from typing import Dict, Any, Set, Optional
import threading
from datetime import datetime, timedelta

try:
    import jwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False
    logging.getLogger("api.auth.blacklist").warning(
        "PyJWT not installed. Blacklist functionality will be limited."
    )

# Configure logging
logger = logging.getLogger("api.auth.blacklist")
logger.setLevel(logging.INFO)

class TokenBlacklist:
    """
    Thread-safe token blacklist manager with expiration cleanup.
    """
    
    def __init__(self, cleanup_interval: int = 3600):
        """
        Initialize the token blacklist.
        
        Args:
            cleanup_interval: Interval in seconds for cleaning up expired tokens
        """
        # Structure: {jti: expiration_timestamp}
        self._blacklist = {}
        self._lock = threading.RLock()
        self._cleanup_interval = cleanup_interval
        self._last_cleanup = time.time()
        
        logger.info("Token blacklist initialized")
    
    def add(self, jti: str, expiration: Optional[float] = None) -> bool:
        """
        Add a token ID to the blacklist.
        
        Args:
            jti: Token ID to blacklist
            expiration: Optional expiration timestamp for automatic cleanup
            
        Returns:
            bool: True if successful
        """
        if not jti:
            return False
            
        with self._lock:
            # If no expiration provided, default to 30 days from now
            if expiration is None:
                expiration = time.time() + (30 * 24 * 60 * 60)
                
            self._blacklist[jti] = expiration
            logger.info(f"Token with JTI {jti} added to blacklist (expires: {datetime.fromtimestamp(expiration).isoformat()})")
            
            # Perform cleanup if needed
            self._maybe_cleanup()
            
            return True
    
    def check(self, jti: str) -> bool:
        """
        Check if a token ID is blacklisted.
        
        Args:
            jti: Token ID to check
            
        Returns:
            bool: True if blacklisted
        """
        if not jti:
            return False
            
        with self._lock:
            # Perform cleanup if needed
            self._maybe_cleanup()
            
            # Check if token is in blacklist
            return jti in self._blacklist
    
    def remove(self, jti: str) -> bool:
        """
        Remove a token ID from the blacklist.
        
        Args:
            jti: Token ID to remove
            
        Returns:
            bool: True if successful
        """
        if not jti:
            return False
            
        with self._lock:
            if jti in self._blacklist:
                del self._blacklist[jti]
                logger.info(f"Token with JTI {jti} removed from blacklist")
                return True
                
            return False
    
    def clear(self) -> int:
        """
        Clear the token blacklist.
        
        Returns:
            int: Number of tokens cleared
        """
        with self._lock:
            count = len(self._blacklist)
            self._blacklist.clear()
            logger.info(f"Cleared {count} tokens from blacklist")
            return count
    
    def size(self) -> int:
        """
        Get the size of the blacklist.
        
        Returns:
            int: Number of tokens in the blacklist
        """
        with self._lock:
            return len(self._blacklist)
    
    def _maybe_cleanup(self) -> None:
        """
        Clean up expired tokens if cleanup interval has passed.
        """
        current_time = time.time()
        
        # Check if cleanup interval has passed
        if current_time - self._last_cleanup < self._cleanup_interval:
            return
            
        # Update last cleanup time
        self._last_cleanup = current_time
        
        # Find expired tokens
        expired_jtis = [
            jti for jti, expires_at in self._blacklist.items()
            if expires_at < current_time
        ]
        
        # Remove expired tokens
        for jti in expired_jtis:
            del self._blacklist[jti]
            
        if expired_jtis:
            logger.info(f"Cleaned up {len(expired_jtis)} expired tokens from blacklist")


def extract_jti_from_token(token: str) -> Optional[str]:
    """
    Extract the JTI from a JWT token without verifying the signature.
    
    Args:
        token: JWT token
        
    Returns:
        str: Token JTI or None if extraction fails
    """
    if not JWT_AVAILABLE or not token:
        return None
        
    try:
        # Decode the token without verification to get the JTI
        decoded = jwt.decode(
            token,
            options={"verify_signature": False}
        )
        
        # Return the JTI if present
        return decoded.get("jti")
    except Exception as e:
        logger.warning(f"Error extracting JTI from token: {e}")
        return None

# Create a global instance of the token blacklist
token_blacklist = TokenBlacklist()