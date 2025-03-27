
# api/controllers/system_controller.py
"""
System controller.

This module provides FastAPI endpoints for system operations.
"""

import os
import logging
from datetime import datetime
from typing import Dict, Any, Counter

from fastapi import APIRouter, Depends, HTTPException, status, Request

from api.auth.middleware import auth_required

# Configure logging
logger = logging.getLogger("api.controllers.system")
logger.setLevel(logging.INFO)

# Create router
router = APIRouter(prefix="/system", tags=["System"])

# Request counter
request_counter = Counter()

@router.get("/health")
async def health_check():
    """
    Check system health.
    
    This endpoint does not require authentication.
    
    Returns:
        Dict: Health check response
    """
    try:
        # Increment counter
        request_counter["health_check"] += 1
        
        # In a real application, you'd check database connectivity, etc.
        return {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "version": os.environ.get("API_VERSION", "1.0.0"),
            "environment": os.environ.get("ENVIRONMENT", "development")
        }
    except Exception as e:
        # Log and return error
        logger.error(f"Health check failed: {e}")
        return {
            "status": "unhealthy",
            "timestamp": datetime.now().isoformat(),
            "error": str(e)
        }

@router.get("/info")
async def system_info(
    request: Request,
    user_info: Dict[str, Any] = Depends(auth_required)
):
    """
    Get system information (admin only).
    
    Args:
        request: FastAPI request object
        user_info: User information from auth middleware
        
    Returns:
        Dict: System information
    """
    # Check if user is admin
    if user_info.get("sub") != "admin" and not user_info.get("arn", "").endswith("/Admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required for this endpoint"
        )
    
    # Increment counter
    request_counter["system_info"] += 1
    
    # Return system information
    return {
        "api_version": os.environ.get("API_VERSION", "1.0.0"),
        "environment": os.environ.get("ENVIRONMENT", "development"),
        "aws_region": os.environ.get("AWS_REGION"),
        "request_count": dict(request_counter),
        "dynamo_table": os.environ.get("DYNAMODB_TABLE_NAME",""),
        "auth_mode": "JWT and AWS SSO"
    }

