# api/controllers/activity_controller.py
"""
Activity log controller for the GUARD application.

This module provides FastAPI endpoints for retrieving activity logs and system statistics.
"""

import logging
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from pydantic import BaseModel, Field
from datetime import datetime, timedelta

from api.auth.middleware import auth_required

# Configure logging
logger = logging.getLogger("api.controllers.activity")
logger.setLevel(logging.INFO)

# Create router
router = APIRouter(prefix="/system", tags=["System"])

# Activity log entry model
class ActivityLogEntry(BaseModel):
    """Activity log entry for the UI."""
    id: str
    type: str
    message: str
    timestamp: str
    icon: str
    color: str
    user_id: Optional[str] = None

@router.get("/activity", response_model=List[ActivityLogEntry])
async def get_activity_log(
    request: Request,
    limit: int = Query(50, ge=1, le=100, description="Maximum number of entries to return"),
    page: int = Query(1, ge=1, description="Page number"),
    user_id: Optional[str] = Query(None, description="Filter by user ID"),
    type: Optional[str] = Query(None, description="Filter by event type"),
    user_info: Dict[str, Any] = Depends(auth_required)
):
    """
    Get activity log entries.
    
    This endpoint supports the React dashboard's activity log display.
    """
    try:
        # Get client IP for audit logging
        client_ip = request.client.host if request.client else "unknown"
        
        # Log the request
        logger.info(f"Getting activity log for user: {user_info.get('sub')} from {client_ip}")
        
        # In a real implementation, you would fetch from a database
        # Here we'll generate synthetic activity for demonstration
        
        # Check if the user has administrative privileges
        is_admin = user_info.get("role") == "Administrator" or "admin" in user_info.get("sub", "")
        
        if not is_admin:
            # Regular users can only see their own activity
            logger.info(f"Non-admin user {user_info.get('sub')} limited to own activity")
            if user_id and user_id != user_info.get("sub"):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="You can only view your own activity"
                )
            # Force user_id filter to current user
            user_id = user_info.get("sub")
        
        # Generate synthetic activity (this would be a database query in production)
        all_activities = generate_synthetic_activity(user_info.get("sub"))
        
        # Apply filters
        filtered_activities = all_activities
        
        if user_id:
            filtered_activities = [a for a in filtered_activities if a.user_id == user_id]
            
        if type:
            filtered_activities = [a for a in filtered_activities if a.type == type]
        
        # Count total items after filtering
        total_items = len(filtered_activities)
        
        # Apply pagination
        start_idx = (page - 1) * limit
        end_idx = start_idx + limit
        paginated_activities = filtered_activities[start_idx:end_idx]
        
        # Create pagination metadata
        pagination = {
            "page": page,
            "limit": limit,
            "total": total_items,
            "pages": (total_items + limit - 1) // limit
        }
        
        # Add pagination headers
        request.state.pagination = pagination
        
        return paginated_activities
            
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        # Log and convert other exceptions to HTTP exceptions
        logger.error(f"Error getting activity log: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail="Internal server error"
        )

@router.get("/stats", response_model=Dict[str, Any])
async def get_system_stats(
    request: Request,
    user_info: Dict[str, Any] = Depends(auth_required)
):
    """
    Get system statistics for the dashboard.
    
    This endpoint supports the React dashboard's statistics display.
    """
    try:
        # Get client IP for audit logging
        client_ip = request.client.host if request.client else "unknown"
        
        # Log the request
        logger.info(f"Getting system stats for user: {user_info.get('sub')} from {client_ip}")
        
        # In a real implementation, you would calculate these from database
        # Here we'll generate synthetic statistics for demonstration
        
        # Generate statistics
        from random import randint
        
        # Get current user ID
        user_id = user_info.get("sub")
        
        # Stats for current user (would be from database in production)
        stats = {
            "totalItems": randint(40, 60),
            "categories": randint(4, 6),
            "securityLevel": "High",
            "lastAccess": "2h ago",
            "growthRate": randint(8, 15),
            "newCategories": randint(1, 3),
            "activity": {
                "viewCount": randint(15, 30),
                "editCount": randint(5, 15),
                "addCount": randint(2, 8),
                "deleteCount": randint(0, 3)
            },
            "securityMetrics": {
                "encryptionStrength": "AES-256",
                "accessControlEnabled": True,
                "mfaEnabled": True,
                "lastSecurityScan": "1 day ago"
            }
        }
        
        return stats
            
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        # Log and convert other exceptions to HTTP exceptions
        logger.error(f"Error getting system stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail="Internal server error"
        )

# Helper function to generate synthetic activity for demonstration
def generate_synthetic_activity(current_user_id: str) -> List[ActivityLogEntry]:
    """
    Generate synthetic activity log entries for demonstration.
    
    In a production environment, this would be replaced with database queries.
    """
    # Set up sample data
    activities = []
    now = datetime.now()
    
    # Data view activities
    activities.append(ActivityLogEntry(
        id="act-001",
        type="VIEW",
        message="Viewed Bank Account data",
        timestamp=(now - timedelta(hours=2)).isoformat(),
        icon="eye",
        color="#3B82F6",  # Blue
        user_id=current_user_id
    ))
    
    activities.append(ActivityLogEntry(
        id="act-002",
        type="CREATE",
        message="Added new Credit Card entry",
        timestamp=(now - timedelta(hours=5)).isoformat(),
        icon="plus",
        color="#10B981",  # Green
        user_id=current_user_id
    ))
    
    activities.append(ActivityLogEntry(
        id="act-003",
        type="UPDATE",
        message="Updated Home Address information",
        timestamp=(now - timedelta(days=1)).isoformat(),
        icon="edit",
        color="#F59E0B",  # Amber
        user_id=current_user_id
    ))
    
    activities.append(ActivityLogEntry(
        id="act-004",
        type="LOGOUT",
        message="Logged out of session",
        timestamp=(now - timedelta(days=2)).isoformat(),
        icon="log-out",
        color="#EF4444",  # Red
        user_id=current_user_id
    ))
    
    activities.append(ActivityLogEntry(
        id="act-005",
        type="LOGIN",
        message="Logged in via AWS SSO",
        timestamp=(now - timedelta(days=2, minutes=30)).isoformat(),
        icon="log-in",
        color="#8B5CF6",  # Purple
        user_id=current_user_id
    ))
    
    # Add some more activities with timestamps spread out
    activities.append(ActivityLogEntry(
        id="act-006",
        type="VIEW",
        message="Viewed Passport details",
        timestamp=(now - timedelta(days=3, hours=4)).isoformat(),
        icon="eye",
        color="#3B82F6",  # Blue
        user_id=current_user_id
    ))
    
    activities.append(ActivityLogEntry(
        id="act-007",
        type="CREATE",
        message="Added new Email Account credentials",
        timestamp=(now - timedelta(days=4, hours=2)).isoformat(),
        icon="plus",
        color="#10B981",  # Green
        user_id=current_user_id
    ))
    
    activities.append(ActivityLogEntry(
        id="act-008",
        type="EXPORT",
        message="Exported data report",
        timestamp=(now - timedelta(days=5)).isoformat(),
        icon="download",
        color="#6B7280",  # Gray
        user_id=current_user_id
    ))
    
    # For admin users, add some activities from other users
    if "admin" in current_user_id:
        activities.append(ActivityLogEntry(
            id="act-009",
            type="LOGIN",
            message="Logged in via Password",
            timestamp=(now - timedelta(days=1, hours=5)).isoformat(),
            icon="log-in",
            color="#8B5CF6",  # Purple
            user_id="john.smith"
        ))
        
        activities.append(ActivityLogEntry(
            id="act-010",
            type="CREATE",
            message="Added new Medical Insurance details",
            timestamp=(now - timedelta(days=1, hours=4)).isoformat(),
            icon="plus",
            color="#10B981",  # Green
            user_id="john.smith"
        ))
    
    # Sort by timestamp (newest first)
    activities.sort(key=lambda x: x.timestamp, reverse=True)
    
    return activities