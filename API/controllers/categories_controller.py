# api/controllers/categories_controller.py
"""
Categories controller for the GUARD application.

This module provides FastAPI endpoints for retrieving and managing PII data categories.
"""

import logging
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from pydantic import BaseModel, Field

from api.auth.middleware import auth_required
from api.data.database import DatabaseHandler
import os

# Configure logging
logger = logging.getLogger("api.controllers.categories")
logger.setLevel(logging.INFO)

# Create router
router = APIRouter(prefix="/categories", tags=["Categories"])

# Import mock handler if defined in PII controller to share the same mock DB
if os.environ.get("USE_MOCK_DB", "true").lower() == "true":
    # Share the mock database with PII controller
    from api.controllers.pii_enhanced_controller import db_handler
else:
    # Use real database handler for production
    db_handler = DatabaseHandler()

class CategoryResponse(BaseModel):
    """Category response model for UI."""
    id: int
    name: str
    count: int
    color: str
    icon: str

@router.get("/", response_model=List[CategoryResponse])
async def get_categories(
    request: Request,
    user_info: Dict[str, Any] = Depends(auth_required)
):
    """
    Get all categories with item counts.
    
    This endpoint supports the React dashboard's category listing.
    """
    try:
        # Get client IP for audit logging
        client_ip = request.client.host if request.client else "unknown"
        
        # Log the request
        logger.info(f"Getting categories for user: {user_info.get('sub')} from {client_ip}")
        
        # Get all items for this user
        user_id = user_info.get('sub').split(':')[-1]
        success, items = db_handler.get_all_items(user_id)
        
        if not success:
            logger.error(f"Database error: {items}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
                detail="Database error"
            )
        
        # Count items by category
        category_counts = {}
        for item in items:
            category = item.get('Category', 'Uncategorized')
            if category in category_counts:
                category_counts[category] += 1
            else:
                category_counts[category] = 1
        
        # Define standard category colors and icons
        category_metadata = {
            "Financial": {"color": "#3B82F6", "icon": "💳"},
            "Personal": {"color": "#F59E0B", "icon": "👤"},
            "Medical": {"color": "#EF4444", "icon": "🏥"},
            "Accounts": {"color": "#10B981", "icon": "🔑"},
            "Documents": {"color": "#8B5CF6", "icon": "📄"},
            "Uncategorized": {"color": "#6B7280", "icon": "📁"}
        }
        
        # Build response
        categories = []
        category_id = 1
        
        for category_name, count in category_counts.items():
            # Get metadata or use defaults
            metadata = category_metadata.get(category_name, {"color": "#6B7280", "icon": "📁"})
            
            categories.append(CategoryResponse(
                id=category_id,
                name=category_name,
                count=count,
                color=metadata["color"],
                icon=metadata["icon"]
            ))
            category_id += 1
        
        # Sort by name
        categories.sort(key=lambda x: x.name)
        
        return categories
            
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        # Log and convert other exceptions to HTTP exceptions
        logger.error(f"Error getting categories: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail="Internal server error"
        )

@router.get("/{category_name}/items", response_model=List[Dict[str, Any]])
async def get_items_by_category(
    request: Request,
    category_name: str,
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(20, ge=1, le=100, description="Items per page"),
    user_info: Dict[str, Any] = Depends(auth_required)
):
    """
    Get all items in a specific category.
    
    This endpoint supports the React dashboard's category filtering.
    """
    try:
        # Get client IP for audit logging
        client_ip = request.client.host if request.client else "unknown"
        
        # Log the request
        logger.info(f"Getting items for category {category_name} for user: {user_info.get('sub')} from {client_ip}")
        
        # Get all items for this user
        user_id = user_info.get('sub').split(':')[-1]
        success, items = db_handler.get_all_items(user_id)
        
        if not success:
            logger.error(f"Database error: {items}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
                detail="Database error"
            )
        
        # Filter by category
        filtered_items = [item for item in items if item.get('Category', '') == category_name]
        
        # Count total items after filtering
        total_items = len(filtered_items)
        
        # Apply pagination
        start_idx = (page - 1) * limit
        end_idx = start_idx + limit
        paginated_items = filtered_items[start_idx:end_idx]
        
        # Decrypt and transform items (similar to get_all_pii_data)
        # [Similar transformation code as in the PII controller]
        transformed_items = []
        for item in paginated_items:
            # Decrypt the item
            success, decrypted_item = db_handler.decrypt_item(item)
            if not success:
                # Log decryption error but continue with other items
                logger.warning(f"Failed to decrypt item: {item.get('_id')}")
                continue
                
            # Format for React UI
            try:
                # Parse PII data from string to structured format
                pii_data = decrypted_item.get('PII', '[]')
                if isinstance(pii_data, str):
                    import ast
                    try:
                        pii_fields = ast.literal_eval(pii_data)
                        if not isinstance(pii_fields, list):
                            pii_fields = [{"Item Name": "Data", "Data": pii_data}]
                    except (ValueError, SyntaxError):
                        pii_fields = [{"Item Name": "Data", "Data": pii_data}]
                else:
                    pii_fields = pii_data
                
                # Determine security level based on data type
                security_level = "high"  # Default for financial, medical
                if decrypted_item.get('Category') == "Personal":
                    security_level = "medium"
                elif "password" in decrypted_item.get('Type', '').lower() or "account" in decrypted_item.get('Type', '').lower():
                    security_level = "high"
                
                # Get metadata
                created_at = decrypted_item.get('created_at', '')
                updated_at = decrypted_item.get('updated_at', '')
                
                # Calculate "last updated" in human-readable format
                last_updated = "just now"
                if updated_at or created_at:
                    from datetime import datetime
                    import pytz
                    
                    # Use updated_at if available, otherwise created_at
                    timestamp_str = updated_at if updated_at else created_at
                    
                    try:
                        # Parse ISO format
                        timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                        timestamp = timestamp.replace(tzinfo=pytz.UTC)
                        
                        # Calculate time difference
                        now = datetime.now(pytz.UTC)
                        diff = now - timestamp
                        
                        if diff.days > 30:
                            months = diff.days // 30
                            last_updated = f"{months} month{'s' if months > 1 else ''} ago"
                        elif diff.days > 0:
                            last_updated = f"{diff.days} day{'s' if diff.days > 1 else ''} ago"
                        elif diff.seconds // 3600 > 0:
                            hours = diff.seconds // 3600
                            last_updated = f"{hours} hour{'s' if hours > 1 else ''} ago"
                        else:
                            minutes = (diff.seconds // 60) % 60
                            last_updated = f"{minutes} minute{'s' if minutes > 1 else ''} ago"
                    except (ValueError, AttributeError):
                        last_updated = "unknown"
                
                # Create UI-friendly format
                ui_item = {
                    "id": decrypted_item.get('_id'),
                    "category": decrypted_item.get('Category'),
                    "type": decrypted_item.get('Type'),
                    "securityLevel": security_level,
                    "lastUpdated": last_updated,
                    "piiData": [
                        {"name": field.get("Item Name", ""), "value": field.get("Data", "")}
                        for field in pii_fields
                    ],
                    "createdAt": created_at,
                    "updatedAt": updated_at,
                    "createdBy": decrypted_item.get('created_by', user_id),
                    "accessCount": decrypted_item.get('access_count', 0)
                }
                
                transformed_items.append(ui_item)
            except Exception as e:
                logger.warning(f"Error transforming item {item.get('_id')}: {e}")
                continue
                
        # Create pagination metadata
        pagination = {
            "page": page,
            "limit": limit,
            "total": total_items,
            "pages": (total_items + limit - 1) // limit
        }
        
        # Add pagination headers
        request.state.pagination = pagination
        
        return transformed_items
            
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        # Log and convert other exceptions to HTTP exceptions
        logger.error(f"Error getting items by category: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail="Internal server error"
        )