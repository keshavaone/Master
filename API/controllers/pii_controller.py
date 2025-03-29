"""
PII data controller.

This module provides FastAPI endpoints for managing PII data.
"""

import logging
from typing import Dict, Any, List, Union

from fastapi import APIRouter, Depends, HTTPException, status, Request, BackgroundTasks, Path, Body

from api.auth.middleware import auth_required
from api.data.models import (
    PIIItemCreate, PIIItemUpdate, PIIItemDelete, PIIItemResponse, 
    PIISearchParams, APIResponse
)
from api.data.database import DatabaseHandler

# Configure logging
logger = logging.getLogger("api.controllers.pii")
logger.setLevel(logging.INFO)

# Create router
router = APIRouter(prefix="/pii", tags=["PII Data"])

# Create database handler
db_handler = DatabaseHandler()


@router.get("/", response_model=List[PIIItemResponse])
async def get_all_pii_data(
    request: Request,
    search_params: PIISearchParams = Depends(),
    user_info: Dict[str, Any] = Depends(auth_required)
):
    """
    Get all PII data with optional filtering.
    """
    try:
        # Get client IP for audit logging
        client_ip = request.client.host if request.client else "unknown"
        
        # Log the request
        logger.info(f"Getting PII data for user: {user_info.get('sub')} from {client_ip}")
        
        # Get all items from the database
        success, items = db_handler.get_all_items()
        
        if not success:
            # Handle database error
            logger.error(f"Database error: {items}")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error")
        if search_params.category or search_params.type or search_params.search:
            # Filter items if search parameters are provided
            if search_params.category:
                items = [item for item in items if item.get('Category') == search_params.category]
            
            if search_params.type:
                items = [item for item in items if item.get('Type') == search_params.type]
            
            if search_params.search:
                # Simple search - in a real application you'd want better search capabilities
                search_term = search_params.search.lower()
                items = [
                    item for item in items if 
                    search_term in item.get('Category', '').lower() or
                    search_term in item.get('Type', '').lower()
                ]
        else:
            # If no search parameters, return all items
            items = items
        # Decrypt items
        decrypted_items = []
        for item in items:
            success, decrypted_item = db_handler.decrypt_item(item)
            if success:
                decrypted_items.append(decrypted_item)
            else:
                # Log decryption error but continue with other items
                logger.warning(f"Failed to decrypt item: {item.get('_id')}")
        
        # Convert to response model
        response_items = []
        for item in decrypted_items:
            try:
                response_items.append(
                    PIIItemResponse(
                        _id=item.get('_id'),
                        category=item.get('Category'),
                        type=item.get('Type'),
                        pii=item.get('PII')
                    )
                )
            except Exception as e:
                logger.warning(f"Failed to convert item to response model: {e}")
        
        return response_items
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        # Log and convert other exceptions to HTTP exceptions
        logger.error(f"Error getting PII data: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")

@router.post("/", response_model=APIResponse)
async def create_pii_item(
    request: Request,
    item: PIIItemCreate,
    user_info: Dict[str, Any] = Depends(auth_required)
):
    """
    Create a new PII data item.
    """
    try:
        # Get client IP for audit logging
        client_ip = request.client.host if request.client else "unknown"
        
        # Log the request
        logger.info(f"Creating PII item for user: {user_info.get('sub')} from {client_ip}")
        
        # Create the item
        success, result = db_handler.create_item(
            item=item,
            user_id=user_info.get('sub'),
            auth_type=user_info.get('auth_type', 'unknown')
        )
        
        if not success:
            # Handle database error
            logger.error(f"Database error: {result}")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error")
        
        # Return success response
        return APIResponse(
            success=True,
            message="PII item created successfully",
            data={"item_id": result.get('_id')}
        )
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        # Log and convert other exceptions to HTTP exceptions
        logger.error(f"Error creating PII item: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")

@router.patch("/{item_id}", response_model=APIResponse)
async def update_pii_item(
    item_id: str = Path(..., description="ID of the PII item to update"),
    request: Request = None,
    update_data: Dict[str, Any] = Body(..., description="Fields to update"),
    user_info: Dict[str, Any] = Depends(auth_required)
):
    """
    Update an existing PII data item.
    
    This endpoint allows updating specific fields of a PII data item.
    """
    try:
        # Get client IP for audit logging
        client_ip = request.client.host if request.client else "unknown"
        
        # Log the request
        logger.info(f"Updating PII item {item_id} for user: {user_info.get('sub')} from {client_ip}")
        print(f"Updating PII item {item_id} for user: {user_info.get('sub')} from {client_ip}")
        # First check if the item exists
        success, existing_item = db_handler.get_item_by_id(item_id)
        if not success:
            logger.warning(f"Item not found for update: {item_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"PII item with ID {item_id} not found"
            )

        # Create update model from the request data
        try:
            # Extract fields from update_data
            category = update_data.get('category')
            item_type = update_data.get('type')
            pii = update_data.get('pii')
            
            # Validate required fields
            if pii is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="PII data must be provided"
                )
            
            # Create update model
            update_item = PIIItemUpdate(
                _id=item_id,
                category=category or existing_item.get('Category'),
                type=item_type or existing_item.get('Type'),
                pii=pii or existing_item.get('PII')
            )
        except Exception as e:
            logger.error(f"Error creating update model: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid update data: {str(e)}"
            )
        
        # Update the item
        success, result = db_handler.update_item(
            item=update_item,
            user_id=user_info.get('sub'),
            auth_type=user_info.get('auth_type', 'unknown')
        )
        
        if not success:
            # Handle database error
            logger.error(f"Database error: {result}")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error")
        
        # Return success response
        return APIResponse(
            success=True,
            message="PII item updated successfully",
            data={"item_id": result.get('_id')}
        )
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        # Log and convert other exceptions to HTTP exceptions
        logger.error(f"Error updating PII item {item_id}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")

@router.delete("/{item_id}", response_model=APIResponse)
async def delete_pii_item(
    item_id: str = Path(..., description="ID of the PII item to delete"),
    request: Request = None,
    user_info: Dict[str, Any] = Depends(auth_required)
):
    """
    Delete a PII data item.
    
    This endpoint permanently removes a PII data item by its ID.
    """
    try:
        # Get client IP for audit logging
        client_ip = request.client.host if request.client else "unknown"
        
        # Log the request
        logger.info(f"Deleting PII item {item_id} for user: {user_info.get('sub')} from {client_ip}")
        
        # First check if the item exists
        success, existing_item = db_handler.get_item_by_id(item_id)
        if not success:
            logger.warning(f"Item not found for deletion: {item_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"PII item with ID {item_id} not found"
            )
        
        # Create delete model
        delete_item = PIIItemDelete(
            _id=item_id,
            category=existing_item.get('Category'),
            type=existing_item.get('Type')
        )
        
        # Delete the item
        success, result = db_handler.delete_item(
            item=delete_item,
            user_id=user_info.get('sub'),
            auth_type=user_info.get('auth_type', 'unknown')
        )
        
        if not success:
            # Handle database error
            logger.error(f"Database error: {result}")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error")
        
        # Return success response
        return APIResponse(
            success=True,
            message="PII item deleted successfully",
            data={"item_id": item_id}
        )
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        # Log and convert other exceptions to HTTP exceptions
        logger.error(f"Error deleting PII item {item_id}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")