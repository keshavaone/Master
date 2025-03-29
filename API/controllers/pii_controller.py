"""
PII data controller.

This module provides FastAPI endpoints for managing PII data.
"""

import logging
from typing import Dict, Any, List, Union

from fastapi import APIRouter, Depends, HTTPException, status, Request, BackgroundTasks

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
        logger.info(
            f"Getting PII data for user: {user_info.get('sub')} from {client_ip}")
        # Get all items from the database
        success, items = db_handler.get_all_items(user_info.get('sub').split(':')[-1])

        if not success:
            # Handle database error
            logger.error(f"Database error: {items}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error")
        if search_params.category or search_params.type or search_params.search:
            # Filter items if search parameters are provided
            if search_params.category:
                items = [item for item in items if item.get(
                    'Category') == search_params.category]

            if search_params.type:
                items = [item for item in items if item.get(
                    'Type') == search_params.type]

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
                        Category=item.get('Category'),
                        Type=item.get('Type'),
                        PII=item.get('PII')
                    )
                )
            except Exception as e:
                logger.warning(
                    f"Failed to convert item to response model: {e}")
        return response_items
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        # Log and convert other exceptions to HTTP exceptions
        logger.error(f"Error getting PII data: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")


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
        logger.info(
            f"Creating PII item for user: {user_info.get('sub')} from {client_ip}")

        # Create the item
        success, result = db_handler.create_item(
            item=item,
            user_id=user_info.get('sub'),
            auth_type=user_info.get('auth_type', 'unknown')
        )

        if not success:
            # Handle database error
            logger.error(f"Database error: {result}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error")

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
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")


@router.patch("/", response_model=APIResponse)
async def update_pii_item(
    request: Request,
    item: PIIItemUpdate,
    user_info: Dict[str, Any] = Depends(auth_required)
):
    """
    Update an existing PII data item.
    """
    try:
        # Get client IP for audit logging
        client_ip = request.client.host if request.client else "unknown"

        # Log the request
        logger.info(
            f"Updating PII item for user: {user_info.get('sub')} from {client_ip}")

        # Validate that the item ID exists
        if not item.id:
            logger.error("Missing item ID in update request")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Item ID is required for updates"
            )

        # Update the item
        success, result = db_handler.update_item(
            item=item,
            user_id=user_info.get('sub'),
            auth_type=user_info.get('auth_type', 'unknown')
        )
        print(result)
        if not success:
            # Handle database error
            logger.error(f"Database error: {result}")
            if isinstance(result, str) and "not found" in result.lower():
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail=f"Item with ID {item.id} not found")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error")

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
        logger.error(f"Error updating PII item: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")


@router.delete("/", response_model=APIResponse)
async def delete_pii_item(
    request: Request,
    item: PIIItemDelete,
    user_info: Dict[str, Any] = Depends(auth_required)
):
    """
    Delete a PII data item.
    """
    try:
        # Get client IP for audit logging
        client_ip = request.client.host if request.client else "unknown"

        # Log the request
        logger.info(
            f"Deleting PII item for user: {user_info.get('sub')} from {client_ip}")

        # Validate that the item ID exists
        if not item.id:
            logger.error("Missing item ID in delete request")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Item ID is required for deletion"
            )

        # Delete the item
        success, result = db_handler.delete_item(
            item=item,
            user_id=user_info.get('sub'),
            auth_type=user_info.get('auth_type', 'unknown')
        )

        if not success:
            # Handle database error
            logger.error(f"Database error: {result}")
            if isinstance(result, str) and "not found" in result.lower():
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail=f"Item with ID {item.id} not found")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error")

        # Return success response
        return APIResponse(
            success=True,
            message="PII item deleted successfully",
            data={"item_id": item.id}
        )
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        # Log and convert other exceptions to HTTP exceptions
        logger.error(f"Error deleting PII item: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
