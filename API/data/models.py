"""
Data models for the API.

This module defines Pydantic models for data validation and serialization.
"""

from typing import Dict, Any, Optional, List, Union
from pydantic import BaseModel, Field, validator
from datetime import datetime
import uuid


class PIIDataItem(BaseModel):
    """
    Model for PII data items within a record.
    """
    item_name: str = Field(..., description="Name of the item")
    data: str = Field(..., description="PII data value")
    
    model_config = {
        "extra": "ignore"
    }


class PIIItemBase(BaseModel):
    """
    Base model for PII data records.
    """
    category: str = Field(..., description="Category of the PII data")
    type: str = Field(..., description="Type of the PII data")
    
    model_config = {
        "extra": "ignore"
    }


class PIIItemCreate(PIIItemBase):
    """
    Model for creating PII data.
    """
    pii: str = Field(..., description="PII data as a string (typically JSON)")


class PIIItemUpdate(PIIItemBase):
    """
    Model for updating PII data.
    """
    id: str = Field(..., description="Unique ID of the record", alias="_id")
    pii: str = Field(..., description="PII data as a string (typically JSON)")
    
    model_config = {
        "populate_by_name": True
    }


class PIIItemDelete(BaseModel):
    """
    Model for deleting PII data.
    """
    id: str = Field(..., description="Unique ID of the record", alias="_id")
    category: Optional[str] = Field(None, description="Category of the PII data")
    type: Optional[str] = Field(None, description="Type of the PII data")
    
    model_config = {
        "populate_by_name": True
    }


class PIIItemResponse(PIIItemBase):
    """
    Model for PII data responses.
    """
    id: str = Field(..., description="Unique ID of the record", alias="_id")
    pii: str = Field(..., description="PII data as a string (typically JSON)")

    model_config = {
        "json_schema_extra": {
            "example": {
                "_id": "61409aa3e8e5b2c3f0f7c5d2",
                "category": "Financial",
                "type": "CreditCards",
                "pii": "[{'item_name': 'Card Number', 'data': '**** **** **** 1234'}]"
            }
        },
        "populate_by_name": True
    }


class PIISearchParams(BaseModel):
    """
    Model for searching PII data.
    """
    category: Optional[str] = Field(None, description="Category to filter by")
    type: Optional[str] = Field(None, description="Type to filter by")
    search: Optional[str] = Field(None, description="Search term")


class APIResponse(BaseModel):
    """
    Standard API response model.
    """
    success: bool = Field(..., description="Whether the operation was successful")
    message: str = Field(..., description="Response message")
    data: Optional[Any] = Field(None, description="Response data")
    error: Optional[str] = Field(None, description="Error message if unsuccessful")


class AuditLogEntry(BaseModel):
    """
    Model for audit log entries.
    """
    timestamp: datetime = Field(default_factory=datetime.now, description="When the event occurred")
    operation_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique ID for the operation")
    event_type: str = Field(..., description="Type of event")
    message: str = Field(..., description="Event message")
    user_id: str = Field(..., description="User who performed the action")
    auth_type: str = Field(..., description="Authentication type used")
    client_ip: str = Field(..., description="Client IP address")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional event details")