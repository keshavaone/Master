from logging.handlers import RotatingFileHandler
from fastapi.middleware.cors import CORSMiddleware
import logging
from collections import Counter
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field, ValidationError
import API.CONSTANTS as CONSTANTS
from API.backend import Agent
from API.auth_endpoints import router as auth_router
from API.auth_middleware import auth_required, get_current_user, audit_log_middleware
from fastapi import FastAPI, HTTPException, status, Request, Depends, Header
import uvicorn
import boto3
import time
import uuid
import os
from datetime import datetime

# Configure logging
handler = RotatingFileHandler(
    'application.log', maxBytes=1000000, backupCount=3)
logging.basicConfig(handlers=[handler], level=logging.INFO)
logger = logging.getLogger("api")

# Initialize app
app = FastAPI(
    title="GUARD API",
    description="Secure PII Data Management API",
    version="1.0.0"
)
app.include_router(auth_router)

# Request counter
counter_calls = Counter()

# Initialize AWS resources
file_name = CONSTANTS.AWS_FILE
s3 = CONSTANTS.AWS_S3
agent = Agent(s3=s3, file_name=file_name)

# Define models for consistent data shapes
class PIIDataItem(BaseModel):
    """Model for PII data items."""
    Item_Name: str
    Data: str

class PIIItemBase(BaseModel):
    """Base model for PII data records."""
    Category: str
    Type: str

class PIIItemCreate(PIIItemBase):
    """Model for creating PII data."""
    PII: str

class PIIItemUpdate(PIIItemBase):
    """Model for updating PII data."""
    _id: str
    PII: str

class PIIItemDelete(BaseModel):
    """Model for deleting PII data."""
    _id: str
    Category: Optional[str] = None
    Type: Optional[str] = None

class PIIItemResponse(PIIItemBase):
    """Model for PII data responses."""
    _id: str
    PII: str
    
    class Config:
        """Configuration for Pydantic model."""
        schema_extra = {
            "example": {
                "_id": "61409aa3e8e5b2c3f0f7c5d2",
                "Category": "Financial",
                "Type": "CreditCards",
                "PII": "[{'Item Name': 'Card Number', 'Data': '**** **** **** 1234'}]"
            }
        }

class TokenResponse(BaseModel):
    """Model for token response."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: str


# Set up CORS
origins = [
    "http://localhost:8000",
    "http://localhost:3000",  # Add any frontend origins
    "https://app.yourdomain.com",  # Add production domains
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add audit logging middleware
app.middleware("http")(audit_log_middleware)

# Add request counting middleware
@app.middleware("http")
async def count_api_calls(request: Request, call_next):
    """
    Middleware to count and log API calls.
    
    Args:
        request: The incoming request
        call_next: The next middleware or route handler
        
    Returns:
        Response from the next handler
    """
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    
    counter_calls["totalCalls"] += 1
    logger.info(
        f"Request #{counter_calls['totalCalls']} - {request.method} {request.url.path} "
        f"| Status: {response.status_code} | Time: {process_time:.3f}s"
    )
    
    return response

# Authentication endpoints
@app.post("/auth/token", response_model=TokenResponse, tags=["Authentication"])
async def create_token(username: str = Header(...), password: str = Header(...)):
    """
    Create an authentication token with username/password.
    
    This is for development and testing purposes only.
    In production, use SSO authentication.
    """
    # In production, validate against a secure user database
    # This is a simplified example for development only
    if username != "admin" or password != CONSTANTS.APP_PASSWORD:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Import here to avoid circular imports
    from API.auth_middleware import create_jwt_token
    
    # Create and return token
    token = create_jwt_token(username)
    expires_in = 60 * 60  # 1 hour
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": expires_in,
        "user_id": username
    }

@app.get("/auth/user", tags=["Authentication"])
async def get_user_info(current_user = Depends(get_current_user)):
    """Get information about the currently authenticated user."""
    return {
        "user_id": current_user.get("sub"),
        "auth_type": current_user.get("auth_type"),
        "authenticated": True
    }

# Helper function for processing PII data
def process_data(item, operation, current_user: Dict[str, Any]):
    """
    Process data operations for PII data with security logging.
    
    Args:
        item: The data item to process
        operation: The operation to perform (insert, update, delete, get)
        current_user: Current authenticated user info
        
    Returns:
        dict: Response data
        
    Raises:
        HTTPException: If validation fails or operation is invalid
    """
    try:
        # Add audit trail entry
        user_id = current_user.get("sub", "unknown")
        operation_id = str(uuid.uuid4())
        
        logger.info(
            f"User {user_id} performing {operation} operation (ID: {operation_id})"
        )
        
        # Using conditional statements
        if operation == 'insert':
            response = agent.insert_new_data(item)
        elif operation == 'update':
            response = agent.update_one_data(item)
        elif operation == 'delete':
            response = agent.delete_one_data(item)
        elif operation == 'get':
            return agent.get_all_data()
        else:
            raise ValueError("Invalid operation")

        # Log the operation result
        success = bool(response)
        logger.info(
            f"Operation {operation_id} completed with status: {'success' if success else 'failure'}"
        )
        
        if success:
            return {
                "message": f"PII data {operation}ed successfully",
                "response": response,
                "operation_id": operation_id,
                "timestamp": datetime.now().isoformat()
            }
        else:
            error_message = f"Failed to {operation} PII data. Reason: {response}"
            logger.error(f"Operation {operation_id} failed: {error_message}")
            return {
                "message": error_message,
                "operation_id": operation_id,
                "timestamp": datetime.now().isoformat()
            }
    except ValidationError as e:
        logger.error(f"Validation error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(f"Error processing data: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

# API endpoints
@app.post("/pii", tags=["PII Data"])
async def insert_pii_item(
    item: PIIItemCreate,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Insert a new PII data item."""
    return process_data(item.dict(), 'insert', current_user)

@app.patch("/pii", tags=["PII Data"])
async def update_pii_item(
    item: PIIItemUpdate,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Update an existing PII data item."""
    return process_data(item.dict(), 'update', current_user)

@app.delete("/pii", tags=["PII Data"])
async def delete_pii_item(
    item: PIIItemDelete,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Delete a PII data item."""
    return process_data(item.dict(), 'delete', current_user)

@app.get("/pii", response_model=List[PIIItemResponse], tags=["PII Data"])
async def get_pii_data(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get all PII data."""
    return process_data(None, 'get', current_user)

# Health check endpoint - no auth required
@app.get("/health", tags=["System"])
async def health_check():
    """Check system health."""
    try:
        # Check AWS connectivity by listing S3 buckets (minimal permission required)
        s3 = boto3.client('s3')
        response = s3.list_buckets()
        
        return {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "version": "1.0.0",
            "aws_status": "connected"
        }
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return {
            "status": "unhealthy",
            "timestamp": datetime.now().isoformat(),
            "error": str(e)
        }

# System info endpoint - auth required
@app.get("/system/info", tags=["System"])
async def system_info(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get system information (admin only)."""
    if current_user.get("sub") != "admin" and not current_user.get("arn", "").endswith("/Admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required for this endpoint"
        )
    
    return {
        "api_version": "1.0.0",
        "request_count": dict(counter_calls),
        "environment": os.environ.get("ENVIRONMENT", "development"),
        "aws_region": os.environ.get("AWS_REGION", "us-east-1"),
        "dynamo_table": "myPII",
        "auth_mode": "JWT and AWS SSO"
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)

# export PYTHONPATH=$PYTHONPATH:$(pwd)
