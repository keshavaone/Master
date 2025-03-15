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
import pandas as pd
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
# Update these model definitions in your main.py file

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

class PIIItemResponse(BaseModel):
    """Model for PII data responses."""
    _id: str
    Category: str
    Type: str  
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
        # Allow for extra fields that might be in the database but not in the model
        extra = "ignore"

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

# Add this to your API/main.py file to provide a direct AWS SSO authentication endpoint

@app.post("/auth/aws-sso", response_model=TokenResponse, tags=["Authentication"])
async def auth_with_aws_sso(
    request: Request,
    access_key: str = Header(..., alias="X-AWS-Access-Key-ID"),
    secret_key: str = Header(..., alias="X-AWS-Secret-Access-Key"),
    session_token: Optional[str] = Header(None, alias="X-AWS-Session-Token")
):
    """
    Authenticate with AWS SSO credentials directly.
    
    This endpoint allows clients to authenticate using their AWS SSO credentials
    without relying on the server's ability to correctly handle AWS SSO tokens
    through the regular authentication flow.
    """
    try:
        # Validate the AWS credentials
        sts = boto3.client(
            'sts',
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token
        )
        
        # Verify the credentials
        identity = sts.get_caller_identity()
        user_id = identity.get("UserId", "aws-user")
        
        # Create a JWT token for the user
        # Import JWT utilities
        from API.jwt_utils import create_user_token
        
        # Add user data to the token
        user_data = {
            "arn": identity.get("Arn", ""),
            "account": identity.get("Account", ""),
            "auth_type": "aws_sso"
        }
        
        # Create token with 1 hour expiration
        token = create_user_token(user_id, user_data, 60)
        
        logger.info(f"AWS SSO authentication successful for user: {user_id}")
        
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": 3600,  # 1 hour in seconds
            "user_id": user_id
        }
    except ClientError as e:
        logger.error(f"AWS SSO authentication error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"AWS SSO authentication failed: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        logger.error(f"Unexpected error during AWS SSO authentication: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Authentication error: {str(e)}",
        )
        
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
            # Get the data from agent
            data = agent.get_all_data()
            
            # Ensure the data is in the correct format for model validation
            if isinstance(data, pd.DataFrame):
                # Convert DataFrame to list of dictionaries
                data_records = data.to_dict(orient='records')
                return data_records
            elif isinstance(data, list) and len(data) > 0:
                if not isinstance(data[0], dict):
                    # If we have a list of non-dictionary items, convert to proper format
                    columns = data
                    data_records = []
                    for i in range(0, len(columns), 4):  # Assuming 4 columns: _id, Type, PII, Category
                        if i + 3 < len(columns):
                            data_records.append({
                                "_id": str(data[i]),
                                "Type": str(data[i + 1]),
                                "PII": str(data[i + 2]),
                                "Category": str(data[i + 3])
                            })
                    return data_records
                else:
                    # Already a list of dictionaries
                    return data
            else:
                # If it's something else, return as is and let FastAPI handle validation
                return data
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

@app.get("/pii", tags=["PII Data"])
async def get_pii_data(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get all PII data."""
    try:
        data = process_data(None, 'get', current_user)
        
        # Ensure data is properly formatted for response model
        if isinstance(data, pd.DataFrame):
            # Convert DataFrame to list of dictionaries
            return data.to_dict(orient='records')
        elif isinstance(data, list):
            # If we already have a list, ensure each item is a proper dict
            if len(data) > 0 and not isinstance(data[0], dict):
                logger.warning("PII data is not in expected format, attempting to convert")
                # Try to interpret as column names
                response_list = []
                for i in range(0, len(data), 4):  # Assuming 4 columns: _id, Type, PII, Category
                    if i + 3 < len(data):
                        response_list.append({
                            "_id": str(data[i]),
                            "Type": str(data[i + 1]),
                            "PII": str(data[i + 2]),
                            "Category": str(data[i + 3])
                        })
                return response_list
        
        # Return data as is
        return data
    except Exception as e:
        logger.error(f"Error retrieving PII data: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail=f"Error retrieving PII data: {str(e)}"
        )

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
