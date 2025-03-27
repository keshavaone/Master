from logging.handlers import RotatingFileHandler
from fastapi.middleware.cors import CORSMiddleware
import logging
from collections import Counter
from typing import Dict, Any, Optional, Union
from pydantic import BaseModel, Field, ValidationError
import API.CONSTANTS as CONSTANTS
from API.Backend import Agent
from API.auth_middleware import enhanced_auth_required
from fastapi import FastAPI, HTTPException, status, Request, Depends, Header, BackgroundTasks
from fastapi.responses import JSONResponse
import uvicorn
import boto3
import time
import uuid
import pandas as pd
import os
from botocore.exceptions import ClientError
from datetime import datetime
from API.aws_sso_endpoint import aws_sso_router
from contextlib import contextmanager
from fastapi.concurrency import run_in_threadpool
import asyncio

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
app.include_router(aws_sso_router)

# Request counter
counter_calls = Counter()

# Global agent storage - will be lazily initialized per user
# This is more secure than creating a single global agent
user_agents = {}
user_agent_lock = asyncio.Lock()

# Global file_name & s3 values for backward compatibility
file_name = CONSTANTS.AWS_FILE
s3 = CONSTANTS.AWS_S3

# For backward compatibility - a global agent for legacy code that might expect it
# This will be initialized during the first auth and points to the most recent user's agent
global_agent = None

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
    
    try:
        # Process the request normally
        response = await call_next(request)
        
        # Log request metrics
        process_time = time.time() - start_time
        counter_calls["totalCalls"] += 1
        logger.info(
            f"Request #{counter_calls['totalCalls']} - {request.method} {request.url.path} "
            f"| Status: {response.status_code} | Time: {process_time:.3f}s"
        )
        
        return response
    except Exception as e:
        # Handle any uncaught exceptions
        process_time = time.time() - start_time
        logger.error(
            f"Unhandled exception in {request.method} {request.url.path}: {str(e)} "
            f"| Time: {process_time:.3f}s"
        )
        
        # Create a proper error response
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Internal server error. Please try again later."}
        )

# Agent management functions
async def get_or_create_agent(user_id: str, user_info: dict = None) -> Agent:
    """
    Get an existing agent for a user or create a new one.
    
    This function ensures each user has their own Agent instance that's
    properly initialized after authentication. It uses a lock to prevent
    race conditions in concurrent requests.
    
    Args:
        user_id: Authenticated user ID
        user_info: Optional user information dict with additional context
        
    Returns:
        Agent: The agent instance for this user
    """
    global global_agent
    async with user_agent_lock:
        # Check if agent already exists for this user
        if user_id in user_agents:
            logger.info(f"Using existing agent for user: {user_id}")
            return user_agents[user_id]
        
        logger.info(f"Creating new agent for user: {user_id}")
        
        # Initialize the agent with AWS resources
        # Use run_in_threadpool to avoid blocking the event loop with synchronous code
        agent = await run_in_threadpool(
            lambda: Agent(file_name=CONSTANTS.AWS_FILE)
        )
        
        # Create auth context with more detailed info from user_info
        auth_context = {
            "user_id": user_id,
            "auth_type": "aws_sso",
            "arn": user_info.get("arn", ""),
            "account": user_info.get("account", ""),
            "session_id": str(uuid.uuid4()),
            "login_time": datetime.now().isoformat()
        }
        
        # Set authentication context in the agent
        try:
            if hasattr(agent, 'set_auth_context'):
                # Use the method if available
                client_ip = None
                if 'client_ip' in auth_context:
                    client_ip = auth_context['client_ip']
                
                agent.set_auth_context(
                    user_id=user_id,
                    auth_type="aws_sso",
                    client_ip=client_ip
                )
            elif hasattr(agent, 'auth_context'):
                # Direct assignment if the method doesn't exist
                agent.auth_context = auth_context
            else:
                # Log a warning if we can't set the auth context
                logger.warning(f"Could not set auth context for agent - missing attribute. User: {user_id}")
        except Exception as e:
            logger.warning(f"Error setting auth context: {str(e)}")
            
        # Update the global agent reference for backward compatibility
        global_agent = agent
        
        # Store the agent for this user
        user_agents[user_id] = agent
        return agent

async def cleanup_agent(user_id: str):
    """
    Clean up an agent when no longer needed.
    
    This function should be called during logout or session expiration.
    
    Args:
        user_id: User ID whose agent should be cleaned up
    """
    async with user_agent_lock:
        if user_id in user_agents:
            agent = user_agents[user_id]
            # Run cleanup in a thread to avoid blocking
            await run_in_threadpool(agent.end_work)
            # Remove from the dictionary
            del user_agents[user_id]
            logger.info(f"Cleaned up agent for user: {user_id}")

@contextmanager
def agent_error_handler():
    """
    Context manager for handling agent operation errors consistently.
    
    Returns:
        Generator that yields and catches exceptions
    """
    try:
        yield
    except ValidationError as e:
        logger.error(f"Validation error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except HTTPException:
        # Re-raise HTTP exceptions without modifying them
        raise
    except Exception as e:
        logger.error(f"Error during agent operation: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

# Enhanced user dependency that provides both the user and agent
async def get_current_user_with_agent(request: Request = None):
    """
    Dependency that returns both the current user and their agent.
    
    Args:
        request: Optional request object for accessing client info
        
    Returns:
        Tuple[Dict, Agent]: The user information and agent
    """
    # Get the user information from the auth middleware
    user_info = await enhanced_auth_required(request) if request else await enhanced_auth_required()
    
    # Validate the user info
    if not user_info or not user_info.get("sub"):
        logger.error("Missing or invalid user information from auth middleware")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Get the user ID
    user_id = user_info.get("sub")
    
    # Get or create the agent for this user
    try:
        agent = await get_or_create_agent(user_id, user_info)
    except Exception as e:
        logger.error(f"Failed to initialize agent for user {user_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to initialize secure agent: {str(e)}"
        )
    
    # Return both the user info and agent
    return user_info, agent

async def process_data(item, operation, current_user: Dict[str, Any], agent: Agent):
    """
    Process data operations for PII data with security logging.

    Args:
        item: The data item to process
        operation: The operation to perform (insert, update, delete, get)
        current_user: Current authenticated user info
        agent: The user's agent instance

    Returns:
        dict: Response data

    Raises:
        HTTPException: If validation fails or operation is invalid
    """
    with agent_error_handler():
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
                    # Assuming 4 columns: _id, Type, PII, Category
                    for i in range(0, len(columns), 4):
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

# Authentication endpoints
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
        logger.error(
            f"Unexpected error during AWS SSO authentication: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Authentication error: {str(e)}",
        )

@app.get("/auth/user", tags=["Authentication"])
async def get_user_info(user_and_agent=Depends(get_current_user_with_agent)):
    """Get information about the currently authenticated user."""
    user_info, _ = user_and_agent
    return {
        "user_id": user_info.get("sub"),
        "auth_type": user_info.get("auth_type"),
        "authenticated": True
    }

@app.post("/auth/logout", tags=["Authentication"])
async def logout(
    background_tasks: BackgroundTasks, 
    user_and_agent=Depends(get_current_user_with_agent)
):
    """
    Logout the current user and clean up their agent.
    
    Args:
        background_tasks: FastAPI background tasks
        user_and_agent: The user info and agent dependency
        
    Returns:
        dict: Logout status
    """
    user_info, _ = user_and_agent
    user_id = user_info.get("sub")
    
    # Schedule cleanup to run in the background
    background_tasks.add_task(cleanup_agent, user_id)
    
    return {
        "message": "Logout successful",
        "user_id": user_id,
        "timestamp": datetime.now().isoformat()
    }

# API endpoints for PII data
@app.post("/pii", tags=["PII Data"])
async def insert_pii_item(
    item: PIIItemCreate,
    user_and_agent=Depends(get_current_user_with_agent)
):
    """Insert a new PII data item."""
    user_info, agent = user_and_agent
    return await process_data(item.dict(), 'insert', user_info, agent)

@app.patch("/pii", tags=["PII Data"])
async def update_pii_item(
    item: PIIItemUpdate,
    user_and_agent=Depends(get_current_user_with_agent)
):
    """Update an existing PII data item."""
    user_info, agent = user_and_agent
    return await process_data(item.dict(), 'update', user_info, agent)

@app.delete("/pii", tags=["PII Data"])
async def delete_pii_item(
    item: PIIItemDelete,
    user_and_agent=Depends(get_current_user_with_agent)
):
    """Delete a PII data item."""
    user_info, agent = user_and_agent
    return await process_data(item.dict(), 'delete', user_info, agent)

@app.get("/pii", tags=["PII Data"])
async def get_pii_data(user_and_agent=Depends(get_current_user_with_agent)):
    """Get all PII data."""
    with agent_error_handler():
        user_info, agent = user_and_agent
        logger.info(f"Getting all PII data for user: {user_info.get('sub')}")
        
        # Process 
        data = await process_data(None, 'get', user_info, agent)

        # Ensure data is properly formatted for response model
        if isinstance(data, pd.DataFrame):
            # Convert DataFrame to list of dictionaries
            return data.to_dict(orient='records')
        elif isinstance(data, list):
            # If we already have a list, ensure each item is a proper dict
            if len(data) > 0 and not isinstance(data[0], dict):
                logger.warning(
                    "PII data is not in expected format, attempting to convert")
                # Try to interpret as column names
                response_list = []
                # Assuming 4 columns: _id, Type, PII, Category
                for i in range(0, len(data), 4):
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

# System info endpoint - admin auth required
@app.get("/system/info", tags=["System"])
async def system_info(user_and_agent=Depends(get_current_user_with_agent)):
    """Get system information (admin only)."""
    user_info, _ = user_and_agent
    
    if user_info.get("sub") != "admin" and not user_info.get("arn", "").endswith("/Admin"):
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
        "auth_mode": "JWT and AWS SSO",
        "active_agents": len(user_agents)
    }

# Endpoint to get agent status for debugging/monitoring
@app.get("/system/agent-status", tags=["System"])
async def agent_status(user_and_agent=Depends(get_current_user_with_agent)):
    """Get the status of the current user's agent (admin only)."""
    user_info, agent = user_and_agent
    
    # Only allow admins to access this endpoint
    if user_info.get("sub") != "admin" and not user_info.get("arn", "").endswith("/Admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required for this endpoint"
        )
    
    # Get the number of active agents
    agent_count = len(user_agents)
    
    # Get information about this agent
    agent_info = {
        "user_id": user_info.get("sub"),
        "auth_context": agent.auth_context,
        "session_token_valid": agent.validate_session(),
        "operation_id": agent.operation_id,
        "encryption_status": agent.kms_client.get_encryption_context() if hasattr(agent, "kms_client") else None
    }
    
    return {
        "active_agents": agent_count,
        "current_agent": agent_info,
        "timestamp": datetime.now().isoformat()
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
    # agent = Agent(file_name=CONSTANTS.AWS_FILE)
    # print(agent.get_all_data())    
    
    