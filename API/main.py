# api/main.py

"""
Main FastAPI application.

This module sets up the FastAPI application with routes and middleware.
"""

import os
import logging
from logging.handlers import RotatingFileHandler
import time
from collections import Counter
from contextlib import asynccontextmanager
from typing import Dict, Any
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from fastapi import FastAPI, Request, status, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.auth import auth_router, init_auth_system
from api.controllers.pii_enhanced_controller import router as pii_router
from api.controllers.pii_enhanced_controller import router as pii_enhanced_router
from api.controllers.categories_controller import router as categories_router
from api.controllers.system_controller import router as system_router
from api.controllers.activity_controller import router as activity_router
from api.controllers.auth_enhanced_controller import router as auth_enhanced_router
from api.controllers.calendar_controller import router as calendar_router
from api.encryption import get_kms_handler

# Configure logging
handler = RotatingFileHandler(
    'application.log', maxBytes=1000000, backupCount=3)
logging.basicConfig(handlers=[handler], level=logging.INFO)
logger = logging.getLogger("api")

# Request counter
counter_calls = Counter()

# Define lifespan event handler
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup events
    logger.info(f"Application starting in {os.environ.get('ENVIRONMENT', 'development')} mode")
    
    # Initialize the authentication system
    init_auth_system()
    
    # Initialize encryption
    kms_handler = get_kms_handler()
    
    # Initialize KMS from secret if configured
    secret_name = os.environ.get("KMS_SECRET_NAME")
    if secret_name:
        if not kms_handler.initialized:
            logger.info(f"Initializing KMS from secret: {secret_name}")
            success = kms_handler.initialize_from_secret(secret_name)
            if not success:
                logger.warning(f"Failed to initialize KMS from secret: {secret_name}")
    
    logger.info("Application started successfully")
    
    # Yield control back to FastAPI
    yield
    
    # Shutdown events
    logger.info("Application shutting down")
    
    # Perform any cleanup here
    logger.info("Cleanup completed")

# Initialize app with lifespan
app = FastAPI(
    title="GUARD API",
    description="Secure PII Data Management API",
    version=os.environ.get("API_VERSION", "1.0.0"),
    lifespan=lifespan
)

# Include routers
app.include_router(auth_router)
app.include_router(auth_enhanced_router)  # New enhanced auth router
app.include_router(pii_router)
app.include_router(pii_enhanced_router)   # New enhanced PII router
app.include_router(categories_router)     # New categories router
app.include_router(system_router)
app.include_router(activity_router)       # New activity router
app.include_router(calendar_router)       # New calendar router

# Set up CORS for the React frontend
origins = [
    "http://localhost:8000",
    "http://localhost:3000",  
    "https://guard-dashboard.example.com",  # Add your React app domain
    "*"  # For development - restrict in production
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Middleware to add pagination headers
@app.middleware("http")
async def add_pagination_headers(request: Request, call_next):
    """
    Add pagination headers to responses when pagination is used.
    """
    # Process the request and get the response
    response = await call_next(request)
    
    # Check if pagination info is available
    if hasattr(request.state, 'pagination'):
        pagination = request.state.pagination
        
        # Add pagination headers
        response.headers["X-Total-Count"] = str(pagination["total"])
        response.headers["X-Page"] = str(pagination["page"])
        response.headers["X-Per-Page"] = str(pagination["limit"])
        response.headers["X-Total-Pages"] = str(pagination["pages"])
        
    return response

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

# Root route
@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "details": {
            "api_version": os.environ.get("API_VERSION", "1.0.0"),
            "environment": os.environ.get("ENVIRONMENT", "development")
        },
        "title": app.title,
        "version": app.version,
        "description": app.description,
        "documentation": "/docs",
        "health_check": "/system/health",
        "message": "Welcome to the GUARD API for secure PII data management"
    }

# Check if running directly
if __name__ == "__main__":
    import uvicorn
    # Use environment variables for host and port if available
    host = os.environ.get("API_HOST", "0.0.0.0")
    port = int(os.environ.get("API_PORT", 8000))
    uvicorn.run("api.main:app", host=host, port=port, reload=True)