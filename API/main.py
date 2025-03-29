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

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.auth import auth_router, init_auth_system
from api.controllers.pii_controller import router as pii_router
from api.controllers.system_controller import router as system_router
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
app.include_router(pii_router)
app.include_router(system_router)

# Set up CORS
origins = [
    "http://localhost:8000",
    "http://localhost:3000",  # Add any frontend origins
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

# Root route
@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "Details":{
            "API_Version": os.environ.get("API_VERSION", "1.0.0"),
            "Environment": os.environ.get("ENVIRONMENT", "development")
        },
        "Title": app.title,
        "version": app.version,
        "description": app.description,
        "documentation": "/docs",
        "health_check": "/health",
        "system_info": "/info",
        "message": "Welcome to the "+app.title
    }

# Check if running directly
if __name__ == "__main__":
    import uvicorn
    # Use environment variables for host and port if available
    host = os.environ.get("API_HOST", "0.0.0.0")
    port = int(os.environ.get("API_PORT", 8000))
    uvicorn.run("api.main:app", host=host, port=port, reload=True)