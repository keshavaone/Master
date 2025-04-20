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
from fastapi.middleware.gzip import GZipMiddleware

from api.auth import auth_router, init_auth_system
from api.controllers.pii_enhanced_controller import router as pii_router
from api.controllers.categories_controller import router as categories_router
from api.controllers.system_controller import router as system_router
from api.controllers.activity_controller import router as activity_router
from api.controllers.auth_enhanced_controller import router as auth_enhanced_router
from api.controllers.calendar_controller import router as calendar_router
from api.encryption import get_kms_handler
from api.auth.security_enhancements import get_secure_headers, apply_rate_limit

# Configure logging
import os
import json
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler

# Ensure logs directory exists
log_dir = 'logs'
os.makedirs(log_dir, exist_ok=True)

# Configure rotating file handler
file_handler = RotatingFileHandler(
    os.path.join(log_dir, 'application.log'), 
    maxBytes=10485760,  # 10MB
    backupCount=10
)

# Add timed rotating handler for daily logs
daily_handler = TimedRotatingFileHandler(
    os.path.join(log_dir, 'daily.log'),
    when='midnight',
    interval=1,
    backupCount=30
)

# Configure log format
log_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(log_format)
daily_handler.setFormatter(log_format)

# Configure root logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[file_handler, daily_handler]
)
logger = logging.getLogger("api")

# Request counter and metrics
counter_calls = Counter()
api_metrics = {
    "response_times": [],
    "error_count": 0,
    "request_count": 0,
    "avg_response_time": 0.0
}

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
app.include_router(pii_router)           # PII data router
app.include_router(categories_router)    # Categories router
app.include_router(system_router)
app.include_router(activity_router)      # Activity router
app.include_router(calendar_router)      # Calendar router

# Set up CORS for the React frontend
origins = [
    "http://localhost:8000",
    "http://localhost:3000",
    "http://127.0.0.1:3000",  
    "http://127.0.0.1:8000",
    "https://guard-dashboard.example.com",  # Add your React app domain
    "*"  # For development - restrict in production
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["X-Total-Count", "X-Page", "X-Per-Page", "X-Total-Pages"]
)

# Add GZip compression for responses
app.add_middleware(GZipMiddleware, minimum_size=1000)

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

# Add security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """
    Add security headers to all responses
    """
    # First apply rate limiting - this will raise an exception if rate limit is exceeded
    await apply_rate_limit(request)
    
    # Process the request
    response = await call_next(request)
    
    # Add security headers
    security_headers = get_secure_headers()
    for header_name, header_value in security_headers.items():
        response.headers[header_name] = header_value
    
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
        
        # Log and track request metrics
        process_time = time.time() - start_time
        counter_calls["totalCalls"] += 1
        api_metrics["request_count"] += 1
        api_metrics["response_times"].append(process_time)
        
        # Keep only last 1000 response times in memory
        if len(api_metrics["response_times"]) > 1000:
            api_metrics["response_times"] = api_metrics["response_times"][-1000:]
        
        # Calculate average response time
        api_metrics["avg_response_time"] = sum(api_metrics["response_times"]) / len(api_metrics["response_times"])
        
        # Add response time header
        response.headers["X-Process-Time"] = str(process_time)
        
        logger.info(
            f"Request #{counter_calls['totalCalls']} - {request.method} {request.url.path} "
            f"| Status: {response.status_code} | Time: {process_time:.3f}s"
        )
        
        return response
    except Exception as e:
        # Handle any uncaught exceptions
        process_time = time.time() - start_time
        api_metrics["error_count"] += 1
        
        # Add response time to metrics
        api_metrics["response_times"].append(process_time)
        if len(api_metrics["response_times"]) > 1000:
            api_metrics["response_times"] = api_metrics["response_times"][-1000:]
            
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
    # Get basic system metrics
    avg_response_time = api_metrics["avg_response_time"]
    total_requests = api_metrics["request_count"]
    error_count = api_metrics["error_count"]
    
    return {
        "details": {
            "api_version": os.environ.get("API_VERSION", "1.0.0"),
            "environment": os.environ.get("ENVIRONMENT", "development"),
            "system_status": "healthy",
            "metrics": {
                "total_requests": total_requests,
                "error_count": error_count,
                "avg_response_time": f"{avg_response_time:.3f}s"
            }
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