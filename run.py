"""
Run script for the API.

This module provides a convenient way to run the API locally.
"""

import os
import uvicorn
import logging
from dotenv import load_dotenv

# Set up logging
logger = logging.getLogger("startup")
logging.basicConfig(level=logging.INFO)

# Load environment variables from .env file
env_path = os.path.join(os.path.dirname(__file__), '.env')
if os.path.exists(env_path):
    load_dotenv(env_path)
    logger.info(f"Loaded environment from {env_path}")
else:
    logger.warning(f"No .env file found at {env_path}, using system environment variables")

if __name__ == "__main__":
    # Get configuration from environment variables
    host = os.environ.get("API_HOST", "0.0.0.0")
    port = int(os.environ.get("API_PORT", 8000))
    reload = os.environ.get("RELOAD", "true").lower() == "true"
    workers = int(os.environ.get("API_WORKERS", "1"))
    log_level = os.environ.get("LOG_LEVEL", "info")
    
    # Log startup configuration
    logger.info(f"Starting server on {host}:{port}")
    logger.info(f"Environment: {os.environ.get('ENVIRONMENT', 'development')}")
    logger.info(f"Workers: {workers}, Auto-reload: {reload}")
    
    # Configure uvicorn with optimized settings
    uvicorn_config = {
        "app": "api.main:app",
        "host": host,
        "port": port,
        "reload": reload,
        "workers": workers,
        "log_level": log_level,
        "loop": "uvloop",
        "http": "httptools",
        "limit_concurrency": 1000,
        "timeout_keep_alive": 65
    }
    
    # Run the application with improved settings
    uvicorn.run(**uvicorn_config)