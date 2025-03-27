"""
Run script for the API.

This module provides a convenient way to run the API locally.
"""

import os
import uvicorn
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

if __name__ == "__main__":
    # Get configuration from environment variables
    host = os.environ.get("API_HOST", "0.0.0.0")
    port = int(os.environ.get("API_PORT", 8000))
    reload = os.environ.get("RELOAD", "true").lower() == "true"
    
    # Run the application
    uvicorn.run(
        "api.main:app",
        host=host,
        port=port,
        reload=reload
    )