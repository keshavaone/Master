from logging.handlers import RotatingFileHandler
from fastapi.middleware.cors import CORSMiddleware
import logging
from collections import Counter
from typing import Dict, Any
from pydantic import ValidationError
import API.CONSTANTS as CONSTANTS  # Fixed import
from API.backend import Agent  # Fixed import
from fastapi import FastAPI, HTTPException, status, Request, Depends
import uvicorn

app = FastAPI()
counter_calls = Counter()

file_name = CONSTANTS.AWS_FILE
s3 = CONSTANTS.AWS_S3
agent = Agent(s3=s3, file_name=file_name)

"""
 1. CREATE APIs with Security, Authenticity and Authority.
 2. API for Data Security and Authenticity.
 3. API for Backups.
 """

origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
handler = RotatingFileHandler(
    'application.log', maxBytes=1000000, backupCount=3)
logging.basicConfig(handlers=[handler], level=logging.INFO)


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
    response = await call_next(request)
    counter_calls["totalCalls"] += 1
    print('Total API Calls: ', counter_calls["totalCalls"])
    print('Current Session-Calling:',
          counter_calls["totalCalls"], request.method, ':', request.url)
    logging.info(
        f"Log from API EndPoint - Current Session-Calling Count: '{counter_calls['totalCalls']}'. Method: '{request.method}'. EndPoint: '{request.url}'")
    return response


def process_data(item, operation):
    """
    Process data operations for PII data.

    Args:
        item: The data item to process
        operation: The operation to perform (insert, update, delete, get)

    Returns:
        dict: Response data

    Raises:
        HTTPException: If validation fails or operation is invalid
    """
    try:
        # Using conditional statements instead of match for Python 3.8/3.9 compatibility
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

        if response:
            return {"message": f"PII data {operation}ed successfully", "response": response}
        else:
            return {"message": f"Failed to {operation} PII data. Reason: {response}"}
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


# API endpoints
@app.post("/pii")
async def insert_pii_item(item: Dict[str, Any]):
    """Insert a new PII data item."""
    return process_data(item, 'insert')


@app.patch("/pii")
async def update_pii_item(item: Dict[str, Any]):
    """Update an existing PII data item."""
    return process_data(item, 'update')


@app.delete("/pii")
async def delete_pii_item(item: Dict[str, Any]):
    """Delete a PII data item."""
    return process_data(item, 'delete')


@app.get("/pii")
async def get_pii_data():
    """Get all PII data."""
    return process_data(None, 'get')


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
