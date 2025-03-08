from logging.handlers import RotatingFileHandler
from fastapi.middleware.cors import CORSMiddleware
import logging
from collections import Counter
from typing import Dict, Any
from pydantic import ValidationError
import CONSTANTS as CONSTANTS
from Backend import Agent
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
    response = await call_next(request)
    counter_calls["totalCalls"] += 1
    print('Total API Calls: ', counter_calls["totalCalls"])
    print('Current Session-Calling:',
          counter_calls["totalCalls"], request.method, ':', request.url)
    logging.info(
        f"Log from API EndPoint - Current Session-Calling Count: '{counter_calls['totalCalls']}'. Method: '{request.method}'. EndPoint: '{request.url}'")
    return response


def process_data(item, operation):
    try:
        match operation:
            case 'insert':
                response = agent.insert_new_data(item)
            case 'update':
                response = agent.update_one_data(item)
            case 'delete':
                response = agent.delete_one_data(item)
            case 'get':
                return agent.get_all_data()
            case _:
                raise ValueError("Invalid operation")

        if response:
            return {"message": f"PII data {operation}ed successfully", "response": response}
        else:
            return {"message": f"Failed to {operation} PII data. Reason: {response}"}
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

# 1. API for CREATE


@app.post("/pii")
async def insert_pii_item(item: Dict[str, Any]):
    return process_data(item, 'insert')


@app.patch("/pii")
async def update_pii_item(item: Dict[str, Any]):
    return process_data(item, 'update')


@app.delete("/pii")
async def delete_pii_item(item: Dict[str, Any]):
    return process_data(item, 'delete')


@app.get("/pii")
async def get_pii_data():
    return process_data(None, 'get')


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
