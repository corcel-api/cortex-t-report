from fastapi import FastAPI, HTTPException, Request
from loguru import logger
from motor.motor_asyncio import AsyncIOMotorClient
from substrateinterface.keypair import Keypair
import time
import os
from pydantic import BaseModel


class Metadata(BaseModel):
    uid: int
    accumulate_score: float
    credit: int


METADATA_COLLECTION = "metadata"
DATABASE_NAME = "cortex"

app = FastAPI()
mongodb_client = AsyncIOMotorClient(os.environ.get("MONGODB_URI"))
mongodb_client.get_database(DATABASE_NAME).get_collection(METADATA_COLLECTION)


def verify_headers(headers: dict):
    signature = headers.get("signature")
    message = headers.get("message")
    ss58_address = headers.get("ss58_address")
    logger.info(f"Verifying headers: {headers}")
    if not signature:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    keypair = Keypair(ss58_address=ss58_address)
    if not keypair.verify(message, signature):
        raise HTTPException(status_code=401, detail="Invalid signature")
    address_message, timestamp = message.split(":")
    if time.time() - float(timestamp) > 60:
        raise HTTPException(status_code=401, detail="Signature expired")
    return address_message


@app.post("/api/report_metadata")
async def report_metadata(request: Request):
    headers = request.headers
    address_message = verify_headers(headers)
    metadatas = await request.json()
    metadatas = [Metadata(**metadata) for metadata in metadatas.values()]
    logger.info(f"Received metadata from {address_message}: {metadatas}")
    data = {
        "_id": address_message,
        "metadatas": metadatas,
    }
    await mongodb_client.get_database(DATABASE_NAME).get_collection(
        METADATA_COLLECTION
    ).insert_one(data)
    return {"message": "Metadata received"}
