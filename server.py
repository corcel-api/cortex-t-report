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
    data = await request.json()
    logger.info(f"Received data: {data}")
    metadatas = [Metadata(**metadata) for metadata in data.values()]
    # Convert Pydantic models to dictionaries and update uid
    metadata_dicts = []
    for metadata in metadatas:
        metadata_dict = metadata.model_dump()
        metadata_dict["uid"] = str(metadata_dict["uid"])
        metadata_dicts.append(metadata_dict)

    logger.info(f"Received metadata from {address_message}: {metadata_dicts}")

    # Update with upsert
    try:
        await mongodb_client.get_database(DATABASE_NAME).get_collection(
            METADATA_COLLECTION
        ).update_one(
            {"_id": address_message},
            {"$set": {"metadatas": metadata_dicts}},
            upsert=True,
        )
        return {"message": "Metadata received and stored"}
    except Exception as e:
        logger.error(f"Error storing metadata: {e}")
        raise HTTPException(status_code=500, detail=f"Error storing metadata: {str(e)}")
