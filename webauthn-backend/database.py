from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
import os

load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017/biometric-auth")

client = AsyncIOMotorClient(MONGODB_URI)

db = client.get_database("biometric-auth")
users_collection = db.get_collection("users")