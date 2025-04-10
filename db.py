# db.py
import os
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv

# .env 파일 로드
load_dotenv()

# 환경변수에서 값 불러오기
MONGO_URI = os.getenv("MONGODB_URI")
DB_NAME = os.getenv("MONGODB_NAME")

# MongoDB 연결
client = AsyncIOMotorClient(MONGO_URI)
db = client[DB_NAME]
