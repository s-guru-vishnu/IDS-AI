from pymongo import MongoClient
import os
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()
mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
client = MongoClient(mongo_uri)
db = client["IDS"]
collection = db["batch_logs"]

print(f"Checking for recent logs (currentTime: {datetime.now()})")
recent_logs = list(collection.find().sort("Timestamp", -1).limit(5))

if not recent_logs:
    print("No recent logs found in MongoDB 'IDS.batch_logs'.")
else:
    for log in recent_logs:
        print(f"[{log.get('Timestamp')}] {log.get('Source_IP')} -> {log.get('Attack_Type')} ({log.get('Decision')})")
