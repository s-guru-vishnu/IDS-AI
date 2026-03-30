import logging
import os
import time
from datetime import datetime
from pymongo import MongoClient
from dotenv import load_dotenv

class MongoDBHandler(logging.Handler):
    """
    A custom logging handler that sends log records to a MongoDB collection.
    """
    def __init__(self, collection, level=logging.NOTSET):
        super().__init__(level)
        self.collection = collection

    def emit(self, record):
        try:
            log_entry = {
                "Timestamp": datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S'),
                "Timestamp_Epoch": record.created,
                "Logger": record.name,
                "Level": record.levelname,
                "Message": self.format(record),
                "File": record.pathname,
                "Line": record.lineno,
                "FunctionName": record.funcName
            }
            # Add extra context if it exists
            if hasattr(record, "request_id"):
                log_entry["Request_ID"] = record.request_id
                
            self.collection.insert_one(log_entry)
        except Exception as e:
            # Fallback to printing if MongoDB insert fails to avoid silent failures
            print(f"Failed to log to MongoDB: {e}")

def setup_mongo_logging(logger_name=None, database_name="IDS", collection_name="logs"):
    """
    Attaches a MongoDBHandler to the specified logger (or root logger if None).
    """
    load_dotenv()
    mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
    
    try:
        client = MongoClient(mongo_uri, serverSelectionTimeoutMS=2000)
        # Check connection
        client.server_info()
        
        db = client[database_name]
        collection = db[collection_name]
        
        handler = MongoDBHandler(collection)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        
        target_logger = logging.getLogger(logger_name) # None gets root logger
        target_logger.addHandler(handler)
        
        print(f"✅ MongoDB logging enabled for '{logger_name or 'root'}' -> collection '{collection_name}'")
        return client, db
    except Exception as e:
        print(f"❌ Could not enable MongoDB logging: {e}")
        return None, None

if __name__ == "__main__":
    # Test script
    logging.basicConfig(level=logging.INFO)
    client, db = setup_mongo_logging()
    if client:
        test_logger = logging.getLogger("test_logger")
        test_logger.info("This is a test log message sent to MongoDB.")
        print("Success! Check your MongoDB collection.")
