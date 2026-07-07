import os
import csv
from pymongo import MongoClient
from dotenv import load_dotenv

def migrate_csv_to_mongo():
    load_dotenv()
    mongo_uri = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
    client = MongoClient(mongo_uri)
    db = client["AI-IDS"]
    
    root_dir = os.path.dirname(os.path.abspath(__file__))
    directories_to_check = [root_dir, os.path.join(root_dir, "stimulate"), os.path.join(root_dir, "stimulater")]
    
    csv_files = []
    for d in directories_to_check:
        if os.path.exists(d):
            for file in os.listdir(d):
                if file.endswith(".csv"):
                    csv_files.append(os.path.join(d, file))
                    
    print(f"Found {len(csv_files)} CSV files to migrate.")
    
    for csv_file in csv_files:
        collection_name = os.path.splitext(os.path.basename(csv_file))[0]
        collection = db[collection_name]
        
        try:
            with open(csv_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                if rows:
                    collection.insert_many(rows)
                    print(f"✅ Migrated {len(rows)} records from '{os.path.basename(csv_file)}' into collection '{collection_name}'")
                else:
                    print(f"⚠️ '{os.path.basename(csv_file)}' was empty.")
        except Exception as e:
            print(f"❌ Failed to migrate '{os.path.basename(csv_file)}': {e}")
            
if __name__ == '__main__':
    migrate_csv_to_mongo()
