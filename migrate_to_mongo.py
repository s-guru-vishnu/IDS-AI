import os
import csv
import json
from pymongo import MongoClient
from dotenv import load_dotenv
from datetime import datetime

def migrate_to_mongo():
    load_dotenv()
    mongo_uri = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
    client = MongoClient(mongo_uri)
    db = client["IDS"]
    collection = db["logs"]
    
    root_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 1. Discover CSV Files
    csv_files = []
    
    # Root directory: Non-recursive
    for file in os.listdir(root_dir):
        if file.endswith(".csv"):
            csv_files.append(os.path.join(root_dir, file))
            
    # Sub directories: Recursive
    sub_dirs = ["stimulate", "stimulater", "logs"]
    for sub in sub_dirs:
        d = os.path.join(root_dir, sub)
        if os.path.exists(d):
            for root, dirs, files in os.walk(d):
                # Exclude venv and .git
                if 'venv' in dirs: dirs.remove('venv')
                if '.git' in dirs: dirs.remove('.git')
                for file in files:
                    if file.endswith(".csv"):
                        csv_files.append(os.path.join(root, file))
                    
    print(f"🔍 Found {len(csv_files)} CSV files to migrate.")
    for csv_file in csv_files:
        source_name = os.path.basename(csv_file)
        
        try:
            with open(csv_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                if rows:
                    # Add source field
                    for row in rows:
                        row["Source_File"] = source_name
                    
                    collection.insert_many(rows)
                    print(f"✅ Migrated {len(rows)} records from '{source_name}' into 'IDS.logs'")
                else:
                    print(f"⚠️ '{os.path.basename(csv_file)}' was empty.")
        except Exception as e:
            print(f"❌ Failed to migrate '{os.path.basename(csv_file)}': {e}")

    # 2. Migrate JSON Alert Files
    json_alerts = [
        os.path.join(root_dir, "mitm_alerts.json"),
        os.path.join(root_dir, "stimulater", "nids_summary.json")
    ]
    
    print(f"🔍 Checking for JSON alert files...")
    for json_file in json_alerts:
        if not os.path.exists(json_file):
            continue
            
        source_name = os.path.basename(json_file)
        
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                # Check if it's a list of JSON objects (one per line) or a single JSON object/list
                content = f.read().strip()
                if not content:
                    continue
                    
                data_to_insert = []
                try:
                    # Try parsing as a single JSON object or list
                    data = json.loads(content)
                    if isinstance(data, list):
                        data_to_insert = data
                    else:
                        data_to_insert = [data]
                except json.JSONDecodeError:
                    # Try parsing as one JSON object per line (NDJSON)
                    f.seek(0)
                    for line in f:
                        if line.strip():
                            data_to_insert.append(json.loads(line))
                
                if data_to_insert:
                    for item in data_to_insert:
                        item["Source_File"] = source_name
                    collection.insert_many(data_to_insert)
                    print(f"✅ Migrated {len(data_to_insert)} records from '{source_name}' into 'IDS.logs'")
        except Exception as e:
            print(f"❌ Failed to migrate '{os.path.basename(json_file)}': {e}")

    # 3. Migrate Text Logs (Optional/Basic)
    print("🏁 Migration complete!")

if __name__ == '__main__':
    migrate_to_mongo()
