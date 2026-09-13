#!/usr/bin/env python3
"""
Load the fixed dataset CSVs into MongoDB collections.

Run this once after starting MongoDB:
    python3 database/init_db.py

It will:
- Create collections for each CSV
- Load all rows
- Create appropriate indexes for query performance
- Report success/failure

Safe to run multiple times — it clears existing collections before loading.
"""
import os
import sys
import pandas as pd
from pymongo import MongoClient, ASCENDING
from pymongo.errors import ConnectionFailure

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")


def init_db():
    """Initialize MongoDB with the fixed dataset."""
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        client.admin.command("ping")
        db = client["threat_detection"]
        print(f"✓ Connected to MongoDB at {MONGO_URI}")
    except ConnectionFailure as e:
        print(f"✗ Failed to connect to MongoDB: {e}")
        print("Make sure MongoDB is running: docker-compose up -d")
        sys.exit(1)

    collections_to_create = {
        "security_events": ("security_events.csv", [("event_id", ASCENDING), ("timestamp", ASCENDING)]),
        "assets": ("assets.csv", [("asset_name", ASCENDING)]),
        "vulnerabilities": ("vulnerabilities.csv", [("cve_id", ASCENDING)]),
        "threat_intelligence": ("threat_intelligence.csv", [("indicator_value", ASCENDING)]),
        "incident_history": ("incident_history.csv", [("event_id", ASCENDING)]),
        "mitre_attack_mapping": ("mitre_attack_mapping.csv", [("event_type", ASCENDING)]),
        "mitre_technique_catalog": ("mitre_technique_catalog.csv", [("mitre_id", ASCENDING)]),
    }

    for coll_name, (csv_file, indexes) in collections_to_create.items():
        csv_path = os.path.join(DATA_DIR, csv_file)
        if not os.path.exists(csv_path):
            print(f"✗ {csv_file} not found at {csv_path}")
            sys.exit(1)

        # load the CSV
        df = pd.read_csv(csv_path)
        records = df.to_dict("records")

        # clear + insert
        coll = db[coll_name]
        coll.delete_many({})  # wipe old data
        coll.insert_many(records)
        print(f"✓ Loaded {len(records)} rows into {coll_name}")

        # create indexes
        for field, direction in indexes:
            try:
                coll.create_index([(field, direction)])
                print(f"  ├─ Index on {field}")
            except Exception as e:
                print(f"  ├─ Failed to index {field}: {e}")

    # summary
    print("\n✓ Database initialized successfully")
    print("\nCollections in 'threat_detection' database:")
    for coll_name in db.list_collection_names():
        count = db[coll_name].count_documents({})
        print(f"  - {coll_name}: {count} documents")

    client.close()


if __name__ == "__main__":
    init_db()
