from database.mongo_db import mongo

def cleanup():
    mongo.connect()
    db = mongo.get_database()
    coll = db["threat_predictions"]
    
    # 1. Delete documents with non-standard event_id (not EVTXXXXXX)
    res1 = coll.delete_many({"event_id": {"$not": {"$regex": "^EVT\\d+"}}})
    print(f"Deleted non-standard event_id records: {res1.deleted_count}")
    
    # 2. Check total count
    count = coll.count_documents({})
    print(f"Current threat_predictions count: {count}")
    mongo.disconnect()

if __name__ == "__main__":
    cleanup()
