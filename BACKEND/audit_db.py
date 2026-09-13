"""Quick DB audit script for M3 hardening pass."""
import sys
sys.path.insert(0, '.')

from database.mongo_db import mongo
from collections import Counter

mongo.connect()
db = mongo.get_database()

# Threat actor values in incidents
print("=== THREAT ACTOR VALUES IN INCIDENTS ===")
pipeline = [
    {"$group": {"_id": "$threat_actor", "count": {"$sum": 1}}},
    {"$sort": {"count": -1}},
    {"$limit": 15}
]
for doc in db["incidents"].aggregate(pipeline):
    print(f"  threat_actor={doc['_id']!r}, count={doc['count']}")

print()
print("=== SAMPLE threat_actor from threat_intelligence collection ===")
for doc in db["threat_intelligence"].find({}).limit(5):
    print(f"  indicator_value={doc.get('indicator_value')!r}, threat_actor={doc.get('threat_actor')!r}, confidence={doc.get('confidence')!r}, severity={doc.get('severity')!r}, threat_name={doc.get('threat_name')!r}")

print()
print("=== IOC in incidents ===")
for doc in db["incidents"].find({"ioc_status": "Malicious"}).limit(5):
    print(f"  incident={doc.get('incident_id')}, threat_actor={doc.get('threat_actor')!r}, ioc_status={doc.get('ioc_status')}")

print()
print("=== ANCHOR UNIQUENESS CHECK ===")
anchors = [d["anchor_event_id"] for d in db["incidents"].find({}, {"anchor_event_id": 1}) if "anchor_event_id" in d]
dup = {k: v for k, v in Counter(anchors).items() if v > 1}
print(f"Total incidents: {db['incidents'].count_documents({})}")
print(f"Anchors found: {len(anchors)}")
print(f"Unique anchors: {len(set(anchors))}")
print(f"Duplicate anchor count: {len(dup)}")
if dup:
    print("Sample dups:", list(dup.items())[:5])

print()
print("=== CURRENT INDEXES ===")
idx = db["incidents"].index_information()
for name, info in idx.items():
    print(f"  name={name}, unique={info.get('unique', False)}, key={info['key']}")

print()
print("=== ATTACK CHAIN STATS ===")
total = db["incidents"].count_documents({})
with_chain = db["incidents"].count_documents({"attack_chain_detected": True})
chain_types = list(db["incidents"].aggregate([
    {"$match": {"attack_chain_detected": True}},
    {"$group": {"_id": "$attack_chain_type", "count": {"$sum": 1}}}
]))
print(f"Total incidents: {total}, With attack chain: {with_chain}")
for ct in chain_types:
    print(f"  chain_type={ct['_id']!r}, count={ct['count']}")

print()
print("=== SAMPLE INCIDENTS ===")
for doc in db["incidents"].find({}).limit(5):
    print(f"  id={doc.get('incident_id')}, anchor={doc.get('anchor_event_id')}, threat_type={doc.get('threat_type')}, attack_chain_type={doc.get('attack_chain_type')}")
