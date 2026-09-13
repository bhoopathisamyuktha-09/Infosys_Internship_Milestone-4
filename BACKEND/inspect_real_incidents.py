"""Real data inspection of 10 incidents for M3 hardening verification."""
import sys
sys.path.insert(0, '.')

from database.mongo_db import mongo

mongo.connect()
db = mongo.get_database()

# Inspect INC-000058 (key validation incident) + 9 others
incident_ids = ["INC-000058", "INC-000153", "INC-001029", "INC-008201", "INC-000131",
                "INC-007962", "INC-007785", "INC-000536", "INC-003680", "INC-000185"]

print("=== REAL INCIDENT DATA INSPECTION ===\n")

for iid in incident_ids:
    doc = db["incidents"].find_one({"incident_id": iid})
    if not doc:
        print(f"  [{iid}] NOT FOUND")
        continue

    chain = doc.get("attack_chain") or {}
    stages = chain.get("stages", [])

    print(f"[{iid}]")
    print(f"  anchor_event_id    : {doc.get('anchor_event_id')}")
    print(f"  threat_type        : {doc.get('threat_type')}")
    print(f"  risk_score         : {doc.get('risk_score')}")
    print(f"  risk_level         : {doc.get('risk_level')}")
    print(f"  asset_id           : {doc.get('asset_id')}")
    print(f"  asset_name         : {doc.get('asset_name')}")
    print(f"  ioc_status         : {doc.get('ioc_status')}")
    print(f"  ioc_type           : {doc.get('ioc_type')}")
    print(f"  ioc_confidence     : {doc.get('ioc_confidence')}")
    print(f"  threat_name        : {doc.get('threat_name')}")
    print(f"  threat_actor       : {doc.get('threat_actor')!r}")
    print(f"  attack_chain_det   : {doc.get('attack_chain_detected')}")
    print(f"  attack_chain_type  : {doc.get('attack_chain_type')}")
    print(f"  chain_stages_count : {len(stages)}")
    if stages:
        stage_types = [s.get('event_type') for s in stages]
        print(f"  chain_stage_types  : {stage_types}")
    print(f"  event_ids_count    : {len(doc.get('event_ids', []))}")
    print(f"  related_events     : {doc.get('related_events_count')}")
    print(f"  reasons[0]         : {doc.get('reasons', ['N/A'])[0]}")
    print()

print("=== MENTOR ACCEPTANCE VERIFICATION ===")
print("event_id EVT000058:")
e58 = db["security_events"].find_one({"event_id": "EVT000058"})
if e58:
    print(f"  event_type : {e58.get('event_type')}")
    print(f"  source_ip  : {e58.get('source_ip')}")
    print(f"  username   : {e58.get('username')}")
    print(f"  asset_name : {e58.get('asset_name')}")
    print(f"  timestamp  : {e58.get('timestamp')}")

# Check risk breakdown for a high-score incident  
inc58 = db["incidents"].find_one({"incident_id": "INC-000058"})
if inc58:
    rb = inc58.get("risk_breakdown", {})
    print(f"\nINC-000058 risk_breakdown:")
    for k, v in rb.items():
        print(f"  {k}: {v}")

print()
print("=== ATTACK CHAIN VALIDATION ON INC-000058 ===")
if inc58 and inc58.get("attack_chain"):
    ac = inc58["attack_chain"]
    stages = ac.get("stages", [])
    print(f"  attack_chain_type: {inc58.get('attack_chain_type')}")
    print(f"  description: {ac.get('description')}")
    print(f"  stage_count: {len(stages)}")
    anchor = inc58.get("anchor_event_id")
    stage_eids = [s.get("event_id") for s in stages]
    print(f"  anchor_in_chain: {anchor in stage_eids}")
    for i, s in enumerate(stages, 1):
        print(f"    Stage {i}: {s.get('stage_name')} | {s.get('event_type')} | {s.get('timestamp')}")
    # Verify same username
    stage_users = [s.get("event_id") for s in stages]
    # Fetch the events to check usernames
    ev_docs = list(db["security_events"].find({"event_id": {"$in": stage_eids}}))
    users = list(set(e.get("username") for e in ev_docs if e.get("username")))
    src_ips = list(set(e.get("source_ip") for e in ev_docs if e.get("source_ip")))
    print(f"  chain_usernames: {users}")
    print(f"  chain_source_ips: {src_ips}")

print()
print("=== UNIQUE ANCHOR INDEX VERIFICATION ===")
from pymongo import ASCENDING
idx = db["incidents"].index_information()
ai = idx.get("anchor_event_id_1", {})
print(f"  anchor_event_id_1 unique = {ai.get('unique', False)}")
print(f"  (True = DB-level duplicate protection active)")

print()
print("=== IOC LOOKUP: source_ip vs destination_ip ===")
# Find an incident where source_ip triggered IOC match
mal_inc = db["incidents"].find_one({"ioc_status": "Malicious"})
if mal_inc:
    evt = db["security_events"].find_one({"event_id": mal_inc.get("anchor_event_id")})
    if evt:
        print(f"  Incident: {mal_inc.get('incident_id')}")
        print(f"  Event source_ip: {evt.get('source_ip')}")
        print(f"  Event dest_ip: {evt.get('destination_ip')}")
        # Check which IP is in threat_intel
        src_ti = db["threat_intelligence"].find_one({"indicator_value": evt.get("source_ip")})
        dst_ti = db["threat_intelligence"].find_one({"indicator_value": evt.get("destination_ip")})
        print(f"  source_ip in TI: {src_ti is not None}")
        print(f"  dest_ip in TI: {dst_ti is not None}")
        print(f"  threat_name in incident: {mal_inc.get('threat_name')!r}")
        print(f"  threat_actor in incident: {mal_inc.get('threat_actor')!r}")
        print(f"  ioc_confidence: {mal_inc.get('ioc_confidence')!r}")
        print(f"  ioc_severity: {mal_inc.get('ioc_severity')!r}")
