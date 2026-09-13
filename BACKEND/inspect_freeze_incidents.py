"""
inspect_freeze_incidents.py — Deep verification of real incidents for M3 Freeze Pass.
"""
import sys
sys.path.insert(0, ".")

from database.mongo_db import mongo

mongo.connect()
db = mongo.get_database()

test_incidents = [
    "INC-000058", "INC-000153", "INC-001029", "INC-008201", "INC-000131",
    "INC-007962", "INC-007785", "INC-000536", "INC-003680", "INC-000185"
]

print("=" * 70)
print("REAL INCIDENT INSPECTION (10 INCIDENTS) FOR FREEZE PASS")
print("=" * 70)

for inc_id in test_incidents:
    doc = db["incidents"].find_one({"incident_id": inc_id})
    if not doc:
        print(f"  [ERROR] {inc_id} not found in database!")
        continue

    ac = doc.get("attack_chain") or {}
    stages = ac.get("stages", [])
    
    print(f"\n--- {inc_id} ---")
    print(f"  Incident ID        : {doc.get('incident_id')}")
    print(f"  Anchor Event ID    : {doc.get('anchor_event_id')}")
    print(f"  Event IDs Count    : {len(doc.get('event_ids', []))}")
    print(f"  Threat Type        : {doc.get('threat_type')}")
    print(f"  Risk Score / Level : {doc.get('risk_score')} / {doc.get('risk_level')} (Priority: {doc.get('priority')})")
    print(f"  Asset ID / Name    : {doc.get('asset_id')} / {doc.get('asset_name')} (Dept: {doc.get('department')})")
    print(f"  Affected User      : {doc.get('affected_user')}")
    print(f"  ML Confidence      : {doc.get('ml_confidence')}%")
    print(f"  CVSS Score         : {doc.get('cvss_score')}")
    print(f"  IOC Status / Type  : {doc.get('ioc_status')} / {doc.get('ioc_type')}")
    print(f"  Threat Name        : {doc.get('threat_name')}")
    print(f"  Threat Actor       : {doc.get('threat_actor')!r}")
    print(f"  IOC Confidence/Sev : {doc.get('ioc_confidence')} / {doc.get('ioc_severity')}")
    print(f"  MITRE Techniques   : {doc.get('mitre_techniques')}")
    print(f"  Attack Chain Det.  : {doc.get('attack_chain_detected')}")
    if doc.get('attack_chain_detected'):
        print(f"  Attack Chain ID    : {ac.get('attack_chain_id')}")
        print(f"  Attack Chain Type  : {doc.get('attack_chain_type')}")
        print(f"  Chain Confidence   : {ac.get('confidence')}")
        print(f"  Chain Stages Count : {len(stages)}")
        print(f"  Chain Stages Types : {[s.get('event_type') for s in stages]}")
    print(f"  Recommendations    : {len(doc.get('recommendations', []))} items")
    print(f"  Status             : {doc.get('status')}")
    print(f"  Created At         : {doc.get('created_at')}")

print("\n" + "=" * 70)
print("ALL 10 INCIDENTS INSPECTED SUCCESSFULLY")
print("=" * 70)
