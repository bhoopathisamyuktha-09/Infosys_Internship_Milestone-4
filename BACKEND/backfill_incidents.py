"""
backfill_incidents.py — Safe Backfill for Stale Incidents Schema Fields
========================================================================
Synchronizes existing incident documents in MongoDB with their actual
anchor security events data:
  - severity (Critical, High, Medium, Low)
  - cve_id (e.g. CVE-2023-1234, CVE-2024-1045, CVE-2024-2201)
  - source_ip
  - destination_ip
  - status_history (audit records if missing)

Preserves all existing incident scores, feedback, statuses, and correlation data.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List

from pymongo import UpdateOne

import database.mongo_db as mongo_module
from database.incident_repository import ensure_incident_indexes, INCIDENTS_COLLECTION

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
)
log = logging.getLogger("backfill_incidents")


def run_backfill() -> int:
    t0 = time.time()
    mongo_module.mongo.connect()
    db = mongo_module.mongo.get_database()

    # Ensure indexes are up to date
    ensure_incident_indexes(db)

    inc_coll = db[INCIDENTS_COLLECTION]
    total_incidents = inc_coll.count_documents({})
    log.info(f"Starting backfill on {total_incidents} incidents...")

    # Load security events into lookup map
    events_cursor = db["security_events"].find(
        {},
        {
            "event_id": 1,
            "severity": 1,
            "vulnerability_id": 1,
            "source_ip": 1,
            "destination_ip": 1,
        },
    )
    events_map: Dict[str, Dict[str, Any]] = {e["event_id"]: e for e in events_cursor}
    log.info(f"Loaded {len(events_map)} security events into memory ({time.time() - t0:.2f}s).")

    batch_updates: List[UpdateOne] = []
    updated_total = 0

    for doc in inc_coll.find({}, {"_id": 1, "anchor_event_id": 1, "created_at": 1, "status": 1, "status_history": 1}):
        anchor_id = doc.get("anchor_event_id")
        evt = events_map.get(anchor_id)
        if not evt:
            continue

        set_fields: Dict[str, Any] = {}
        if evt.get("severity"):
            set_fields["severity"] = evt["severity"]
        if evt.get("vulnerability_id"):
            set_fields["cve_id"] = evt["vulnerability_id"]
        if evt.get("source_ip"):
            set_fields["source_ip"] = evt["source_ip"]
        if evt.get("destination_ip"):
            set_fields["destination_ip"] = evt["destination_ip"]

        if not doc.get("status_history"):
            set_fields["status_history"] = [
                {
                    "status": doc.get("status", "Open"),
                    "changed_by": "System",
                    "changed_at": doc.get("created_at", "2025-08-01 00:00:00"),
                    "reason": "Incident initialized",
                }
            ]

        if set_fields:
            batch_updates.append(UpdateOne({"_id": doc["_id"]}, {"$set": set_fields}))

        if len(batch_updates) >= 500:
            res = inc_coll.bulk_write(batch_updates, ordered=False)
            updated_total += res.modified_count
            batch_updates.clear()

    if batch_updates:
        res = inc_coll.bulk_write(batch_updates, ordered=False)
        updated_total += res.modified_count
        batch_updates.clear()

    elapsed = time.time() - t0
    log.info(f"Backfill complete in {elapsed:.2f}s! Total modified documents: {updated_total}")

    # Post-validation checks
    sev_counts = {
        s: inc_coll.count_documents({"severity": s})
        for s in ["Critical", "High", "Medium", "Low"]
    }
    cve_count = inc_coll.count_documents({"cve_id": {"$ne": None}})
    log.info(f"Severity distribution in incidents: {sev_counts}")
    log.info(f"Incidents with CVE: {cve_count}")

    return updated_total


if __name__ == "__main__":
    run_backfill()
