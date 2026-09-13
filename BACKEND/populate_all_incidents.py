"""
populate_all_incidents.py — Milestone 3 Batch Incident Generator
================================================================
Milestone 3: Risk Prioritization & Security Intelligence

Generates M3 incidents from existing M2 prediction and security event records
in MongoDB with idempotency, deduplication, and progress logging.

Eligibility Rule:
    Every M2 prediction that has a corresponding security_events record is eligible
    to become an M3 incident. There is no confidence threshold or limit filter.
    The script processes predictions in confidence_score DESC order for deterministic
    incident ID generation, but all eligible predictions are processed.

Deduplication:
    - Each event can be the anchor of at most one incident (anchor_event_id uniqueness).
    - Correlated/related events may appear in multiple incidents' event_ids arrays.
    - The --force flag drops and recreates the entire incidents collection.

Usage:
    python populate_all_incidents.py [--limit N] [--force]
    python populate_all_incidents.py --force          # Process ALL predictions (default)
    python populate_all_incidents.py --limit 500      # Process only top 500 by confidence
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Set

BACKEND_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BACKEND_DIR))

from database.mongo_db import mongo
from database.incident_repository import ensure_incident_indexes, INCIDENTS_COLLECTION
from services.incident_service import process_event_to_incident
from services.data_store import store

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
)
log = logging.getLogger("populate_incidents")


def populate_incidents(limit: int = 0, force_recreate: bool = False) -> int:
    """
    Populate M3 incidents from real M2 predictions in MongoDB.

    Parameters
    ----------
    limit: int
        Maximum number of predictions to process.
        0 (default) means process ALL predictions (no cap).
    force_recreate: bool
        If True, clears existing `incidents` collection before generating.
    """
    start_time = time.time()
    mongo.connect()
    db = mongo.get_database()

    # Load static MITRE store cache
    store.load()

    # Ensure indexes
    ensure_incident_indexes(db)

    inc_coll = db[INCIDENTS_COLLECTION]
    if force_recreate:
        log.warning("Force flag enabled: dropping existing `incidents` collection...")
        inc_coll.drop()
        ensure_incident_indexes(db)

    # Cache existing anchor_event_ids and incident_ids for deduplication
    existing_anchor_event_ids: Set[str] = set()
    existing_incident_ids: Set[str] = set()
    for doc in inc_coll.find({}, {"incident_id": 1, "anchor_event_id": 1}):
        if "incident_id" in doc:
            existing_incident_ids.add(doc["incident_id"])
        if "anchor_event_id" in doc:
            existing_anchor_event_ids.add(doc["anchor_event_id"])

    log.info(f"Initial state: {inc_coll.count_documents({})} existing incidents ({len(existing_anchor_event_ids)} covered anchor events).")

    # Query candidate events
    preds_coll = db["threat_predictions"]

    total_preds = preds_coll.count_documents({})
    effective_limit = limit if limit > 0 else total_preds
    log.info(f"Processing {'ALL' if limit == 0 else f'up to {limit}'} of {total_preds} total M2 threat predictions...")

    # Fetch predictions sorted by confidence score DESC
    cursor = preds_coll.find({}).sort("confidence_score", -1)
    if limit > 0:
        cursor = cursor.limit(limit)

    created_count = 0
    skipped_count = 0
    errors_count = 0

    batch_to_insert: List[Dict[str, Any]] = []

    for idx, pred in enumerate(cursor, start=1):
        event_id = pred.get("event_id")
        if not event_id:
            continue

        # Skip if this event is already an anchor for an existing incident
        if event_id in existing_anchor_event_ids:
            skipped_count += 1
            continue

        try:
            # Generate incident document without persisting immediately
            inc_data = process_event_to_incident(event_id, db=db, persist=False)

            # Check duplicate incident_id
            if inc_data["incident_id"] in existing_incident_ids:
                skipped_count += 1
                continue

            batch_to_insert.append(inc_data)
            existing_incident_ids.add(inc_data["incident_id"])
            existing_anchor_event_ids.add(event_id)

            if len(batch_to_insert) >= 100:
                inc_coll.insert_many(batch_to_insert, ordered=False)
                created_count += len(batch_to_insert)
                batch_to_insert.clear()
                log.info(f"Progress: {created_count} incidents created ({idx}/{effective_limit} predictions evaluated)...")

        except Exception as e:
            errors_count += 1
            log.debug(f"Skipped event '{event_id}': {e}")

    # Insert remainder
    if batch_to_insert:
        inc_coll.insert_many(batch_to_insert, ordered=False)
        created_count += len(batch_to_insert)
        batch_to_insert.clear()

    total_final = inc_coll.count_documents({})
    elapsed = time.time() - start_time

    log.info("=" * 65)
    log.info(f"INCIDENT POPULATION COMPLETE in {elapsed:.2f}s")
    log.info(f"  • Total M2 Predictions  : {total_preds}")
    log.info(f"  • Predictions Examined  : {effective_limit}")
    log.info(f"  • New Incidents Created : {created_count}")
    log.info(f"  • Duplicates Skipped    : {skipped_count}")
    log.info(f"  • Errors/Missing Events : {errors_count}")
    log.info(f"  • Total Incidents in DB : {total_final}")
    log.info("=" * 65)

    mongo.disconnect()
    return created_count


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Populate M3 incidents from M2 predictions")
    parser.add_argument("--limit", type=int, default=0, help="Max predictions to process (0 = ALL, default: 0)")
    parser.add_argument("--force", action="store_true", help="Recreate incidents collection from scratch")
    args = parser.parse_args()

    populate_incidents(limit=args.limit, force_recreate=args.force)
