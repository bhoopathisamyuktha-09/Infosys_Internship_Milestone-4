"""
Data access layer — queries MongoDB fresh on every call.

Only `mitre_attack_mapping` is cached at startup: it's static reference data
with no write endpoint, so caching it is safe and avoids re-querying a small
lookup table on every single event row. Everything else — events, vulnerabilities,
threat intel, incidents — is queried live from MongoDB on every request, so a
POST'd event shows up in GET /events immediately, no restart needed.
"""
import pandas as pd

from database.mongo_db import mongo
from utils.logger import get_logger

log = get_logger("data_store")


class DataStore:
    def __init__(self):
        self._mitre_by_event_type: dict = {}
        self._loaded = False

    def load(self):
        """Load only the static MITRE mapping at startup. Called once after mongo.connect()."""
        try:
            db = mongo.get_database()
            mitre_df = pd.DataFrame(list(db["mitre_attack_mapping"].find({}, {"_id": 0})))
            self._mitre_by_event_type = mitre_df.set_index("event_type").to_dict("index")
            self._loaded = True
            log.info(f"MITRE mapping cached ({len(mitre_df)} event types). "
                     f"All other collections are queried live from MongoDB per request.")
        except RuntimeError as e:
            # In test environment there may be no real MongoDB connection.
            log.warning(f"Skipping MITRE cache load (no DB connection): {e}")
            self._mitre_by_event_type = {}
            self._loaded = True
        except Exception as e:
            log.error(f"Failed to load MITRE mapping from MongoDB: {e}")
            raise RuntimeError(
                f"Could not load data from MongoDB: {e}. "
                f"Make sure the database has been initialized (run: python3 database/init_db.py)"
            ) from e

    @property
    def loaded(self) -> bool:
        return self._loaded

    def mitre_for(self, event_type: str) -> dict | None:
        return self._mitre_by_event_type.get(event_type)

    # ---------------------------------------------------------------
    # Security events — live queries, always current
    # ---------------------------------------------------------------
    def query_events(self, severity: str | None = None, event_type: str | None = None,
                      limit: int = 500) -> pd.DataFrame:
        db = mongo.get_database()
        query = {}
        if severity and severity != "All":
            query["severity"] = severity
        if event_type and event_type != "All":
            query["event_type"] = event_type
        cursor = (
            db["security_events"]
            .find(query, {"_id": 0})
            .sort("timestamp", -1)
            .limit(limit)
        )
        return pd.DataFrame(list(cursor))

    def event_counts_by_severity(self) -> dict:
        db = mongo.get_database()
        coll = db["security_events"]
        return {
            "total": coll.count_documents({}),
            "critical": coll.count_documents({"severity": "Critical"}),
            "high": coll.count_documents({"severity": "High"}),
        }

    def event_type_counts(self) -> list[dict]:
        """Real MongoDB aggregation pipeline — grouped counts, sorted descending."""
        db = mongo.get_database()
        pipeline = [
            {"$group": {"_id": "$event_type", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
        ]
        results = db["security_events"].aggregate(pipeline)
        return [{"event_type": r["_id"], "count": r["count"]} for r in results]

    def all_event_ids_and_severities(self) -> list[dict]:
        """Lightweight projection (2 fields only) for computing avg risk score
        without pulling full documents."""
        db = mongo.get_database()
        cursor = db["security_events"].find({}, {"_id": 0, "event_id": 1, "severity": 1})
        return list(cursor)

    def insert_event(self, event_dict: dict) -> str:
        """Insert a new event into MongoDB. Called by POST /events.
        Auto-generates a sequential event_id (EVT000001-style, matching the existing
        dataset's convention) if the caller didn't supply one — every event needs one,
        since routes/events.py's response model requires it.
        No cache to invalidate — the next GET /events will see it immediately."""
        db = mongo.get_database()
        coll = db["security_events"]

        if not event_dict.get("event_id"):
            existing_ids = coll.find({}, {"event_id": 1, "_id": 0})
            max_num = 0
            for doc in existing_ids:
                eid = doc.get("event_id", "")
                if eid.startswith("EVT") and eid[3:].isdigit():
                    max_num = max(max_num, int(eid[3:]))
            event_dict["event_id"] = f"EVT{max_num + 1:06d}"

        result = coll.insert_one(event_dict)
        return event_dict["event_id"]

    # ---------------------------------------------------------------
    # Reference / supporting tables — live queries
    # ---------------------------------------------------------------
    def query_vulnerabilities(self, severity: str | None = None, limit: int = 50) -> pd.DataFrame:
        db = mongo.get_database()
        query = {}
        if severity and severity != "All":
            query["severity"] = severity
        cursor = db["vulnerabilities"].find(query, {"_id": 0}).limit(limit)
        return pd.DataFrame(list(cursor))

    def count_vulnerabilities(self) -> int:
        return mongo.get_database()["vulnerabilities"].count_documents({})

    def query_threat_intel(self, severity: str | None = None, limit: int = 50) -> pd.DataFrame:
        db = mongo.get_database()
        query = {}
        if severity and severity != "All":
            query["severity"] = severity
        cursor = db["threat_intelligence"].find(query, {"_id": 0}).limit(limit)
        return pd.DataFrame(list(cursor))

    def count_active_incidents(self) -> int:
        db = mongo.get_database()
        return db["incident_history"].count_documents({"status": {"$in": ["Open", "In Progress"]}})


# single shared instance, populated once at app startup
store = DataStore()
