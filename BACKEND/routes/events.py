from fastapi import APIRouter, Query, HTTPException, status
from pydantic import BaseModel
from typing import Optional
from enum import Enum
import pandas as pd

from services.data_store import store
from services.m1_risk_scoring import risk_score_for
from models.schemas import Event, MitreInfo
from utils.logger import get_logger

log = get_logger("events_route")

router = APIRouter()


# ---------------------------------------------------------------------------
# Enums — source of truth is the MITRE mapping CSV + dataset event_status values
# ---------------------------------------------------------------------------

class SeverityEnum(str, Enum):
    critical = "Critical"
    high = "High"
    medium = "Medium"
    low = "Low"


class EventStatusEnum(str, Enum):
    open = "Open"
    blocked = "Blocked"
    failed = "Failed"
    investigating = "Investigating"
    resolved = "Resolved"
    closed = "Closed"


class EventTypeEnum(str, Enum):
    brute_force = "Brute Force"
    failed_login = "Failed Login"
    file_access = "File Access"
    login_success = "Login Success"
    malware_detection = "Malware Detection"
    phishing_email = "Phishing Email"
    port_scan = "Port Scan"
    privilege_escalation = "Privilege Escalation"
    sql_injection = "SQL Injection Attempt"
    usb_device = "USB Device Connected"


class EventInput(BaseModel):
    """Schema for creating a new security event.

    Validated fields (HTTP 422 returned on invalid values):
    - severity: Critical | High | Medium | Low
    - event_status: Open | Blocked | Failed | Investigating | Resolved | Closed
    - event_type: one of the 10 known event types mapped in mitre_attack_mapping
    """
    event_id: Optional[str] = None          # auto-generated as EVT######  if omitted
    timestamp: str                           # ISO-8601 string, e.g. "2025-08-03 08:10:00"
    source_ip: str
    destination_ip: str
    username: str
    event_type: EventTypeEnum               # validated against known MITRE-mapped types
    protocol: str
    source_country: str
    destination_country: str
    device_name: str
    os: str
    event_status: EventStatusEnum           # validated against known status values
    severity: SeverityEnum                  # validated: Critical | High | Medium | Low
    failed_login_attempts: int = 0
    malware_detected: str = "No"
    vulnerability_id: Optional[str] = None
    cvss_score: float = 0.0
    asset_name: str
    department: str


def _row_to_event(row) -> Event:
    mitre = store.mitre_for(row["event_type"]) or {
        "mitre_id": "N/A", "technique_name": "Unclassified", "tactic": "Unclassified"
    }
    mitre_id = mitre.get("mitre_id") or mitre.get("technique_id") or "N/A"
    mitre_technique = mitre.get("technique_name") or "Unclassified"
    mitre_tactic = mitre.get("tactic") or "Unclassified"
    ts = pd.to_datetime(row["timestamp"])
    return Event(
        id=row["event_id"],
        timestamp=ts.isoformat(),
        time=ts.strftime("%b %d, %H:%M"),
        eventType=row["event_type"],
        severity=row["severity"],
        sourceIP=row["source_ip"],
        destIP=row["destination_ip"],
        department=row["department"],
        status=row["event_status"],
        mitre=MitreInfo(
            id=mitre_id, technique=mitre_technique, tactic=mitre_tactic
        ),
        riskScore=risk_score_for(row["event_id"], row["severity"]),
    )


@router.get("/events", response_model=list[Event])
def get_events(
    severity: Optional[str] = Query(None, description="Filter by severity: Critical/High/Medium/Low"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    limit: int = Query(500, ge=1, le=5000, description="Max rows to return"),
):
    """Returns processed security events, queried live from MongoDB on every call —
    a POST'd event shows up here immediately, no restart needed. Matches the project
    doc's GET /events spec, with optional filtering."""
    df = store.query_events(severity=severity, event_type=event_type, limit=limit)
    if df.empty:
        return []
    return [_row_to_event(row) for _, row in df.iterrows()]


@router.post("/events", response_model=dict, status_code=status.HTTP_201_CREATED)
def create_event(event: EventInput):
    """Insert a new security event into MongoDB.

    **Validated fields** — HTTP 422 is returned automatically by FastAPI/Pydantic if an
    invalid value is supplied:
    - `severity`: `Critical` | `High` | `Medium` | `Low`
    - `event_status`: `Open` | `Blocked` | `Failed` | `Investigating` | `Resolved` | `Closed`
    - `event_type`: `Brute Force` | `Failed Login` | `File Access` | `Login Success` |
      `Malware Detection` | `Phishing Email` | `Port Scan` | `Privilege Escalation` |
      `SQL Injection Attempt` | `USB Device Connected`

    `event_id` is auto-generated as `EVT######` if omitted.
    """
    # Store the string value of each enum (not the enum member itself)
    event_dict = event.model_dump(exclude_none=True)
    event_dict["event_type"] = event.event_type.value
    event_dict["event_status"] = event.event_status.value
    event_dict["severity"] = event.severity.value

    try:
        event_id = store.insert_event(event_dict)
        log.info(f"Inserted new event: {event_id}")
        return {"status": "created", "event_id": event_id}
    except Exception as e:
        log.error(f"Failed to insert event: {e}")
        raise HTTPException(status_code=500, detail="Failed to insert event")


@router.get("/events/{event_id}", response_model=Event, summary="Get Single Security Event by ID")
def get_single_event(event_id: str):
    """
    Retrieve an individual security event by its event_id with full MITRE ATT&CK mapping
    and risk score, enabling investigation drill-down down to individual telemetry events.
    """
    from database.mongo_db import mongo
    coll = mongo.get_database()["security_events"]
    doc = coll.find_one({"event_id": event_id.strip()}, {"_id": 0})
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security event '{event_id}' not found.",
        )
    return _row_to_event(doc)
