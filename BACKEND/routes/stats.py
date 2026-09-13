from fastapi import APIRouter

from services.data_store import store
from services.m1_risk_scoring import risk_score_for
from models.schemas import Stats

router = APIRouter()


@router.get("/stats", response_model=Stats)
def get_stats():
    """Returns dashboard KPI numbers, queried live from MongoDB on every call.
    Matches the project doc's GET /stats spec exactly: total_events, critical_events,
    high_events — plus vulnerabilities and active_incidents for the frontend's 5 KPI
    cards, and avg_risk_score for the AI Insight panel."""
    counts = store.event_counts_by_severity()
    vulnerabilities = store.count_vulnerabilities()
    active_incidents = store.count_active_incidents()

    # only event_id + severity are pulled (not full documents) to compute the average
    id_severity_pairs = store.all_event_ids_and_severities()
    scores = [risk_score_for(r["event_id"], r["severity"]) for r in id_severity_pairs]
    avg_risk_score = round(sum(scores) / len(scores)) if scores else 0

    return Stats(
        total_events=counts["total"],
        critical_events=counts["critical"],
        high_events=counts["high"],
        vulnerabilities=vulnerabilities,
        active_incidents=active_incidents,
        avg_risk_score=avg_risk_score,
    )
