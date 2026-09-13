from fastapi import APIRouter

from services.data_store import store
from models.schemas import ThreatCount

router = APIRouter()


@router.get("/threats", response_model=list[ThreatCount])
def get_threats():
    """Returns event counts grouped by type, sorted descending — via a real MongoDB
    aggregation pipeline, queried live on every call. Matches the project doc's
    GET /threats spec — feeds the frontend's Top Attack Types bar chart."""
    return [ThreatCount(**row) for row in store.event_type_counts()]
