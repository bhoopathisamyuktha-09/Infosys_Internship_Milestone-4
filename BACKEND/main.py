"""
SentinelAI — Creation of Security Operations Dashboard for Threat Detection with Risk Mitigation Analytics
Backend API (Milestones 1–4)

Preferred start:
    python run.py

Alternative (manual uvicorn):
    uvicorn main:app --reload --port 8000

Interactive docs at http://localhost:8000/docs once running.
"""
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

load_dotenv()  # picks up MONGO_URI etc. from .env if present

from services.data_store import store
from routes import (
    events,
    stats,
    threats,
    threat_intel,
    vulnerabilities,
    prediction_routes,
    risk_routes,
    incident_routes,
    dashboard_routes,
    report_routes,
)
from database.mongo_db import mongo
from database.seeder import seed_if_empty, seed_predictions_if_empty, seed_incidents_if_empty
from database.prediction_store import ensure_indexes
from database.incident_repository import ensure_incident_indexes
from utils.logger import get_logger

log = get_logger("threat_dashboard")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan handler — runs once at startup and once at shutdown."""
    # 1. Connect to MongoDB (raises RuntimeError with a clear message if unreachable)
    mongo.connect()

    # 2. Auto-seed: imports all datasets on first run; no-op on subsequent runs.
    #    seed_if_empty() raises RuntimeError on any failure, which prevents the
    #    server from completing startup with a broken/partial database.
    seed_if_empty(mongo.get_database())
    
    # 2b. Auto-seed M2 predictions if empty (handles fresh Docker volumes)
    seed_predictions_if_empty(mongo.get_database())

    # 2c. Auto-seed M3 incidents if empty
    seed_incidents_if_empty(mongo.get_database())

    # 3. Ensure MongoDB indexes for threat_predictions and incidents collections
    ensure_indexes()
    ensure_incident_indexes()

    # 4. Cache the static MITRE mapping in memory (10 rows, never written to)
    store.load()

    # 5. Load production ML model artifacts into memory singletons
    from ml.model_loader import get_loaded_models
    get_loaded_models()

    yield

    # Shutdown: close the MongoDB connection
    mongo.disconnect()


app = FastAPI(
    title="SentinelAI — Creation of Security Operations Dashboard for Threat Detection with Risk Mitigation Analytics",
    description="Backend API for SentinelAI: Creation of Security Operations Dashboard for Threat Detection with Risk Mitigation Analytics (Milestones 1–4)",
    version="4.0.0",
    lifespan=lifespan,
)

# CORS: allows the React frontend (running on a different port, e.g. 5173) to call this API.
# Origins are configurable via CORS_ORIGINS (comma-separated) so you don't have to edit code
# to add your deployed frontend's URL — defaults cover the common local dev setups.
import os
default_origins = "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173"
cors_origins = [o.strip() for o in os.getenv("CORS_ORIGINS", default_origins).split(",")]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

app.include_router(events.router, tags=["Events"])
app.include_router(stats.router, tags=["Stats"])
app.include_router(threats.router, tags=["Threats"])
app.include_router(threat_intel.router, tags=["Threat Intelligence"])
app.include_router(vulnerabilities.router, tags=["Vulnerabilities"])
app.include_router(prediction_routes.router, tags=["Predictions"])
app.include_router(risk_routes.router)
app.include_router(incident_routes.router)
app.include_router(dashboard_routes.router)
app.include_router(report_routes.router)


@app.get("/", tags=["Health"])
def root():
    return {"status": "ok", "message": "Threat Detection Dashboard API is running"}


@app.get("/health", tags=["Health"])
def health():
    return {"status": "ok", "data_loaded": store.loaded}
