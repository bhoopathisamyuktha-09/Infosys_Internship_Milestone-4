"""
run.py — Simple launcher for SentinelAI: Creation of Security Operations Dashboard for Threat Detection with Risk Mitigation Analytics.

Usage:
    python run.py

Equivalent to:
    uvicorn main:app --reload --port 8000

Environment variables (set in .env or the shell before running):
    MONGO_URI        MongoDB connection string (default: mongodb://localhost:27017)
    MONGO_TIMEOUT_MS Server selection timeout in ms (default: 5000)
    CORS_ORIGINS     Comma-separated list of allowed frontend origins
    PORT             Override the listening port (default: 8000)
    HOST             Override the listening host (default: 127.0.0.1)
    RELOAD           Set to "false" to disable auto-reload in production (default: true)
"""
import os
import uvicorn
from dotenv import load_dotenv

load_dotenv()  # Load .env before reading env vars

HOST   = os.getenv("HOST",   "127.0.0.1")
PORT   = int(os.getenv("PORT", "8000"))
RELOAD = os.getenv("RELOAD", "true").lower() != "false"

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=HOST,
        port=PORT,
        reload=RELOAD,
    )
