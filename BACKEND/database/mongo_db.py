"""
MongoDB connection manager. Handles startup, connection pooling, and graceful shutdown.
For Milestone 1, we default to localhost:27017 (single node). Can be extended to
replica sets or Atlas in production.
"""
import os
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from contextlib import asynccontextmanager

from utils.logger import get_logger

log = get_logger("mongo_db")


class MongoDatabase:
    def __init__(self):
        self.client: MongoClient | None = None
        self.db = None
        self._connected = False

    def connect(self):
        """Establish connection to MongoDB. Called once at app startup."""
        mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017")
        timeout_ms = int(os.getenv("MONGO_TIMEOUT_MS", "5000"))

        try:
            self.client = MongoClient(
                mongo_uri,
                serverSelectionTimeoutMS=timeout_ms,
                connectTimeoutMS=timeout_ms,
            )
            # Force a connection attempt right away (will raise if server unavailable)
            self.client.admin.command("ping")
            self.db = self.client["threat_detection"]
            self._connected = True
            log.info(f"Connected to MongoDB: {mongo_uri}")
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            log.error(f"Failed to connect to MongoDB at {mongo_uri}: {e}")
            self._connected = False
            raise RuntimeError(
                f"Could not connect to MongoDB at {mongo_uri}. "
                f"Make sure MongoDB is running (docker-compose up, or mongod locally), "
                f"or set MONGO_URI to a valid connection string."
            ) from e

    def disconnect(self):
        """Close the connection. Called at app shutdown."""
        if self.client:
            self.client.close()
            self._connected = False
            log.info("Disconnected from MongoDB")

    @property
    def connected(self) -> bool:
        return self._connected

    def get_collection(self, name: str):
        """Get or create a collection."""
        if not self._connected:
            raise RuntimeError("Not connected to MongoDB")
        return self.db[name]

    def get_database(self):
        """Get the database object for direct access."""
        if not self._connected:
            raise RuntimeError("Not connected to MongoDB")
        return self.db


# single shared instance
mongo = MongoDatabase()
