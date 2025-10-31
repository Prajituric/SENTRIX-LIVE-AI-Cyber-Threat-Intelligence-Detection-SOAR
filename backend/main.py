"""
Main FastAPI application for the SENTRIX LIVE++ platform.
"""
import asyncio
import logging
import uuid
from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from backend.core.config import settings
from backend.core.db import get_db, init_db
from backend.core.auth import get_current_active_user, get_admin_user, get_analyst_user, get_viewer_user
from backend.core.ws import websocket_endpoint, sse_endpoint
from backend.stream.kafka_consumer import start_kafka_consumer, stop_kafka_consumer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="SENTRIX LIVE++",
    description="AI Cyber Threat Intelligence, Detection & SOAR Platform",
    version="1.0.0",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.api.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Startup and shutdown events
@app.on_event("startup")
async def startup_event():
    """Initialize the application on startup."""
    # Initialize database
    init_db()
    
    # Start Kafka consumer
    await start_kafka_consumer()
    
    logger.info("SENTRIX LIVE++ platform started")


@app.on_event("shutdown")
def shutdown_event():
    """Clean up resources on shutdown."""
    # Stop Kafka consumer
    stop_kafka_consumer()
    
    logger.info("SENTRIX LIVE++ platform stopped")


# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok"}


# WebSocket endpoint
@app.websocket("/ws/{client_id}")
async def websocket_route(websocket: WebSocket, client_id: str):
    """WebSocket endpoint for real-time updates."""
    if not client_id:
        client_id = str(uuid.uuid4())
    await websocket_endpoint(websocket, client_id)


# Server-Sent Events endpoint
@app.get("/sse/{client_id}")
async def sse_route(client_id: str):
    """Server-Sent Events endpoint for real-time updates."""
    if not client_id:
        client_id = str(uuid.uuid4())
    
    return StreamingResponse(
        sse_endpoint(client_id),
        media_type="text/event-stream"
    )


# Include API routers
# These will be implemented in separate files
from backend.api.routes import auth, alerts, search, soar, cti, evals, streams

app.include_router(auth.router, prefix="/auth", tags=["Authentication"])
app.include_router(alerts.router, prefix="/alerts", tags=["Alerts"])
app.include_router(search.router, prefix="/search", tags=["Search"])
app.include_router(soar.router, prefix="/soar", tags=["SOAR"])
app.include_router(cti.router, prefix="/cti", tags=["CTI"])
app.include_router(evals.router, prefix="/evals", tags=["Evaluations"])
app.include_router(streams.router, prefix="/streams", tags=["Streams"])


# Main entry point
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.api.API_HOST,
        port=settings.api.API_PORT,
        reload=settings.DEBUG
    )