"""
WebSocket and Server-Sent Events (SSE) module for the SENTRIX LIVE++ platform.
Handles real-time streaming of alerts and events to the frontend.
"""
import asyncio
import json
import logging
from typing import Dict, List, Any, Callable, Awaitable
from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)


class ConnectionManager:
    """WebSocket connection manager."""
    
    def __init__(self):
        # Active connections: {client_id: {"websocket": websocket, "subscriptions": [topics]}}
        self.active_connections: Dict[str, Dict[str, Any]] = {}
        # Topic subscribers: {topic: [client_ids]}
        self.topic_subscribers: Dict[str, List[str]] = {}
    
    async def connect(self, websocket: WebSocket, client_id: str):
        """Connect a client."""
        await websocket.accept()
        self.active_connections[client_id] = {
            "websocket": websocket,
            "subscriptions": []
        }
        logger.info(f"Client {client_id} connected")
    
    def disconnect(self, client_id: str):
        """Disconnect a client."""
        if client_id in self.active_connections:
            # Remove client from all topic subscriptions
            for topic in self.topic_subscribers:
                if client_id in self.topic_subscribers[topic]:
                    self.topic_subscribers[topic].remove(client_id)
            
            # Remove client from active connections
            del self.active_connections[client_id]
            logger.info(f"Client {client_id} disconnected")
    
    def subscribe(self, client_id: str, topic: str):
        """Subscribe a client to a topic."""
        if client_id not in self.active_connections:
            logger.warning(f"Cannot subscribe non-existent client {client_id} to topic {topic}")
            return
        
        # Add topic to client subscriptions
        if topic not in self.active_connections[client_id]["subscriptions"]:
            self.active_connections[client_id]["subscriptions"].append(topic)
        
        # Add client to topic subscribers
        if topic not in self.topic_subscribers:
            self.topic_subscribers[topic] = []
        if client_id not in self.topic_subscribers[topic]:
            self.topic_subscribers[topic].append(client_id)
        
        logger.info(f"Client {client_id} subscribed to topic {topic}")
    
    def unsubscribe(self, client_id: str, topic: str):
        """Unsubscribe a client from a topic."""
        if client_id not in self.active_connections:
            return
        
        # Remove topic from client subscriptions
        if topic in self.active_connections[client_id]["subscriptions"]:
            self.active_connections[client_id]["subscriptions"].remove(topic)
        
        # Remove client from topic subscribers
        if topic in self.topic_subscribers and client_id in self.topic_subscribers[topic]:
            self.topic_subscribers[topic].remove(client_id)
        
        logger.info(f"Client {client_id} unsubscribed from topic {topic}")
    
    async def broadcast(self, topic: str, message: Dict[str, Any]):
        """Broadcast a message to all subscribers of a topic."""
        if topic not in self.topic_subscribers:
            return
        
        # Convert message to JSON
        json_message = json.dumps(message)
        
        # Send message to all subscribers
        for client_id in self.topic_subscribers[topic]:
            if client_id in self.active_connections:
                try:
                    await self.active_connections[client_id]["websocket"].send_text(json_message)
                except Exception as e:
                    logger.error(f"Error sending message to client {client_id}: {e}")
                    # Don't disconnect here, let the connection handler handle it
    
    async def send_personal_message(self, client_id: str, message: Dict[str, Any]):
        """Send a message to a specific client."""
        if client_id not in self.active_connections:
            return
        
        # Convert message to JSON
        json_message = json.dumps(message)
        
        # Send message to client
        try:
            await self.active_connections[client_id]["websocket"].send_text(json_message)
        except Exception as e:
            logger.error(f"Error sending personal message to client {client_id}: {e}")


# Global connection manager instance
manager = ConnectionManager()


class SSEManager:
    """Server-Sent Events (SSE) manager."""
    
    def __init__(self):
        # Event queues for each client: {client_id: asyncio.Queue}
        self.event_queues: Dict[str, asyncio.Queue] = {}
    
    def connect(self, client_id: str) -> asyncio.Queue:
        """Connect a client and return its event queue."""
        queue = asyncio.Queue()
        self.event_queues[client_id] = queue
        logger.info(f"SSE client {client_id} connected")
        return queue
    
    def disconnect(self, client_id: str):
        """Disconnect a client."""
        if client_id in self.event_queues:
            del self.event_queues[client_id]
            logger.info(f"SSE client {client_id} disconnected")
    
    async def send_event(self, client_id: str, event: str, data: Dict[str, Any]):
        """Send an event to a specific client."""
        if client_id not in self.event_queues:
            return
        
        # Format SSE message
        message = f"event: {event}\ndata: {json.dumps(data)}\n\n"
        
        # Add message to client's queue
        await self.event_queues[client_id].put(message)
    
    async def broadcast_event(self, event: str, data: Dict[str, Any]):
        """Broadcast an event to all connected clients."""
        # Format SSE message
        message = f"event: {event}\ndata: {json.dumps(data)}\n\n"
        
        # Add message to all client queues
        for client_id, queue in self.event_queues.items():
            await queue.put(message)


# Global SSE manager instance
sse_manager = SSEManager()


async def websocket_endpoint(websocket: WebSocket, client_id: str):
    """WebSocket endpoint handler."""
    await manager.connect(websocket, client_id)
    try:
        while True:
            # Receive and process messages from the client
            data = await websocket.receive_text()
            try:
                message = json.loads(data)
                
                # Handle subscription messages
                if message.get("type") == "subscribe" and "topic" in message:
                    manager.subscribe(client_id, message["topic"])
                
                # Handle unsubscription messages
                elif message.get("type") == "unsubscribe" and "topic" in message:
                    manager.unsubscribe(client_id, message["topic"])
                
                # Echo back other messages (for testing)
                else:
                    await manager.send_personal_message(client_id, {
                        "type": "echo",
                        "data": message
                    })
            
            except json.JSONDecodeError:
                await manager.send_personal_message(client_id, {
                    "type": "error",
                    "message": "Invalid JSON message"
                })
    
    except WebSocketDisconnect:
        manager.disconnect(client_id)
    except Exception as e:
        logger.error(f"WebSocket error for client {client_id}: {e}")
        manager.disconnect(client_id)


async def sse_endpoint(client_id: str):
    """SSE endpoint generator."""
    queue = sse_manager.connect(client_id)
    
    # Send initial connection event
    await queue.put(f"event: connected\ndata: {json.dumps({'client_id': client_id})}\n\n")
    
    try:
        while True:
            # Get the next message from the queue
            message = await queue.get()
            yield message
    
    finally:
        sse_manager.disconnect(client_id)