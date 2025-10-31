"""
Kafka consumer module for the SENTRIX LIVE++ platform.
Consumes security events from Kafka topics and processes them.
"""
import asyncio
import json
import logging
from typing import Dict, Any, List, Callable, Awaitable
from confluent_kafka import Consumer, KafkaError, KafkaException
from elasticsearch import Elasticsearch

from backend.core.config import settings
from backend.core.db import es_client, EVENT_INDEX
from backend.core.ws import manager, sse_manager
from backend.stream.parsers_suricata import parse_suricata_event
from backend.stream.parsers_zeek import parse_zeek_event
from backend.stream.parsers_syslog import parse_syslog_event

logger = logging.getLogger(__name__)

# Parser mapping
PARSER_MAPPING = {
    settings.kafka.KAFKA_TOPIC_NETWORK: parse_suricata_event,
    f"{settings.kafka.KAFKA_TOPIC_NETWORK}-zeek": parse_zeek_event,
    settings.kafka.KAFKA_TOPIC_AUTH: parse_syslog_event,
    # Add more parsers as needed
}


class KafkaEventConsumer:
    """Kafka event consumer for security events."""
    
    def __init__(self, topics: List[str], group_id: str = "sentrix-consumer"):
        """Initialize the Kafka consumer."""
        self.topics = topics
        self.group_id = group_id
        self.consumer = None
        self.running = False
        self.callbacks = []
    
    def add_callback(self, callback: Callable[[Dict[str, Any]], Awaitable[None]]):
        """Add a callback function to be called for each event."""
        self.callbacks.append(callback)
    
    async def start(self):
        """Start consuming events."""
        self.running = True
        
        # Create consumer in a separate thread
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._consume)
    
    def stop(self):
        """Stop consuming events."""
        self.running = False
    
    def _consume(self):
        """Consume events from Kafka topics."""
        # Create consumer
        self.consumer = Consumer({
            'bootstrap.servers': settings.kafka.KAFKA_BOOTSTRAP_SERVERS,
            'group.id': self.group_id,
            'auto.offset.reset': 'earliest',
            'enable.auto.commit': True,
        })
        
        # Subscribe to topics
        self.consumer.subscribe(self.topics)
        
        try:
            while self.running:
                # Poll for messages
                msg = self.consumer.poll(timeout=1.0)
                
                if msg is None:
                    continue
                
                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        # End of partition event
                        logger.debug(f"Reached end of partition {msg.topic()}/{msg.partition()}")
                    else:
                        # Error
                        logger.error(f"Error consuming from Kafka: {msg.error()}")
                    continue
                
                # Process message
                try:
                    # Parse message value
                    value = msg.value().decode('utf-8')
                    data = json.loads(value)
                    
                    # Get parser for topic
                    parser = PARSER_MAPPING.get(msg.topic())
                    
                    if parser:
                        # Parse event
                        event = parser(data)
                        
                        # Index event to Elasticsearch
                        asyncio.run_coroutine_threadsafe(
                            self._index_event(event),
                            asyncio.get_event_loop()
                        )
                        
                        # Call callbacks
                        for callback in self.callbacks:
                            asyncio.run_coroutine_threadsafe(
                                callback(event),
                                asyncio.get_event_loop()
                            )
                    else:
                        logger.warning(f"No parser found for topic {msg.topic()}")
                
                except Exception as e:
                    logger.error(f"Error processing message: {e}")
        
        except KafkaException as e:
            logger.error(f"Kafka exception: {e}")
        
        finally:
            # Close consumer
            self.consumer.close()
    
    async def _index_event(self, event: Dict[str, Any]):
        """Index an event to Elasticsearch."""
        try:
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: es_client.index(index=EVENT_INDEX, body=event)
            )
        except Exception as e:
            logger.error(f"Error indexing event to Elasticsearch: {e}")


# Callback functions
async def broadcast_event(event: Dict[str, Any]):
    """Broadcast an event to WebSocket and SSE clients."""
    # Broadcast to WebSocket clients
    topic = f"events.{event.get('event_type', 'unknown')}"
    await manager.broadcast(topic, {
        "type": "event",
        "data": event
    })
    
    # Broadcast to SSE clients
    await sse_manager.broadcast_event("event", event)


# Create Kafka consumer instance
kafka_consumer = KafkaEventConsumer([
    settings.kafka.KAFKA_TOPIC_NETWORK,
    f"{settings.kafka.KAFKA_TOPIC_NETWORK}-zeek",
    settings.kafka.KAFKA_TOPIC_AUTH,
    settings.kafka.KAFKA_TOPIC_APP,
    settings.kafka.KAFKA_TOPIC_EDR,
])

# Add callbacks
kafka_consumer.add_callback(broadcast_event)


async def start_kafka_consumer():
    """Start the Kafka consumer."""
    await kafka_consumer.start()


def stop_kafka_consumer():
    """Stop the Kafka consumer."""
    kafka_consumer.stop()