import aio_pika
import json
from .config import settings
from .logger import setup_logger

logger = setup_logger("rabbitmq")

class RabbitMQPublisher:
    def __init__(self):
        self.connection = None
        self.channel = None

    async def connect(self):
        logger.info(f"Connecting to RabbitMQ at {settings.rabbitmq_url}")
        self.connection = await aio_pika.connect_robust(settings.rabbitmq_url)
        self.channel = await self.connection.channel()
        await self.channel.set_qos(prefetch_count=100)
        self.exchange = await self.channel.declare_exchange("briar.scan", aio_pika.ExchangeType.DIRECT, durable=True)
        logger.info("Connected to RabbitMQ successfully.")

    async def publish(self, routing_key: str, payload: dict):
        if not self.channel:
            await self.connect()
        message = aio_pika.Message(
            body=json.dumps(payload).encode(),
            delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
            headers={"content_type": "application/json"}
        )
        await self.exchange.publish(message, routing_key=routing_key)
        logger.info(f"[RabbitMQ] Published to '{routing_key}': {payload.get('event')}")

    async def close(self):
        if self.connection and not self.connection.is_closed:
            await self.connection.close()
            logger.info("RabbitMQ connection closed.")
