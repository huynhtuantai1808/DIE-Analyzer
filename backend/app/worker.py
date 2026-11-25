import os
import redis
from rq import Worker, Queue
from .config import REDIS_URL

redis_conn = redis.from_url(REDIS_URL)

queues = [
    Queue("die-scans", connection=redis_conn),
    Queue("default", connection=redis_conn),
]

if __name__ == "__main__":
    worker = Worker(
        queues,
        connection=redis_conn
    )
    worker.work()

