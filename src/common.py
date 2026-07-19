"""
common.py — shared helpers used by every stage of the SIEM.

Keeping this tiny and dependency-free (only `redis`) makes the pipeline easy
to read. Each stage connects to Redis, pulls from one queue, does its job,
and pushes to the next queue.

    generator  --(raw_logs)-->  collector  --(collected_logs)-->
    normalizer --(events)-->    correlator --> ALERTS on your screen

Redis is just the "conveyor belt" between the containers. In a real SIEM this
might be Kafka, a syslog receiver, or a message bus — the idea is the same.
"""
import os
import time
import json
import redis

# ---- Queue names (Redis lists act as simple FIFO queues) --------------------
Q_RAW = "raw_logs"           # generator -> collector
Q_COLLECTED = "collected"    # collector -> normalizer
Q_EVENTS = "events"          # normalizer -> correlator

# ---- ANSI colors so the console output is easy to scan ----------------------
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"
BG_RED = "\033[41m"


def connect():
    """Connect to Redis, retrying until it is ready.

    docker-compose starts all containers at once, so a stage may boot before
    Redis is accepting connections. We simply wait and retry instead of
    crashing — this keeps 'one launch and everything works' true.
    """
    host = os.environ.get("REDIS_HOST", "redis")
    while True:
        try:
            r = redis.Redis(host=host, port=6379, decode_responses=True)
            r.ping()
            return r
        except redis.exceptions.RedisError:
            print(f"{DIM}waiting for redis at {host}...{RESET}", flush=True)
            time.sleep(1)


def push(r, queue, obj):
    """Put a message (dict) onto a queue as JSON."""
    r.lpush(queue, json.dumps(obj))


def pop(r, queue, timeout=0):
    """Block until a message is available, then return it as a dict.

    Uses BRPOP so the stage sleeps while idle instead of busy-looping.
    """
    item = r.brpop(queue, timeout=timeout)
    if item is None:
        return None
    _, payload = item
    return json.loads(payload)


def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())


def banner(color, title):
    """Print a labeled startup banner for a stage."""
    line = "=" * 60
    print(f"{color}{BOLD}{line}{RESET}", flush=True)
    print(f"{color}{BOLD}  {title}{RESET}", flush=True)
    print(f"{color}{BOLD}{line}{RESET}", flush=True)
