# One image is built ONCE and reused by all four Python services.
# docker-compose decides which script each container runs (see command:).
FROM python:3.12-slim

WORKDIR /app

# Install the only dependency (the Redis client) first so Docker can cache it.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the SIEM source code.
COPY src/ /app/

# -u = unbuffered output, so logs appear in `docker compose` in real time.
# Default command; each service in docker-compose.yml overrides this.
CMD ["python", "-u", "collector.py"]
