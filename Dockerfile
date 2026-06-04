# Dockerfile — OWASP API Security Scanner demo
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app/ ./app/

# Expose API port
EXPOSE 5000

# Run the vulnerable API (intentionally for testing only)
CMD ["python", "app/vulnerable_api.py"]
