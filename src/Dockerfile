# Production Dockerfile for SMB Lock Manager v2.0
# Includes performance improvements for 60k+ locks

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY async_main.py .
COPY templates/ ./templates/

# Create directory for config
RUN mkdir -p /usr/app

# Expose application port
EXPOSE 4000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import requests; requests.get('http://localhost:4000/')" || exit 1

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Run application with 4 workers (adjust based on CPU)
CMD ["hypercorn", "async_main:app", "--workers", "4", "--bind", "0.0.0.0:4000"]
