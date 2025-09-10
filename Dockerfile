# Multi-stage build for MyProxy Network Gateway
# Compatible with both x86_64 (development) and ARM64 (Raspberry Pi)

FROM python:3.10-slim as base

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    net-tools \
    iproute2 \
    iptables \
    curl \
    sqlite3 \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Create app user (non-root for security)
RUN groupadd -r myproxy && useradd -r -g myproxy -d /app -s /bin/bash myproxy

# Set working directory
WORKDIR /app

# Copy requirements first (for better layer caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Create data directory and set permissions
RUN mkdir -p /app/data && chown -R myproxy:myproxy /app

# Copy application code
COPY src/ ./src/

# Set ownership after copying
RUN chown -R myproxy:myproxy /app

# Create volumes for persistence
VOLUME ["/app/data"]

# Expose ports
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Switch to non-root user
USER myproxy

# Environment variables
ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1
ENV MYPROXY_DATABASE_URL=sqlite+aiosqlite:///app/data/myproxy.db
ENV MYPROXY_DEBUG=false
ENV MYPROXY_WEB_HOST=0.0.0.0
ENV MYPROXY_WEB_PORT=8080

# Create entrypoint script for network gateway mode
USER root
RUN echo '#!/bin/bash\n\
# Fix permissions for mounted volumes\n\
mkdir -p /app/data\n\
chown -R myproxy:myproxy /app/data\n\
# For transparent proxy mode, we need to run as root to use iptables\n\
# This is required for network traffic filtering capabilities\n\
echo "Starting MyProxy in transparent gateway mode (requires root for iptables)"\n\
exec "$@"' > /app/entrypoint.sh && chmod +x /app/entrypoint.sh

# Install gosu for proper user switching (keep for potential future use)
RUN apt-get update && apt-get install -y gosu sudo && rm -rf /var/lib/apt/lists/*

# For network gateway mode, run as root to enable iptables functionality
USER root

# Start command with entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["python", "src/main.py"]