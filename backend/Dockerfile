FROM python:3.10-slim

WORKDIR /app

# Install system dependencies (gcc and OpenSSL headers are required to build yara-python)
# Also install ClamAV and its daemon
RUN apt-get update && apt-get install -y \
    gcc \
    build-essential \
    libssl-dev \
    yara \
    clamav \
    clamav-daemon \
    clamav-freshclam \
    && rm -rf /var/lib/apt/lists/*

# Configure ClamAV directories
RUN mkdir -p /var/lib/clamav /var/run/clamav /etc/clamav && \
    chown -R clamav:clamav /var/lib/clamav /var/run/clamav

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy entrypoint script first with execute permission
COPY --chmod=755 entrypoint.sh /app/entrypoint.sh

# Copy rest of application code
COPY . .

# Ensure entrypoint.sh has execute permission and fix line endings (CRLF -> LF)
RUN chmod +x /app/entrypoint.sh && \
    sed -i 's/\r$//' /app/entrypoint.sh && \
    # Verify the file is executable
    ls -la /app/entrypoint.sh

# Create upload directory
RUN mkdir -p /tmp/securelens_uploads

# Install netcat for healthcheck
RUN apt-get update && apt-get install -y netcat-openbsd && rm -rf /var/lib/apt/lists/*

# Expose port
EXPOSE 8000

# Use entrypoint script to start both ClamAV and FastAPI
ENTRYPOINT ["/app/entrypoint.sh"]

