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

# Copy application code (entrypoint.sh is excluded via .dockerignore)
COPY . .

# Create entrypoint script directly in Dockerfile to avoid permission/line ending issues
RUN cat > /app/entrypoint.sh << 'EOFSCRIPT' && \
    chmod +x /app/entrypoint.sh
#!/bin/bash
set -e

# Create ClamAV directories and set permissions
mkdir -p /var/lib/clamav /var/run/clamav
chown -R clamav:clamav /var/lib/clamav /var/run/clamav

# Create minimal ClamAV daemon config if it doesn't exist
if [ ! -f /etc/clamav/clamd.conf ]; then
    mkdir -p /etc/clamav
    cat > /etc/clamav/clamd.conf << EOF
LocalSocket /var/run/clamav/clamd.sock
TCPSocket 3310
TCPAddr 127.0.0.1
User clamav
AllowSupplementaryGroups
ScanPE
ScanELF
ScanOLE2
ScanPDF
ScanHTML
ScanMail
ScanArchive
ArchiveBlockEncrypted
EOF
fi

# Update ClamAV database (non-blocking, in background)
echo "Updating ClamAV virus database in background..."
freshclam -d || true &

# Wait a bit for initial database check
sleep 5

# Start ClamAV daemon in background
echo "Starting ClamAV daemon..."
clamd &

# Wait for ClamAV daemon to be ready
echo "Waiting for ClamAV daemon to be ready..."
for i in {1..30}; do
    if nc -z localhost 3310 2>/dev/null; then
        echo "ClamAV daemon is ready"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "Warning: ClamAV daemon did not start in time, continuing anyway..."
    fi
    sleep 1
done

# Start the FastAPI application
echo "Starting FastAPI application..."
exec uvicorn main:app --host 0.0.0.0 --port 8000
EOFSCRIPT

# Create upload directory
RUN mkdir -p /tmp/securelens_uploads

# Install netcat for healthcheck
RUN apt-get update && apt-get install -y netcat-openbsd && rm -rf /var/lib/apt/lists/*

# Expose port
EXPOSE 8000

# Use entrypoint script to start both ClamAV and FastAPI
ENTRYPOINT ["/app/entrypoint.sh"]

