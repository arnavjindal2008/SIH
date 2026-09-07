FROM python:3.11-slim

# Prevent interactive prompts during apt-get package installations
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Install system dependencies (Wireshark/tshark, libpcap, and build utilities)
RUN apt-get update && \
    apt-get install -y --no-install-recommends debconf-utils && \
    echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections && \
    apt-get install -y --no-install-recommends \
        tshark \
        libpcap-dev \
        gcc \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency specifications and install Python requirements
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -U pip && \
    pip install --no-cache-dir -r /app/backend/requirements.txt

# Copy backend application source code, dataset samples, and reporting templates
COPY backend /app/backend
COPY data /app/data
COPY reports /app/reports

# Ensure persistent directories exist for PCAP ingestion and PDF report generation
RUN mkdir -p /app/data/uploads /app/data/samples /app/reports/generated

# Environment configurations for module resolution and dynamic port binding
ENV PYTHONPATH=/app
ENV PORT=8000

# Expose default HTTP port
EXPOSE 8000

# Health check configuration matching Railway /api/health endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8000}/api/health || exit 1

# Launch uvicorn bound to Railway dynamic $PORT
CMD ["sh", "-c", "uvicorn backend.app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
