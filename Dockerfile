# Multi-stage Dockerfile for AI Log Troubleshooter
# Stage 1: build dependencies in a slim python image
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# System deps (for opensearch-py, cryptography, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    wget \
    ca-certificates \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --upgrade pip && pip wheel --no-cache-dir --no-deps -r requirements.txt -w /wheels

# Stage 2: runtime
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    STREAMLIT_SERVER_PORT=8501 \
    PIP_NO_CACHE_DIR=1

# Add non-root user
RUN useradd -ms /bin/bash appuser
WORKDIR /app

# Install runtime system libs (lightweight)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Copy wheels and install
COPY --from=builder /wheels /wheels
COPY requirements.txt ./
RUN pip install --no-cache-dir /wheels/* && rm -rf /wheels

# Copy application code
COPY Pega_Log_Troubleshooter.py ./
COPY styles.css ./
COPY alamaticz_logo.png ./

# Expose Streamlit port
EXPOSE 8501

# Create a healthcheck endpoint via Streamlit's network response
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD wget -qO- http://localhost:8501/_stcore/health || exit 1

USER appuser

# Default command
CMD ["streamlit", "run", "Pega_Log_Troubleshooter.py", "--server.port=8501", "--server.address=0.0.0.0"]
