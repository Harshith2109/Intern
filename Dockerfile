# Multi-stage Docker build for DevSecOps Dependency Risk Analyzer
FROM python:3.11-slim

# Install system dependencies & git
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install Aqua Security Trivy CLI from official image
COPY --from=aquasec/trivy:0.50.0 /usr/local/bin/trivy /usr/local/bin/trivy

WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt pytest httpx

# Copy project files
COPY . .

# Expose FastAPI web server port
EXPOSE 8000

# Run Uvicorn production server
CMD ["python", "-m", "uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
