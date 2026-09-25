# Multi-stage Docker build for DevSecOps Dependency Risk Analyzer
FROM python:3.11-slim

# Install system dependencies & git
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install Aqua Security Trivy CLI
RUN wget -qO- https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.50.0

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
