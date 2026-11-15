#!/usr/bin/env bash
# ==============================================================================
# Deploy Script for DevSecOps Analyzer on Azure VM
# This script is executed on the Azure VM by Jenkins or standalone.
# ==============================================================================

set -euo pipefail

DEPLOY_DIR="${1:-/opt/devsecops-analyzer}"
IMAGE_NAME="${2:-devsecops-analyzer}"
IMAGE_TAG="${3:-latest}"
ACR_REGISTRY="${4:-}"
ACR_USER="${5:-}"
ACR_PASSWORD="${6:-}"

echo "=========================================================="
echo " Starting deployment of ${IMAGE_NAME}:${IMAGE_TAG}"
echo " Deployment Directory: ${DEPLOY_DIR}"
echo " Timestamp: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "=========================================================="

# Create deployment directory if not exists
mkdir -p "${DEPLOY_DIR}"
cd "${DEPLOY_DIR}"

# Login to Azure Container Registry if credentials provided
if [ -n "${ACR_REGISTRY}" ] && [ -n "${ACR_USER}" ] && [ -n "${ACR_PASSWORD}" ]; then
    echo "Logging into Azure Container Registry: ${ACR_REGISTRY}..."
    echo "${ACR_PASSWORD}" | docker login "${ACR_REGISTRY}" -u "${ACR_USER}" --password-stdin
fi

# Detect docker compose command (support both 'docker compose' and 'docker-compose')
if docker compose version >/dev/null 2>&1; then
    DOCKER_COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    DOCKER_COMPOSE="docker-compose"
else
    echo "ERROR: Neither 'docker compose' nor 'docker-compose' found on target VM."
    exit 1
fi

echo "Using compose command: ${DOCKER_COMPOSE}"

# Create/Update .env file for docker-compose
cat <<EOF > "${DEPLOY_DIR}/.env"
IMAGE_NAME=${IMAGE_NAME}
IMAGE_TAG=${IMAGE_TAG}
PYTHONUNBUFFERED=1
EOF

# Ensure SQLite database file exists with correct permissions
touch "${DEPLOY_DIR}/devsecops.db"
chmod 666 "${DEPLOY_DIR}/devsecops.db"

# Pull new image
echo "Pulling latest Docker image: ${IMAGE_NAME}:${IMAGE_TAG}..."
${DOCKER_COMPOSE} pull

# Recreate container with zero or minimal downtime
echo "Recreating and launching container..."
${DOCKER_COMPOSE} up -d --remove-orphans --force-recreate

# Wait for container startup and health check
echo "Waiting for service to become healthy..."
MAX_ATTEMPTS=15
ATTEMPT=1
SERVER_HEALTHY=0

while [ ${ATTEMPT} -le ${MAX_ATTEMPTS} ]; do
    HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8000/" || echo "000")
    if [ "${HTTP_STATUS}" -eq 200 ]; then
        echo "Health check passed! HTTP ${HTTP_STATUS} OK (Attempt ${ATTEMPT})"
        SERVER_HEALTHY=1
        break
    else
        echo "Waiting for app to respond... Attempt ${ATTEMPT}/${MAX_ATTEMPTS} (Status: ${HTTP_STATUS})"
        sleep 3
        ATTEMPT=$((ATTEMPT + 1))
    fi
done

if [ ${SERVER_HEALTHY} -ne 1 ]; then
    echo "ERROR: Deployment failed health check! Container logs:"
    ${DOCKER_COMPOSE} logs --tail=50
    exit 1
fi

# Prune old dangling images to conserve VM disk space
echo "Pruning dangling docker images..."
docker image prune -f || true

echo "=========================================================="
echo " Deployment SUCCESSFUL! DevSecOps Analyzer is running."
echo "=========================================================="
