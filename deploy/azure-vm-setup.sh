#!/usr/bin/env bash
# ==============================================================================
# Azure VM Initial Provisioning & Setup Script
# Run this once on your newly created Ubuntu Azure VM, OR run the Azure CLI
# commands below from your local terminal to configure the VM.
# ==============================================================================

set -euo pipefail

echo "=== Initializing Azure VM for Docker & DevSecOps Analyzer ==="

# 1. Update package lists and install prerequisites
sudo apt-get update
sudo apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    git \
    ufw

# 2. Install Docker Official Repository
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# 3. Install Docker Engine and Compose Plugin
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# 4. Add current user to docker group (avoids needing sudo for docker commands)
sudo usermod -aG docker "$USER"

# 5. Create application directory
sudo mkdir -p /opt/devsecops-analyzer
sudo chown -R "$USER":"$USER" /opt/devsecops-analyzer
sudo chmod -R 775 /opt/devsecops-analyzer

# 6. Configure local UFW firewall (if enabled)
if sudo ufw status | grep -q "Status: active"; then
    echo "Opening port 22 and 8000 in UFW..."
    sudo ufw allow 22/tcp
    sudo ufw allow 8000/tcp
    sudo ufw reload
fi

echo "=========================================================="
echo " Docker installation complete!"
echo " Docker version: $(docker --version)"
echo " Compose version: $(docker compose version)"
echo ""
echo " IMPORTANT: Log out and log back in (or run 'newgrp docker')"
echo " for non-root docker permissions to take effect."
echo "=========================================================="
