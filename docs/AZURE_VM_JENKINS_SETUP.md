# 🚀 Jenkins CI/CD Pipeline to Azure VM Setup Guide

This guide walks you through setting up and running the automated Jenkins pipeline to build, test, and deploy the **DevSecOps Dependency Risk Analyzer** to an **Azure Virtual Machine (Ubuntu Linux)**.

---

## 📋 Architecture & Flow

```
[Git Commit] 
     │
     ▼
[Jenkins Pipeline]
  ├── 1. Run Unit Tests (pytest)
  ├── 2. Build Docker Image
  ├── 3. DevSecOps Security Gate (Trivy Scan)
  ├── 4. Push to Azure Container Registry (ACR)
  ├── 5. SSH to Azure VM & Execute docker-compose
  └── 6. Health Check Smoke Test (HTTP 200)
     │
     ▼
[Azure VM (Ubuntu)]
  └── Docker Compose running FastAPI & Dashboard on port 8000
```

---

## 🛠️ Step 1: Azure VM & Network Security Group (NSG) Configuration

### 1.1 Create the Azure VM
If not already created, you can launch an Ubuntu 22.04 or 24.04 LTS VM in the Azure Portal or via Azure CLI:
```bash
az vm create \
  --resource-group rg-devsecops \
  --name vm-devsecops-analyzer \
  --image Ubuntu2204 \
  --admin-username azureuser \
  --generate-ssh-keys \
  --public-ip-sku Standard
```

### 1.2 Open Inbound Ports in Azure Network Security Group (NSG)
Your Azure VM needs:
* **Port 22 (SSH)**: For Jenkins to connect and deploy.
* **Port 8000 (HTTP)**: For accessing the FastAPI web dashboard.

Run the following Azure CLI command to open port 8000:
```bash
az vm open-port \
  --resource-group rg-devsecops \
  --name vm-devsecops-analyzer \
  --port 8000 \
  --priority 1010
```

### 1.3 One-Time Initialization on Azure VM
SSH into your Azure VM and run the setup script:
```bash
# From your local machine:
ssh azureuser@<AZURE_VM_PUBLIC_IP>

# On the Azure VM:
curl -sSL https://raw.githubusercontent.com/<YOUR_REPO>/main/deploy/azure-vm-setup.sh | bash
# OR copy deploy/azure-vm-setup.sh to the VM and run:
bash deploy/azure-vm-setup.sh
```
*This installs Docker, Docker Compose, sets up the `/opt/devsecops-analyzer` directory, and adds `azureuser` to the `docker` group.*

---

## 📦 Step 2: Azure Container Registry (ACR) Setup

If you don't have an ACR registry yet:
```bash
# 1. Create ACR
az acr create \
  --resource-group rg-devsecops \
  --name acrdevsecops$RANDOM \
  --sku Basic \
  --admin-enabled true

# 2. Retrieve Login Credentials
az acr credential show --name <YOUR_ACR_NAME>
```
*Note down:*
* **Login Server**: `<YOUR_ACR_NAME>.azurecr.io`
* **Username**: `<YOUR_ACR_NAME>`
* **Password**: `<ACR_PASSWORD>`

---

## ⚙️ Step 3: Configure Jenkins

### 3.1 Required Jenkins Plugins
In Jenkins, navigate to **Manage Jenkins > Plugins > Available plugins** and ensure these are installed:
1. **Pipeline** (workflow-aggregator)
2. **SSH Agent Plugin** (`ssh-agent`)
3. **Credentials Binding Plugin**
4. **Docker Pipeline Plugin**
5. **AnsiColor Plugin** (optional, for colorized build logs)

### 3.2 Add Credentials in Jenkins
Navigate to **Manage Jenkins > Credentials > System > Global credentials > Add Credentials**:

| Credential ID | Kind | Value / Details |
|---|---|---|
| `azure-vm-ssh-key` | **SSH Username with private key** | Username: `azureuser`<br>Private Key: Enter directly or upload the `.pem`/private key used to access your Azure VM. |
| `azure-acr-credentials` | **Username with password** | Username: ACR Admin username<br>Password: ACR Password |
| `ACR_REGISTRY_HOST` | **Secret text** | Value: `<YOUR_ACR_NAME>.azurecr.io` (e.g. `myacr.azurecr.io`) |
| `AZURE_VM_IP` | **Secret text** | Value: Public IP address of your Azure VM |

---

## 🚀 Step 4: Create the Jenkins Pipeline Job

1. In Jenkins, click **New Item**.
2. Enter name: `devsecops-risk-analyzer`.
3. Select **Pipeline** and click **OK**.
4. In the job configuration:
   * Under **Pipeline**, set **Definition** to `Pipeline script from SCM`.
   * **SCM**: `Git`
   * **Repository URL**: Your Git repo URL (e.g. `https://github.com/<user>/<repo>.git`).
   * **Credentials**: Add your Git credentials if private.
   * **Branch Specifier**: `*/main` (or `*/master`).
   * **Script Path**: `Jenkinsfile`.
5. Click **Save**.

---

## ▶️ Step 5: Run the Pipeline

1. Click **Build with Parameters** in your Jenkins job.
2. Review the parameters:
   * `AZURE_VM_HOST`: (Optional override if different from `AZURE_VM_IP`).
   * `RUN_TESTS`: `true`
   * `RUN_SECURITY_SCAN`: `true`
   * `FAIL_ON_VULNERABILITY`: `false` (set `true` to enforce strict DevSecOps blocking).
3. Click **Build**.
4. Watch the pipeline stages:
   * `Checkout SCM` ➔ `Run Unit Tests` ➔ `Build Docker Image` ➔ `Trivy Scan` ➔ `Push to ACR` ➔ `Deploy to Azure VM` ➔ `Post-Deployment Smoke Test`.

---

## 🌐 Step 6: Access the Application

Once the pipeline completes:
* Open your browser and navigate to:
  ```
  http://<AZURE_VM_PUBLIC_IP>:8000/
  ```
* You should see the live **DevSecOps Dependency Risk Analyzer Dashboard** running!
* The Swagger API documentation is available at:
  ```
  http://<AZURE_VM_PUBLIC_IP>:8000/docs
  ```

---

## 🔍 Troubleshooting & Maintenance

* **Check container status on Azure VM:**
  ```bash
  ssh azureuser@<AZURE_VM_PUBLIC_IP>
  cd /opt/devsecops-analyzer
  docker compose ps
  docker compose logs -f
  ```
* **Restart the application manually:**
  ```bash
  docker compose down && docker compose up -d
  ```
* **Verify database persistence:**
  The SQLite database file is persisted at `/opt/devsecops-analyzer/devsecops.db` and preserved across container restarts and new deployments.
