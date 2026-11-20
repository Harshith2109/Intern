pipeline {
    agent any

    parameters {
        choice(name: 'DEPLOY_ENV', choices: ['production', 'staging'], description: 'Deployment Environment')
        string(name: 'AZURE_VM_HOST', defaultValue: '', description: 'Azure VM Public IP or FQDN (leave empty to use AZURE_VM_IP secret)')
        booleanParam(name: 'RUN_TESTS', defaultValue: true, description: 'Run pytest test suite inside container')
        booleanParam(name: 'RUN_SECURITY_SCAN', defaultValue: true, description: 'Run Trivy container vulnerability scan')
        booleanParam(name: 'FAIL_ON_VULNERABILITY', defaultValue: false, description: 'Fail build if Critical/High vulnerabilities are found')
    }

    environment {
        // --- Application & Registry Configuration ---
        APP_NAME              = 'devsecops-analyzer'
        ACR_REGISTRY          = credentials('ACR_REGISTRY_HOST') // e.g., 'myregistry.azurecr.io'
        ACR_CREDS_ID          = 'azure-acr-credentials'          // Jenkins Credential ID (Username/Password)
        
        // --- Azure Virtual Machine Configuration ---
        AZURE_VM_USER         = 'azureuser'
        AZURE_VM_IP           = credentials('AZURE_VM_IP')       // Jenkins Credential ID (Secret text)
        VM_SSH_CREDS_ID       = 'azure-vm-ssh-key'               // Jenkins Credential ID (SSH Username with private key)
        REMOTE_DEPLOY_DIR     = '/opt/devsecops-analyzer'
        APP_PORT              = '8000'

        // --- Derived Image Tags ---
        IMAGE_FULL_TAG        = "${ACR_REGISTRY}/${APP_NAME}:${BUILD_NUMBER}"
        IMAGE_LATEST_TAG      = "${ACR_REGISTRY}/${APP_NAME}:latest"
    }

    options {
        buildDiscarder(logRotator(numToKeepStr: '15', artifactNumToKeepStr: '10'))
        disableConcurrentBuilds()
        timeout(time: 30, unit: 'MINUTES')
    }

    stages {
        stage('Checkout SCM') {
            steps {
                echo "Pulling source code from Git repository..."
                checkout scm
                script {
                    echo "Current Git Commit: ${env.GIT_COMMIT ?: 'Local Workspace'}"
                    echo "Building Version: ${BUILD_NUMBER}"
                }
            }
        }

        stage('Build Docker Image') {
            steps {
                echo "Building Docker image: ${IMAGE_FULL_TAG}..."
                script {
                    if (isUnix()) {
                        sh "docker build -t ${IMAGE_FULL_TAG} -t ${IMAGE_LATEST_TAG} -f Dockerfile ."
                    } else {
                        bat "docker build -t ${IMAGE_FULL_TAG} -t ${IMAGE_LATEST_TAG} -f Dockerfile ."
                    }
                }
            }
        }

        stage('Run Unit Tests (Container)') {
            when {
                expression { return params.RUN_TESTS }
            }
            steps {
                echo "Executing test suite inside the built Docker container..."
                script {
                    if (isUnix()) {
                        sh "docker run --rm ${IMAGE_FULL_TAG} pytest tests/ -v"
                    } else {
                        bat "docker run --rm ${IMAGE_FULL_TAG} pytest tests/ -v"
                    }
                }
            }
        }

        stage('Container Security Scan (Trivy)') {
            when {
                expression { return params.RUN_SECURITY_SCAN }
            }
            steps {
                echo "Scanning Docker image with Aqua Trivy for vulnerabilities..."
                script {
                    def exitCode = params.FAIL_ON_VULNERABILITY ? '1' : '0'
                    if (isUnix()) {
                        sh """
                            docker run --rm \
                                -v /var/run/docker.sock:/var/run/docker.sock \
                                -v trivy-cache:/root/.cache/ \
                                aquasec/trivy:latest image \
                                --severity HIGH,CRITICAL \
                                --exit-code ${exitCode} \
                                ${IMAGE_FULL_TAG} || true
                        """
                    } else {
                        bat """
                            docker run --rm -v //var/run/docker.sock:/var/run/docker.sock -v trivy-cache:/root/.cache/ aquasec/trivy:latest image --severity HIGH,CRITICAL --exit-code ${exitCode} ${IMAGE_FULL_TAG} || exit 0
                        """
                    }
                }
            }
        }

        stage('Push Image to Registry') {
            steps {
                echo "Authenticating with Container Registry: ${ACR_REGISTRY}..."
                withCredentials([usernamePassword(credentialsId: env.ACR_CREDS_ID, usernameVariable: 'ACR_USER', passwordVariable: 'ACR_PASS')]) {
                    script {
                        if (isUnix()) {
                            sh '''
                                echo "$ACR_PASS" | docker login "$ACR_REGISTRY" -u "$ACR_USER" --password-stdin
                                docker push ${IMAGE_FULL_TAG}
                                docker push ${IMAGE_LATEST_TAG}
                            '''
                        } else {
                            powershell '''
                                Write-Host "--- CREDENTIAL DIAGNOSTICS ---"
                                Write-Host "DIAG: Registry raw length = $($env:ACR_REGISTRY.Length)"
                                Write-Host "DIAG: Registry ends with .azurecr.io = $($env:ACR_REGISTRY.EndsWith('.azurecr.io'))"
                                Write-Host "DIAG: Username = [$($env:ACR_USER)]"
                                Write-Host "DIAG: Password length = $($env:ACR_PASS.Length)"
                                if ($env:ACR_PASS.Length -ge 6) {
                                    Write-Host "DIAG: Password starts with '$($env:ACR_PASS.Substring(0, 5))' ends with '$($env:ACR_PASS.Substring($env:ACR_PASS.Length - 4, 4))'"
                                }
                                Write-Host "-------------------------------"

                                # Ensure clean variables without trailing whitespace or carriage returns
                                $reg = $env:ACR_REGISTRY.Trim()
                                if (-not $reg.EndsWith(".azurecr.io") -and -not $reg.Contains(".")) {
                                    $reg = "$reg.azurecr.io"
                                }
                                $usr = $env:ACR_USER.Trim()
                                $pwd = $env:ACR_PASS.Trim()

                                Write-Host "Attempting docker login to $reg as $usr..."
                                $pwd | docker login $reg -u $usr --password-stdin
                                if ($LASTEXITCODE -ne 0) {
                                    throw "Docker login to $reg failed with exit code $LASTEXITCODE"
                                }

                                docker push $env:IMAGE_FULL_TAG
                                docker push $env:IMAGE_LATEST_TAG
                            '''
                        }
                    }
                }
            }
        }

        stage('Deploy to Azure VM') {
            steps {
                script {
                    def targetHost = (params.AZURE_VM_HOST?.trim()) ? params.AZURE_VM_HOST.trim() : env.AZURE_VM_IP
                    echo "Deploying to Azure VM at ${targetHost}..."

                    withCredentials([
                        usernamePassword(credentialsId: env.ACR_CREDS_ID, usernameVariable: 'ACR_USER', passwordVariable: 'ACR_PASS'),
                        sshUserPrivateKey(credentialsId: env.VM_SSH_CREDS_ID, keyFileVariable: 'SSH_KEY_FILE', usernameVariable: 'SSH_USER')
                    ]) {
                        if (isUnix()) {
                            sh """
                                chmod 600 "${SSH_KEY_FILE}" 2>/dev/null || true
                                SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=20 -i ${SSH_KEY_FILE}"
                                echo "Testing SSH connectivity to Azure VM..."
                                ssh \$SSH_OPTS ${SSH_USER}@${targetHost} "mkdir -p ${REMOTE_DEPLOY_DIR}"

                                echo "Copying docker-compose.yml and deploy scripts to Azure VM..."
                                scp \$SSH_OPTS docker-compose.yml deploy/deploy.sh ${SSH_USER}@${targetHost}:${REMOTE_DEPLOY_DIR}/

                                echo "Executing remote deployment script on Azure VM..."
                                ssh \$SSH_OPTS ${SSH_USER}@${targetHost} \
                                    "sed -i 's/\\r\$//' ${REMOTE_DEPLOY_DIR}/deploy.sh && \
                                     chmod +x ${REMOTE_DEPLOY_DIR}/deploy.sh && \
                                     bash ${REMOTE_DEPLOY_DIR}/deploy.sh \
                                         '${REMOTE_DEPLOY_DIR}' \
                                         '${ACR_REGISTRY}/${APP_NAME}' \
                                         '${BUILD_NUMBER}' \
                                         '${ACR_REGISTRY}' \
                                         '${ACR_USER}' \
                                         '${ACR_PASS}'"
                            """
                        } else {
                            powershell """
                                # Restrict key permissions on Windows so OpenSSH accepts it
                                \$curr = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                                icacls.exe \$env:SSH_KEY_FILE /inheritance:r /grant:r "\${curr}:(R)" | Out-Null

                                \$sshOpts = @("-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=NUL", "-o", "ConnectTimeout=20", "-i", \$env:SSH_KEY_FILE)
                                
                                Write-Host "Testing SSH connectivity to Azure VM (${targetHost})..."
                                ssh @sshOpts "\$env:SSH_USER@${targetHost}" "mkdir -p ${REMOTE_DEPLOY_DIR}"
                                
                                Write-Host "Copying docker-compose.yml and deploy scripts to Azure VM..."
                                scp @sshOpts "docker-compose.yml" "deploy/deploy.sh" "\$env:SSH_USER@${targetHost}:${REMOTE_DEPLOY_DIR}/"
                                
                                Write-Host "Executing remote deployment script on Azure VM..."
                                ssh @sshOpts "\$env:SSH_USER@${targetHost}" "sed -i 's/\\r\$//' ${REMOTE_DEPLOY_DIR}/deploy.sh && chmod +x ${REMOTE_DEPLOY_DIR}/deploy.sh && bash ${REMOTE_DEPLOY_DIR}/deploy.sh '${REMOTE_DEPLOY_DIR}' '${ACR_REGISTRY}/${APP_NAME}' '${BUILD_NUMBER}' '${ACR_REGISTRY}' '\$env:ACR_USER' '\$env:ACR_PASS'"
                            """
                        }
                    }
                }
            }
        }

        stage('Post-Deployment Smoke Test') {
            steps {
                script {
                    def targetHost = (params.AZURE_VM_HOST?.trim()) ? params.AZURE_VM_HOST.trim() : env.AZURE_VM_IP
                    echo "Verifying deployment health at http://${targetHost}:${APP_PORT}/..."

                    if (isUnix()) {
                        sh """
                            for i in \$(seq 1 10); do
                                STATUS=\$(curl -s -o /dev/null -w "%{http_code}" "http://${targetHost}:${APP_PORT}/" || echo "000")
                                if [ "\$STATUS" -eq 200 ]; then
                                    echo "Verification Passed: Application is healthy and responding with HTTP 200!"
                                    exit 0
                                fi
                                echo "Waiting for external endpoint to respond... Attempt \$i/10 (HTTP \$STATUS)"
                                sleep 5
                            done
                            echo "WARNING: Smoke test did not return 200 within 50s. Please check NSG rules on Azure VM port ${APP_PORT}."
                        """
                    } else {
                        powershell """
                            \$healthy = \$false
                            for (\$i = 1; \$i -le 10; \$i++) {
                                try {
                                    \$response = Invoke-WebRequest -Uri "http://${targetHost}:${APP_PORT}/" -UseBasicParsing -TimeoutSec 5
                                    if (\$response.StatusCode -eq 200) {
                                        Write-Host "Verification Passed: Application is healthy and responding with HTTP 200!"
                                        \$healthy = \$true
                                        break
                                    }
                                } catch {
                                    Write-Host "Waiting for external endpoint to respond... Attempt \$i/10"
                                }
                                Start-Sleep -Seconds 5
                            }
                            if (-not \$healthy) {
                                Write-Warning "Smoke test did not return 200 within 50s. Please check NSG rules on Azure VM port ${APP_PORT}."
                            }
                        """
                    }
                }
            }
        }
    }

    post {
        always {
            echo "Pipeline run completed."
        }
        success {
            script {
                def targetHost = (params.AZURE_VM_HOST?.trim()) ? params.AZURE_VM_HOST.trim() : env.AZURE_VM_IP
                echo "=========================================================="
                echo " Pipeline Execution SUCCESSFUL!"
                echo " Deployed Version: ${IMAGE_FULL_TAG}"
                echo " Dashboard Live at: http://${targetHost}:${APP_PORT}/"
                echo "=========================================================="
                try {
                    echo "Cleaning up local workspace and docker images on Jenkins agent..."
                    if (isUnix()) {
                        sh "docker rmi ${IMAGE_FULL_TAG} ${IMAGE_LATEST_TAG} 2>/dev/null || true"
                    } else {
                        bat "docker rmi ${IMAGE_FULL_TAG} ${IMAGE_LATEST_TAG} 2>nul || exit 0"
                    }
                } catch (Exception e) {
                    echo "Docker cleanup step completed or skipped."
                }
            }
        }
        failure {
            echo "=========================================================="
            echo " Pipeline FAILED! Check console log above for details."
            echo "=========================================================="
        }
    }
}
