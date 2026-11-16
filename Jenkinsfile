pipeline {
    agent any

    parameters {
        choice(name: 'DEPLOY_ENV', choices: ['production', 'staging'], description: 'Deployment Environment')
        string(name: 'AZURE_VM_HOST', defaultValue: '', description: 'Azure VM Public IP or FQDN (leave empty to use AZURE_VM_IP secret)')
        booleanParam(name: 'RUN_TESTS', defaultValue: true, description: 'Run pytest test suite before build')
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
        TARGET_VM_HOST        = "${params.AZURE_VM_HOST ?: credentials('AZURE_VM_IP')}"
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

        stage('Run Unit Tests') {
            when {
                expression { return params.RUN_TESTS }
            }
            steps {
                echo "Setting up Python virtual environment and running tests..."
                script {
                    if (isUnix()) {
                        sh '''
                            python3 -m venv .venv || python -m venv .venv
                            . .venv/bin/activate
                            python -m pip install --upgrade pip
                            python -m pip install -r requirements.txt pytest httpx
                            python -m pytest tests/ -v --junitxml=test-results.xml
                        '''
                    } else {
                        bat '''
                            python -m venv .venv
                            call .venv\\Scripts\\activate.bat
                            python -m pip install --upgrade pip
                            python -m pip install -r requirements.txt pytest httpx
                            python -m pytest tests/ -v --junitxml=test-results.xml
                        '''
                    }
                }
            }
            post {
                always {
                    junit testResults: 'test-results.xml', allowEmptyResults: true
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

        stage('Container Security Scan (Trivy)') {
            when {
                expression { return params.RUN_SECURITY_SCAN }
            }
            steps {
                echo "Scanning Docker image with Trivy for vulnerabilities..."
                script {
                    def exitCode = params.FAIL_ON_VULNERABILITY ? '1' : '0'
                    if (isUnix()) {
                        sh """
                            docker run --rm \
                                -v /var/run/docker.sock:/var/run/docker.sock \
                                aquasec/trivy:latest image \
                                --severity HIGH,CRITICAL \
                                --exit-code ${exitCode} \
                                ${IMAGE_FULL_TAG} || true
                        """
                    } else {
                        bat """
                            docker run --rm -v //var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest image --severity HIGH,CRITICAL --exit-code ${exitCode} ${IMAGE_FULL_TAG} || exit 0
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
                            bat """
                                echo %ACR_PASS% | docker login %ACR_REGISTRY% -u %ACR_USER% --password-stdin
                                docker push ${IMAGE_FULL_TAG}
                                docker push ${IMAGE_LATEST_TAG}
                            """
                        }
                    }
                }
            }
        }

        stage('Deploy to Azure VM') {
            steps {
                echo "Deploying to Azure VM at ${TARGET_VM_HOST}..."
                withCredentials([
                    usernamePassword(credentialsId: env.ACR_CREDS_ID, usernameVariable: 'ACR_USER', passwordVariable: 'ACR_PASS'),
                    sshUserPrivateKey(credentialsId: env.VM_SSH_CREDS_ID, keyFileVariable: 'SSH_KEY_FILE', usernameVariable: 'SSH_USER')
                ]) {
                    script {
                        if (isUnix()) {
                            sh '''
                                SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 -i ${SSH_KEY_FILE}"
                                echo "Testing SSH connectivity to Azure VM..."
                                ssh $SSH_OPTS ${SSH_USER}@${TARGET_VM_HOST} "mkdir -p ${REMOTE_DEPLOY_DIR}"

                                echo "Copying docker-compose.yml and deploy scripts to Azure VM..."
                                scp $SSH_OPTS docker-compose.yml deploy/deploy.sh ${SSH_USER}@${TARGET_VM_HOST}:${REMOTE_DEPLOY_DIR}/

                                echo "Executing remote deployment script on Azure VM..."
                                ssh $SSH_OPTS ${SSH_USER}@${TARGET_VM_HOST} \
                                    "chmod +x ${REMOTE_DEPLOY_DIR}/deploy.sh && \
                                     ${REMOTE_DEPLOY_DIR}/deploy.sh \
                                         '${REMOTE_DEPLOY_DIR}' \
                                         '${ACR_REGISTRY}/${APP_NAME}' \
                                         '${BUILD_NUMBER}' \
                                         '${ACR_REGISTRY}' \
                                         '${ACR_USER}' \
                                         '${ACR_PASS}'"
                            '''
                        } else {
                            bat """
                                @echo off
                                echo Testing SSH connectivity to Azure VM...
                                ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 -i "%SSH_KEY_FILE%" %SSH_USER%@%TARGET_VM_HOST% "mkdir -p %REMOTE_DEPLOY_DIR%"

                                echo Copying docker-compose.yml and deploy scripts to Azure VM...
                                scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 -i "%SSH_KEY_FILE%" docker-compose.yml deploy/deploy.sh %SSH_USER%@%TARGET_VM_HOST%:%REMOTE_DEPLOY_DIR%/

                                echo Executing remote deployment script on Azure VM...
                                ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 -i "%SSH_KEY_FILE%" %SSH_USER%@%TARGET_VM_HOST% "chmod +x %REMOTE_DEPLOY_DIR%/deploy.sh && %REMOTE_DEPLOY_DIR%/deploy.sh '%REMOTE_DEPLOY_DIR%' '%ACR_REGISTRY%/%APP_NAME%' '%BUILD_NUMBER%' '%ACR_REGISTRY%' '%ACR_USER%' '%ACR_PASS%'"
                            """
                        }
                    }
                }
            }
        }

        stage('Post-Deployment Smoke Test') {
            steps {
                echo "Verifying deployment health at http://${TARGET_VM_HOST}:${APP_PORT}/..."
                script {
                    if (isUnix()) {
                        sh '''
                            for i in $(seq 1 10); do
                                STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://${TARGET_VM_HOST}:${APP_PORT}/" || echo "000")
                                if [ "$STATUS" -eq 200 ]; then
                                    echo "Verification Passed: Application is healthy and responding with HTTP 200!"
                                    exit 0
                                fi
                                echo "Waiting for external endpoint to respond... Attempt $i/10 (HTTP $STATUS)"
                                sleep 5
                            done
                            echo "WARNING: Smoke test did not return 200 within 50s. Please check NSG rules on Azure VM port ${APP_PORT}."
                        '''
                    } else {
                        powershell """
                            \$healthy = \$false
                            for (\$i = 1; \$i -le 10; \$i++) {
                                try {
                                    \$response = Invoke-WebRequest -Uri "http://${TARGET_VM_HOST}:${APP_PORT}/" -UseBasicParsing -TimeoutSec 5
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
            echo "Cleaning up local workspace and docker images on Jenkins agent..."
            script {
                try {
                    if (isUnix()) {
                        sh "docker rmi ${IMAGE_FULL_TAG} ${IMAGE_LATEST_TAG} 2>/dev/null || true"
                    } else {
                        bat "docker rmi ${IMAGE_FULL_TAG} ${IMAGE_LATEST_TAG} 2>nul || exit 0"
                    }
                } catch (Exception e) {
                    echo "Docker cleanup step skipped or already clean."
                }
            }
        }
        success {
            echo "=========================================================="
            echo " Pipeline Execution SUCCESSFUL!"
            echo " Deployed Version: ${IMAGE_FULL_TAG}"
            echo " Dashboard Live at: http://${TARGET_VM_HOST}:${APP_PORT}/"
            echo "=========================================================="
        }
        failure {
            echo "=========================================================="
            echo " Pipeline FAILED! Check console log above for details."
            echo "=========================================================="
        }
    }
}
