pipeline {
    agent any

    parameters {
        choice(name: 'DEPLOY_ENV', choices: ['production', 'staging'], description: 'Deployment Environment')
        string(name: 'AZURE_VM_HOST', defaultValue: '', description: 'Azure VM Public IP or FQDN (leave empty to use env default)')
        booleanParam(name: 'RUN_TESTS', defaultValue: true, description: 'Run pytest test suite before build')
        booleanParam(name: 'RUN_SECURITY_SCAN', defaultValue: true, description: 'Run Trivy container vulnerability scan')
        booleanParam(name: 'FAIL_ON_VULNERABILITY', defaultValue: false, description: 'Fail build if Critical/High vulnerabilities are found')
    }

    environment {
        // --- Application & Registry Configuration ---
        APP_NAME              = 'devsecops-analyzer'
        // Set your Azure Container Registry (e.g., 'myregistry.azurecr.io') or Docker Hub username
        ACR_REGISTRY          = credentials('ACR_REGISTRY_HOST') // e.g., 'myregistry.azurecr.io'
        ACR_CREDS_ID          = 'azure-acr-credentials'          // Jenkins Credential ID (Username/Password)
        
        // --- Azure Virtual Machine Configuration ---
        AZURE_VM_USER         = 'azureuser'
        // If parameter AZURE_VM_HOST is provided, use it; otherwise fallback to default Jenkins env/secret
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
        ansiColor('xterm')
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
                sh '''
                    python3 -m venv .venv || python -m venv .venv
                    . .venv/bin/activate
                    pip install --upgrade pip
                    pip install -r requirements.txt pytest httpx
                    pytest tests/ -v --junitxml=test-results.xml
                '''
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
                sh '''
                    docker build \
                        -t ${IMAGE_FULL_TAG} \
                        -t ${IMAGE_LATEST_TAG} \
                        -f Dockerfile .
                '''
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
                    sh """
                        if command -v trivy >/dev/null 2>&1; then
                            trivy image \
                                --severity HIGH,CRITICAL \
                                --exit-code ${exitCode} \
                                --format table \
                                ${IMAGE_FULL_TAG}
                        else
                            echo "Trivy CLI is not installed on Jenkins agent. Running Trivy via Docker container..."
                            docker run --rm \
                                -v /var/run/docker.sock:/var/run/docker.sock \
                                aquasec/trivy:latest image \
                                --severity HIGH,CRITICAL \
                                --exit-code ${exitCode} \
                                ${IMAGE_FULL_TAG}
                        fi
                    """
                }
            }
        }

        stage('Push Image to Registry') {
            steps {
                echo "Authenticating with Container Registry: ${ACR_REGISTRY}..."
                withCredentials([usernamePassword(credentialsId: env.ACR_CREDS_ID, usernameVariable: 'ACR_USER', passwordVariable: 'ACR_PASS')]) {
                    sh '''
                        echo "$ACR_PASS" | docker login "$ACR_REGISTRY" -u "$ACR_USER" --password-stdin
                        echo "Pushing images to registry..."
                        docker push ${IMAGE_FULL_TAG}
                        docker push ${IMAGE_LATEST_TAG}
                    '''
                }
            }
        }

        stage('Deploy to Azure VM') {
            steps {
                echo "Deploying to Azure VM at ${TARGET_VM_HOST}..."
                sshagent(credentials: [env.VM_SSH_CREDS_ID]) {
                    withCredentials([usernamePassword(credentialsId: env.ACR_CREDS_ID, usernameVariable: 'ACR_USER', passwordVariable: 'ACR_PASS')]) {
                        sh '''
                            # Ensure strict host checking is relaxed for automated CI or pre-seeded in known_hosts
                            SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15"

                            echo "Testing SSH connectivity to Azure VM..."
                            ssh $SSH_OPTS ${AZURE_VM_USER}@${TARGET_VM_HOST} "mkdir -p ${REMOTE_DEPLOY_DIR}"

                            echo "Copying docker-compose.yml and deploy scripts to Azure VM..."
                            scp $SSH_OPTS docker-compose.yml deploy/deploy.sh ${AZURE_VM_USER}@${TARGET_VM_HOST}:${REMOTE_DEPLOY_DIR}/

                            echo "Executing remote deployment script on Azure VM..."
                            ssh $SSH_OPTS ${AZURE_VM_USER}@${TARGET_VM_HOST} \
                                "chmod +x ${REMOTE_DEPLOY_DIR}/deploy.sh && \
                                 ${REMOTE_DEPLOY_DIR}/deploy.sh \
                                     '${REMOTE_DEPLOY_DIR}' \
                                     '${ACR_REGISTRY}/${APP_NAME}' \
                                     '${BUILD_NUMBER}' \
                                     '${ACR_REGISTRY}' \
                                     '${ACR_USER}' \
                                     '${ACR_PASS}'"
                        '''
                    }
                }
            }
        }

        stage('Post-Deployment Smoke Test') {
            steps {
                echo "Verifying deployment health at http://${TARGET_VM_HOST}:${APP_PORT}/..."
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
            }
        }
    }

    post {
        always {
            echo "Cleaning up local workspace and docker images on Jenkins agent..."
            sh '''
                docker rmi ${IMAGE_FULL_TAG} ${IMAGE_LATEST_TAG} 2>/dev/null || true
            '''
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
