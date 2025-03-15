.PHONY: all build clean test unit-test integration-test python-test docker-test docker docker-build docker-run docker-deploy docker-undeploy k8s-deploy k8s-undeploy k8s-down k8s-up k8s-restart k8s-test

BINARY_NAME=elemta
QUEUE_BINARY_NAME=elemta-queue
VERSION=0.1.0
BUILD_DIR=build
LDFLAGS=-ldflags "-X main.Version=$(VERSION)"
DOCKER_TAG=latest
K8S_NAMESPACE=default

all: clean build

build:
	@echo "Building Elemta MTA..."
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/elemta
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(QUEUE_BINARY_NAME) ./cmd/elemta-queue
	@echo "Build complete!"

clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@echo "Clean complete!"

test: unit-test
	@echo "All tests complete!"

unit-test:
	@echo "Running unit tests..."
	go test -v ./...
	@echo "Unit tests complete!"

integration-test: k8s-test
	@echo "Integration tests complete!"

python-test:
	@echo "Running Python tests..."
	python3 tests/python/test_smtp.py
	python3 tests/python/test_smtp_auth.py
	SKIP_SECURITY_TESTS=true python3 tests/python/test_security.py --test all
	@echo "Python tests complete!"

docker-test:
	@echo "Running Docker tests..."
	docker-compose -f tests/docker/docker-compose.test.yml down --remove-orphans || true
	docker-compose -f tests/docker/docker-compose.test.yml up -d --build
	@echo "Docker tests started! Use 'docker-compose -f tests/docker/docker-compose.test.yml down' to stop."

coverage:
	@echo "Running tests with coverage..."
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out
	@echo "Coverage tests complete!"

install:
	@echo "Installing Elemta MTA..."
	go install $(LDFLAGS) ./cmd/elemta
	go install $(LDFLAGS) ./cmd/elemta-queue
	@echo "Installation complete!"

run:
	@echo "Running Elemta MTA..."
	go run $(LDFLAGS) ./cmd/elemta server

docker-build:
	@echo "Building Docker image..."
	docker build -t elemta:$(DOCKER_TAG) .
	@echo "Docker build complete!"

docker-run:
	@echo "Running Docker container..."
	docker run -p 2525:2525 -v $(CURDIR)/config:/app/config -v $(CURDIR)/queue:/app/queue -v $(CURDIR)/logs:/app/logs --name elemta elemta:$(DOCKER_TAG) server
	@echo "Docker container started!"

docker-deploy: docker-build
	@echo "Deploying with Docker Compose..."
	docker-compose up -d
	@echo "Docker deployment complete!"

docker-undeploy:
	@echo "Undeploying Docker Compose..."
	docker-compose down --remove-orphans || true
	docker network prune -f || true
	@echo "Docker undeployment complete!"

docker-logs:
	@echo "Showing Docker container logs..."
	docker logs -f elemta
	@echo "Docker logs complete!"

docker-stop:
	@echo "Stopping Docker container..."
	docker stop elemta || true
	docker rm elemta || true
	@echo "Docker container stopped!"

k8s-deploy:
	@echo "Deploying to Kubernetes..."
	kubectl apply -f k8s/elemta-all.yaml
	@echo "Kubernetes deployment complete!"

k8s-undeploy:
	@echo "Undeploying from Kubernetes..."
	kubectl delete -f k8s/elemta-all.yaml || true
	@echo "Kubernetes undeployment complete!"

k8s-logs:
	@echo "Showing Kubernetes pod logs..."
	kubectl logs -f -l app=elemta
	@echo "Kubernetes logs complete!"

k8s-status:
	@echo "Checking Kubernetes deployment status..."
	kubectl get pods -l app=elemta
	kubectl get services -l app=elemta
	@echo "Kubernetes status check complete!"

k8s-down:
	@echo "Stopping Kubernetes deployment..."
	kubectl delete -f k8s/elemta-all.yaml || true
	@echo "Kubernetes deployment stopped!"

k8s-up:
	@echo "Starting Kubernetes deployment..."
	kubectl apply -f k8s/elemta-all.yaml
	@echo "Kubernetes deployment started!"

k8s-restart: k8s-down k8s-up
	@echo "Kubernetes deployment restarted!"

k8s-test:
	@echo "Running Kubernetes tests..."
	./tests/k8s/test-elemta.sh
	@echo "Kubernetes tests complete!"

# Alias for backward compatibility
docker: docker-build 