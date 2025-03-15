.PHONY: all build clean test docker docker-build docker-run docker-deploy docker-undeploy k8s-deploy k8s-undeploy k8s-expose

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

test:
	@echo "Running tests..."
	go test -v ./...
	@echo "Tests complete!"

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
	docker-compose down
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
	kubectl apply -f k8s/elemta-config.yaml
	kubectl apply -f k8s/pvc.yaml
	kubectl apply -f k8s/service.yaml
	kubectl apply -f k8s/clean-deployment.yaml
	@echo "Kubernetes deployment complete!"
	@echo "Service exposed on NodePort 30025"
	@echo "You can access the SMTP server at $(shell kubectl get nodes -o jsonpath='{.items[0].status.addresses[0].address}'):30025"

k8s-undeploy:
	@echo "Undeploying from Kubernetes..."
	kubectl delete -f k8s/clean-deployment.yaml || true
	kubectl delete -f k8s/service.yaml || true
	kubectl delete -f k8s/elemta-config.yaml || true
	kubectl delete -f k8s/pvc.yaml || true
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

k8s-expose:
	@echo "Exposing Elemta service externally..."
	kubectl apply -f k8s/service.yaml
	@echo "Service exposed on NodePort 30025"
	@echo "You can access the SMTP server at $(shell kubectl get nodes -o jsonpath='{.items[0].status.addresses[0].address}'):30025"
	@echo "Exposure complete!"

# Alias for backward compatibility
docker: docker-build 