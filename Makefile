.PHONY: all build clean install run test docker docker-build docker-run docker-stop cli cli-install cli-test cli-docker api api-install api-test

# Default target
all: build

# Build targets
build:
	@echo "Building elemta server and utilities..."
	go build -o bin/elemta ./cmd/elemta
	go build -o bin/elemta-queue ./cmd/elemta-queue
	go build -o bin/elemta-cli ./cmd/elemta-cli
	@echo "Build complete."

# Clean targets
clean:
	@echo "Cleaning build artifacts..."
	rm -rf bin/
	@echo "Clean complete."

# Install targets
install: build
	@echo "Installing elemta server and utilities..."
	cp bin/elemta $(GOPATH)/bin/
	cp bin/elemta-queue $(GOPATH)/bin/
	cp bin/elemta-cli $(GOPATH)/bin/
	@echo "Install complete."

# Run targets
run: build
	@echo "Running elemta server..."
	./bin/elemta server

# Test targets
test:
	@echo "Running tests..."
	go test -v ./...

# Docker targets
docker: docker-build docker-run

docker-build:
	@echo "Building Docker image..."
	docker-compose build

docker-run:
	@echo "Starting Docker containers..."
	API_ENABLED=true docker-compose up -d

docker-stop:
	@echo "Stopping Docker containers..."
	docker-compose down

# CLI targets
cli: cli-build

cli-build:
	@echo "Building elemta-cli..."
	go build -o bin/elemta-cli ./cmd/elemta-cli

cli-install: cli-build
	@echo "Installing elemta-cli..."
	cp bin/elemta-cli $(GOPATH)/bin/

cli-test:
	@echo "Testing elemta-cli..."
	docker exec -it elemta_node0 /app/elemta-cli --api-url http://elemta_api:8081 status
	docker exec -it elemta_node0 /app/elemta-cli --api-url http://elemta_api:8081 queue stats

cli-docker:
	@echo "Building Docker image for CLI..."
	docker build -t elemta-cli:latest -f Dockerfile.cli .

# API targets
api: api-install

api-install:
	@echo "Installing API server..."
	chmod +x scripts/api_server.py
	chmod +x scripts/elemta-api.sh
	@if [ -d "$(GOPATH)/bin" ]; then \
		cp scripts/api_server.py $(GOPATH)/bin/; \
		cp scripts/elemta-api.sh $(GOPATH)/bin/elemta-api; \
	fi

api-test:
	@echo "Testing API server..."
	curl -s http://localhost:8081/api/queue/stats | json_pp
	@echo "\nTesting API helper script..."
	./scripts/elemta-api.sh stats
	./scripts/elemta-api.sh --format json list | head -n 20 