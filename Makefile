.PHONY: all build clean test

BINARY_NAME=elemta
QUEUE_BINARY_NAME=elemta-queue
VERSION=0.1.0
BUILD_DIR=build
LDFLAGS=-ldflags "-X main.Version=$(VERSION)"

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
	go run $(LDFLAGS) ./cmd/elemta

docker:
	@echo "Building Docker image..."
	docker build -t elemta:$(VERSION) .
	@echo "Docker build complete!"

docker-run:
	@echo "Running Docker container..."
	docker run -p 25:25 -p 465:465 elemta:$(VERSION)
	@echo "Docker container started!" 