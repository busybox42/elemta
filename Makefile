.PHONY: all help build clean install-bin install install-dev uninstall run test test-load docker docker-build docker-run docker-stop cli cli-install cli-test cli-docker api api-install api-test update update-backup update-restart lint fmt

# Default target
all: build

# Help target
help:
	@echo "Elemta - High Performance SMTP Server"
	@echo ""
	@echo "🐳 Docker Development (Recommended):"
	@echo "  docker-setup   - Build and start full dev stack (Elemta + Valkey + LDAP + Dovecot + Roundcube)"
	@echo "  docker-down    - Stop all services and remove volumes"
	@echo "  docker-stop    - Stop services (keep volumes)"
	@echo "  docker-build   - Rebuild Docker images"
	@echo "  docker-run     - Start containers"
	@echo ""
	@echo "🔧 Build & Test:"
	@echo "  build             - Build Elemta binaries locally"
	@echo "  clean             - Clean build artifacts"
	@echo "  test              - Run Go tests"
	@echo "  test-docker       - Test Docker deployment"
	@echo "  test-auth         - Quick authentication test"
	@echo "  test-security     - Run security tests"
	@echo "  test-load         - Run SMTP load tests"
	@echo "  lint              - Run golangci-lint code quality checks"
	@echo "  fmt               - Format code with gofmt and goimports"
	@echo ""
	@echo "🛠️  Advanced:"
	@echo "  cli            - Build CLI tools"
	@echo "  api            - Build API tools"
	@echo "  install        - Legacy: Interactive installation"
	@echo "  run            - Run Elemta server locally"
	@echo ""
	@echo "⚡ Quick Start:"
	@echo "  make docker-setup    # Start development environment"
	@echo "  make test-docker     # Test the deployment"
	@echo "  make docker-down     # Clean shutdown"

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
install-bin: build
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
	@echo "Running Go tests..."
	@echo "⚠️  Note: Some packages require Docker services to be running"
	@echo "For complete integration tests, run: make test-docker"
	@go test -v -short -timeout 60s ./internal/antispam ./internal/api ./internal/auth ./internal/cache ./internal/context ./internal/datasource ./internal/delivery ./internal/plugin ./internal/queue 2>&1; \
	status=$$?; \
	echo ""; \
	if [ $$status -eq 0 ]; then \
		echo "✅ All unit tests passed"; \
	else \
		echo "⚠️  Some unit tests failed (exit code: $$status)"; \
		echo "Note: Integration tests may require Docker services"; \
	fi; \
	echo "💡 Run 'make test-docker' for full integration test suite (21 tests)"; \
	exit $$status

test-centralized:
	@echo "Running centralized test suite..."
	./tests/run_centralized_tests.sh

init-test-env:
	@echo "🔧 Initializing test environment..."
	@./scripts/init-ldap-users.sh
	@echo "✅ Test environment ready"

test-docker: init-test-env
	@echo "Running Docker deployment tests..."
	./tests/run_centralized_tests.sh --deployment docker-dev

test-auth: ## Quick authentication test
	@echo "Running authentication test..."
	./install/test-auth.sh

test-security:
	@echo "Running security tests..."
	./tests/run_centralized_tests.sh --category security

test-load:
	@echo "Running SMTP load tests..."
	@echo "⚠️  Note: Requires Docker services running (make docker-setup)"
	python3 tests/performance/smtp_load_test.py

test-all: test test-centralized
	@echo "All tests completed."

# Code quality targets
lint:
	@echo "Running golangci-lint..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "⚠️  golangci-lint not installed. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
		exit 1; \
	fi

fmt:
	@echo "Formatting Go code..."
	@go fmt ./...
	@echo "Running goimports..."
	@if command -v goimports >/dev/null 2>&1; then \
		goimports -w .; \
	else \
		echo "⚠️  goimports not installed. Install with: go install golang.org/x/tools/cmd/goimports@latest"; \
	fi

# Docker targets
docker: docker-build docker-run

docker-build:
	@echo "Building Docker image..."
	docker compose -f deployments/compose/docker-compose.yml build

docker-run:
	@echo "Starting Docker containers..."
	API_ENABLED=true docker compose up -d

docker-stop:
	@echo "Stopping Docker containers..."
	docker compose down

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
	docker exec -it elemta-node0 /app/elemta-cli --api-url http://elemta-api:8081 status
	docker exec -it elemta-node0 /app/elemta-cli --api-url http://elemta-api:8081 queue stats

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

# Kibana setup targets
setup-kibana:
	@echo "🔧 Setting up Kibana data views..."
	./scripts/setup-kibana-data-views.sh

docker-setup: docker-build
	@echo "🚀 Starting Elemta stack..."
	docker compose -f deployments/compose/docker-compose.yml up -d
	@echo "⏳ Initializing LDAP users..."
	@./scripts/init-ldap-if-needed.sh
	@echo "✅ Elemta stack running!"

docker-down:
	@echo "🛑 Stopping all Elemta services..."
	docker compose -f deployments/compose/docker-compose.yml down -v

# Installation and update targets
install:
	@echo "🚀 Running Elemta installer..."
	./install/install.sh

install-dev: docker-setup
	@echo "✅ Development environment ready!"
	@echo "   • Elemta SMTP: localhost:2525"
	@echo "   • Metrics: http://localhost:8080/metrics"
	@echo "   • Roundcube: http://localhost:8026"
	@echo "   • Test user: user@example.com / password"

uninstall:
	@echo "🗑️  Uninstalling Elemta..."
	./install/uninstall.sh

update:
	@echo "🔄 Updating Elemta configuration..."
	./install/update.sh

update-backup:
	@echo "🔄 Updating Elemta with backup..."
	./install/update.sh -b

update-restart:
	@echo "🔄 Restarting Elemta services..."
	./install/update.sh -r 