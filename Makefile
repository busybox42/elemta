.PHONY: all help build clean install-bin install install-dev uninstall run test test-load docker docker-build docker-run docker-stop up down down-volumes restart logs logs-elemta status rebuild cli cli-install cli-test cli-docker api api-install api-test update update-backup update-restart lint fmt

# Default target
all: build

# Help target
help:
	@echo "Elemta - High Performance SMTP Server"
	@echo ""
	@echo "🐳 Docker Commands:"
	@echo "  up             - Start services (requires .env)"
	@echo "  down           - Stop services (keep volumes)"
	@echo "  down-volumes   - Stop services and remove volumes"
	@echo "  restart        - Restart all services"
	@echo "  rebuild        - Rebuild images and restart"
	@echo "  logs           - Show all logs (follow mode)"
	@echo "  logs-elemta    - Show Elemta SMTP logs only"
	@echo "  status         - Show service status"
	@echo ""
	@echo "🚀 Setup & Installation:"
	@echo "  install        - Production setup (interactive, creates .env)"
	@echo "  install-dev    - Development setup (auto-configures)"
	@echo "  docker-setup   - Build and start dev stack"
	@echo "  docker-build   - Rebuild Docker images"
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
	@echo "  run            - Run Elemta server locally"
	@echo "  update         - Update configuration"
	@echo ""
	@echo "⚡ Quick Start:"
	@echo "  Development:  make install-dev  # Auto-configured dev environment"
	@echo "  Production:   make install      # Interactive production setup"
	@echo "  Start:        make up           # Start services"
	@echo "  Stop:         make down         # Stop services"
	@echo "  Logs:         make logs         # View logs"
	@echo "  Status:       make status       # Check services"

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
	@echo "ℹ️  Note: Only checking production code (excluding tests, examples)"
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run --timeout 10m \
			--skip-dirs=vendor,venv,bin,build,examples,tests \
			--skip-files='.*_test\.go' \
			./cmd/elemta/commands ./internal/smtp ./internal/queue ./internal/cluster ./internal/performance ./internal/api || true; \
		echo "ℹ️  Lint complete (minor issues are informational)"; \
	else \
		echo "⚠️  golangci-lint not installed. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
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
	@echo "🚀 Setting up Elemta development environment..."
	@if [ ! -f .env ]; then \
		echo "📝 Creating .env for development..."; \
		printf "# Elemta Development Environment - Auto-generated by make docker-setup\n" > .env; \
		printf "ENVIRONMENT=development\n" >> .env; \
		printf "HOSTNAME=mail.dev.evil-admin.com\n" >> .env; \
		printf "LISTEN_PORT=2525\n" >> .env; \
		printf "LOG_LEVEL=DEBUG\n" >> .env; \
		printf "DEV_MODE=true\n" >> .env; \
		printf "TEST_MODE=true\n" >> .env; \
		printf "AUTH_REQUIRED=false\n" >> .env; \
		printf "LDAP_HOST=elemta-ldap\n" >> .env; \
		printf "DELIVERY_HOST=elemta-dovecot\n" >> .env; \
		printf "COMPOSE_PROJECT_NAME=elemta\n" >> .env; \
		printf "COMPOSE_FILE=deployments/compose/docker-compose.yml\n" >> .env; \
		echo "✅ .env created for development"; \
	fi
	@echo "🚀 Starting Elemta stack..."
	docker compose -f deployments/compose/docker-compose.yml up -d
	@echo "⏳ Initializing LDAP users..."
	@./scripts/init-ldap-if-needed.sh || true
	@echo "✅ Elemta stack running!"
	@echo "   • SMTP: localhost:2525"
	@echo "   • Metrics: http://localhost:8080/metrics"
	@echo "   • Web UI: http://localhost:8025"
	@echo "   • Roundcube: http://localhost:8026"

# Modern Docker commands using .env
up:
	@echo "🚀 Starting Elemta services..."
	@if [ ! -f .env ]; then \
		echo "⚠️  No .env file found. Run 'make install' or 'make docker-setup' first."; \
		exit 1; \
	fi
	docker compose -f deployments/compose/docker-compose.yml up -d
	@echo "✅ Services started"

down:
	@echo "🛑 Stopping Elemta services..."
	docker compose -f deployments/compose/docker-compose.yml down
	@echo "✅ Services stopped"

down-volumes:
	@echo "🛑 Stopping Elemta services and removing volumes..."
	docker compose -f deployments/compose/docker-compose.yml down -v
	@echo "✅ Services stopped and volumes removed"

restart:
	@echo "🔄 Restarting Elemta services..."
	docker compose -f deployments/compose/docker-compose.yml restart
	@echo "✅ Services restarted"

logs:
	@echo "📋 Showing Elemta logs (Ctrl+C to exit)..."
	docker compose -f deployments/compose/docker-compose.yml logs -f

logs-elemta:
	@echo "📋 Showing Elemta SMTP server logs..."
	docker logs -f elemta-node0

status:
	@echo "📊 Elemta Services Status:"
	@docker compose -f deployments/compose/docker-compose.yml ps

rebuild:
	@echo "🔨 Rebuilding and restarting Elemta..."
	@make down
	@make docker-build
	@make up
	@echo "✅ Rebuild complete"

docker-down: down-volumes

# Installation and update targets
install:
	@echo "🚀 Elemta Production Installation"
	@echo "=================================="
	@if [ -f .env ]; then \
		echo "⚠️  .env file already exists."; \
		read -p "Overwrite? (y/N): " confirm; \
		if [ "$$confirm" != "y" ] && [ "$$confirm" != "Y" ]; then \
			echo "Installation cancelled."; \
			exit 1; \
		fi; \
	fi
	@echo ""
	@echo "📝 Production Configuration"
	@echo "This will create a production-ready .env file."
	@echo ""
	@read -p "Hostname [mail.example.com]: " hostname; \
	hostname=$${hostname:-mail.example.com}; \
	read -p "SMTP Port [25]: " smtp_port; \
	smtp_port=$${smtp_port:-25}; \
	read -p "Admin Email [admin@example.com]: " admin_email; \
	admin_email=$${admin_email:-admin@example.com}; \
	read -p "Enable Let's Encrypt? (y/N): " letsencrypt; \
	if [ "$$letsencrypt" = "y" ] || [ "$$letsencrypt" = "Y" ]; then \
		letsencrypt_enabled=true; \
	else \
		letsencrypt_enabled=false; \
	fi; \
	read -p "LDAP Host [ldap]: " ldap_host; \
	ldap_host=$${ldap_host:-ldap}; \
	read -p "LDAP Base DN [dc=example,dc=com]: " ldap_base; \
	ldap_base=$${ldap_base:-dc=example,dc=com}; \
	echo ""; \
	echo "📝 Generating .env..."; \
	cat .env.example | sed \
		-e "s/HOSTNAME=.*/HOSTNAME=$$hostname/" \
		-e "s/LISTEN_PORT=.*/LISTEN_PORT=$$smtp_port/" \
		-e "s/LETSENCRYPT_EMAIL=.*/LETSENCRYPT_EMAIL=$$admin_email/" \
		-e "s/LETSENCRYPT_DOMAIN=.*/LETSENCRYPT_DOMAIN=$$hostname/" \
		-e "s/LETSENCRYPT_ENABLED=.*/LETSENCRYPT_ENABLED=$$letsencrypt_enabled/" \
		-e "s/LDAP_HOST=.*/LDAP_HOST=$$ldap_host/" \
		-e "s/LDAP_BASE_DN=.*/LDAP_BASE_DN=$$ldap_base/" \
		> .env
	@echo "✅ .env created successfully"
	@echo ""
	@echo "📋 Next Steps:"
	@echo "   1. Review and edit .env for your environment"
	@echo "   2. Configure TLS certificates (or enable Let's Encrypt)"
	@echo "   3. Update LDAP credentials in .env"
	@echo "   4. Run: make up"
	@echo ""
	@echo "🔐 Security Reminders:"
	@echo "   • Change default passwords in .env"
	@echo "   • Configure TLS certificates for production"
	@echo "   • Review memory and connection limits"
	@echo "   • Set up monitoring and alerts"

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