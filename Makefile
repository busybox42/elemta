.PHONY: all help build clean clean-certs certs install install-dev uninstall run test test-load test-docker up down down-volumes restart logs logs-elemta status rebuild rebuild-dev docker-build docker-run docker-stop update lint lint-fix fmt

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
	@echo "  rebuild-dev    - Quick rebuild (dev only, skips cert check)"
	@echo "  logs           - Show all logs (follow mode)"
	@echo "  logs-elemta    - Show Elemta SMTP logs only"
	@echo "  status         - Show service status"
	@echo ""
	@echo "🚀 Setup & Installation:"
	@echo "  install        - Production setup (interactive, creates .env)"
	@echo "  install-dev    - Development setup (one command, auto-configures)"
	@echo ""
	@echo "🔧 Build & Test:"
	@echo "  build             - Build all Elemta binaries (server, queue, cli)"
	@echo "  clean             - Clean build artifacts"
	@echo "  certs             - Generate self-signed TLS certificates"
	@echo "  clean-certs       - Remove test TLS certificates"
	@echo "  test              - Run Go unit tests"
	@echo "  test-load         - Run SMTP load/performance tests"
	@echo "  test-docker       - Run full integration test suite (21 tests)"
	@echo "  lint              - Run code quality checks (production code)"
	@echo "  fmt               - Format code with gofmt and goimports"
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

clean-certs:
	@echo "Removing test TLS certificates..."
	@rm -f config/test.crt config/test.key
	@echo "Test certificates removed"

certs:
	@echo "🔐 Generating self-signed TLS certificates..."
	@if ! command -v openssl >/dev/null 2>&1; then \
		echo "❌ Error: openssl not found. Please install openssl first."; \
		exit 1; \
	fi
	@openssl req -x509 -newkey rsa:4096 -nodes \
		-keyout config/test.key \
		-out config/test.crt \
		-days 365 \
		-subj '/CN=mail.dev.evil-admin.com/O=Elemta Dev/C=US' \
		-addext 'subjectAltName=DNS:mail.dev.evil-admin.com,DNS:*.dev.evil-admin.com' 2>/dev/null
	@chmod 600 config/test.key
	@chmod 644 config/test.crt
	@echo "✅ TLS certificates generated at config/test.{crt,key}"

# Install targets
install-bin: build
	@echo "Installing elemta server and utilities..."
	cp bin/elemta $(GOPATH)/bin/
	cp bin/elemta-queue $(GOPATH)/bin/
	cp bin/elemta-cli $(GOPATH)/bin/
	@echo "Install complete."

# Local server run (for debugging outside Docker)
run: build
	@echo "Running Elemta server locally (not in Docker)..."
	@echo "⚠️  For normal use, run: make up"
	./bin/elemta server --dev

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
	@echo "ℹ️  Run this before committing to catch lint errors early"
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./cmd/... ./internal/... --timeout=10m; \
	else \
		echo "⚠️  golangci-lint not installed. Install with:"; \
		echo "    go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
		exit 1; \
	fi

lint-fix:
	@echo "Running golangci-lint with auto-fix..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./cmd/... ./internal/... --fix --timeout=10m; \
	else \
		echo "⚠️  golangci-lint not installed"; \
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

# Advanced/internal targets (not shown in help)

# Legacy CLI targets (cli tools built by main 'build' target)
cli-install: build
	@echo "Installing elemta-cli to $(GOPATH)/bin..."
	@cp bin/elemta-cli $(GOPATH)/bin/ 2>/dev/null || echo "⚠️  GOPATH not set, skipping install"

# Legacy docker targets (use 'up'/'down' instead)
docker-run: up
docker-stop: down

# Kibana setup targets
setup-kibana:
	@echo "🔧 Setting up Kibana data views..."
	./scripts/setup-kibana-data-views.sh

install-dev: docker-build
	@echo "🚀 Elemta Development Setup"
	@echo "==========================="
	@if [ ! -f config/test.crt ] || [ ! -f config/test.key ]; then \
		if ! command -v openssl >/dev/null 2>&1; then \
			echo "❌ Error: openssl not found. Install it or run 'make certs' separately."; \
			exit 1; \
		fi; \
		echo "🔐 Generating self-signed TLS certificates..."; \
		openssl req -x509 -newkey rsa:4096 -nodes \
			-keyout config/test.key \
			-out config/test.crt \
			-days 365 \
			-subj '/CN=mail.dev.evil-admin.com/O=Elemta Dev/C=US' \
			-addext 'subjectAltName=DNS:mail.dev.evil-admin.com,DNS:*.dev.evil-admin.com' 2>/dev/null; \
		chmod 600 config/test.key; \
		chmod 644 config/test.crt; \
		echo "✅ TLS certificates generated"; \
	else \
		echo "ℹ️  Using existing TLS certificates"; \
	fi
	@if [ ! -f .env ]; then \
		echo "📝 Creating .env for development..."; \
		printf "# Elemta Development Environment - Auto-generated\n" > .env; \
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
		echo "✅ .env created"; \
	else \
		echo "ℹ️  Using existing .env"; \
	fi
	@echo "🚀 Starting services..."
	@docker compose -f deployments/compose/docker-compose.yml up -d
	@echo "⏳ Initializing LDAP..."
	@./scripts/init-ldap-if-needed.sh || true
	@echo ""
	@echo "✅ Development Environment Ready!"
	@echo "=================================="
	@echo "   📧 SMTP:      localhost:2525"
	@echo "   📊 Metrics:   http://localhost:8080/metrics"
	@echo "   🌐 Web UI:    http://localhost:8025"
	@echo "   ✉️  Roundcube: http://localhost:8026"
	@echo "   👤 Test User: user@example.com / password"
	@echo ""
	@echo "📋 Next Steps:"
	@echo "   make status      # Check service health"
	@echo "   make logs        # View logs"
	@echo "   make test-load   # Run load tests"

docker-setup: install-dev

# Define compose file location
COMPOSE_FILE := deployments/compose/docker-compose.yml

# Modern Docker commands
up:
	@echo "🚀 Starting Elemta services..."
	docker compose -f $(COMPOSE_FILE) up -d
	@echo "✅ Services started"

down:
	@echo "🛑 Stopping Elemta services..."
	docker compose -f $(COMPOSE_FILE) down
	@echo "✅ Services stopped"

down-volumes:
	@echo "🛑 Stopping Elemta services and removing volumes..."
	docker compose -f $(COMPOSE_FILE) down -v
	@echo "✅ Services stopped and volumes removed"

restart:
	@echo "🔄 Restarting Elemta services..."
	docker compose -f $(COMPOSE_FILE) restart
	@echo "✅ Services restarted"

logs:
	@echo "📋 Showing Elemta logs (Ctrl+C to exit)..."
	docker compose -f $(COMPOSE_FILE) logs -f

logs-elemta:
	@echo "📋 Showing Elemta SMTP server logs..."
	docker compose -f $(COMPOSE_FILE) logs -f elemta

status:
	@echo "📊 Elemta Services Status:"
	@docker compose -f $(COMPOSE_FILE) ps

rebuild:
	@echo "🔨 Rebuilding and restarting Elemta..."
	@$(MAKE) down
	docker compose -f $(COMPOSE_FILE) build --no-cache elemta elemta-web
	@$(MAKE) up
	@echo "✅ Rebuild complete"

rebuild-dev:
	@echo "🔨 Quick rebuild for development..."
	@$(MAKE) down
	docker compose -f $(COMPOSE_FILE) build elemta elemta-web
	@$(MAKE) up
	@echo "✅ Development rebuild complete"

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


uninstall:
	@echo "🗑️  Uninstalling Elemta..."
	./install/uninstall.sh

# Legacy update targets (use 'make rebuild' instead)
update: rebuild
update-backup: rebuild  
update-restart: restart 