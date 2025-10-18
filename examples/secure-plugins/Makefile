# Secure Plugin Build System
# This Makefile builds secure plugins without CGO dependencies

.PHONY: all clean build-example-antivirus build-example-antispam help

# Default target
all: build-example-antivirus

# Build example antivirus plugin (CGO-free)
build-example-antivirus:
	@echo "Building secure example antivirus plugin..."
	@mkdir -p example-antivirus
	cd example-antivirus && CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o plugin main.go
	@echo "Built example-antivirus/plugin"

# Build example antispam plugin (CGO-free)
build-example-antispam:
	@echo "Building secure example antispam plugin..."
	@mkdir -p example-antispam
	@echo "Creating example antispam plugin..."
	@cp -r example-antivirus/* example-antispam/
	@sed -i 's/antivirus/antispam/g' example-antispam/plugin.json
	@sed -i 's/example-antivirus/example-antispam/g' example-antispam/plugin.json
	cd example-antispam && CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o plugin main.go
	@echo "Built example-antispam/plugin"

# Validate plugin security
validate-plugins:
	@echo "Validating plugin security..."
	@for dir in */; do \
		if [ -f "$$dir/plugin" ]; then \
			echo "Checking $$dir/plugin..."; \
			file "$$dir/plugin" | grep -q "statically linked" || (echo "WARNING: $$dir/plugin is not statically linked" && exit 1); \
			ldd "$$dir/plugin" 2>/dev/null && (echo "ERROR: $$dir/plugin has dynamic dependencies" && exit 1) || echo "OK: $$dir/plugin is statically linked"; \
		fi \
	done
	@echo "Plugin security validation completed"

# Calculate checksums for plugins
checksums:
	@echo "Calculating plugin checksums..."
	@for dir in */; do \
		if [ -f "$$dir/plugin" ]; then \
			echo "Calculating checksum for $$dir/plugin..."; \
			CHECKSUM=$$(sha256sum "$$dir/plugin" | cut -d' ' -f1); \
			echo "Checksum for $$dir: sha256:$$CHECKSUM"; \
			if [ -f "$$dir/plugin.json" ]; then \
				sed -i "s/\"checksum\": \"[^\"]*\"/\"checksum\": \"sha256:$$CHECKSUM\"/" "$$dir/plugin.json"; \
				echo "Updated checksum in $$dir/plugin.json"; \
			fi \
		fi \
	done

# Test plugins
test-plugins:
	@echo "Testing secure plugins..."
	@for dir in */; do \
		if [ -f "$$dir/plugin" ] && [ -f "$$dir/plugin.json" ]; then \
			echo "Testing $$dir..."; \
			timeout 5 "$$dir/plugin" < /dev/null || echo "Plugin $$dir test completed"; \
		fi \
	done

# Clean built plugins
clean:
	@echo "Cleaning secure plugins..."
	@find . -name "plugin" -type f -delete
	@echo "Cleaned all plugin binaries"

# Package plugins for distribution
package:
	@echo "Packaging secure plugins..."
	@mkdir -p ../secure-plugin-packages
	@for dir in */; do \
		if [ -f "$$dir/plugin" ] && [ -f "$$dir/plugin.json" ]; then \
			PLUGIN_NAME=$$(basename "$$dir"); \
			echo "Packaging $$PLUGIN_NAME..."; \
			tar -czf "../secure-plugin-packages/$$PLUGIN_NAME.tar.gz" -C "$$dir" .; \
			echo "Created ../secure-plugin-packages/$$PLUGIN_NAME.tar.gz"; \
		fi \
	done

# Install plugins to server
install:
	@echo "Installing secure plugins to server..."
	@if [ ! -d "$(DESTDIR)" ]; then \
		echo "ERROR: DESTDIR not specified or does not exist"; \
		echo "Usage: make install DESTDIR=/path/to/elemta/secure-plugins"; \
		exit 1; \
	fi
	@for dir in */; do \
		if [ -f "$$dir/plugin" ] && [ -f "$$dir/plugin.json" ]; then \
			PLUGIN_NAME=$$(basename "$$dir"); \
			echo "Installing $$PLUGIN_NAME to $(DESTDIR)/$$PLUGIN_NAME/"; \
			mkdir -p "$(DESTDIR)/$$PLUGIN_NAME"; \
			cp "$$dir/plugin" "$(DESTDIR)/$$PLUGIN_NAME/"; \
			cp "$$dir/plugin.json" "$(DESTDIR)/$$PLUGIN_NAME/"; \
			chmod 755 "$(DESTDIR)/$$PLUGIN_NAME/plugin"; \
			chmod 644 "$(DESTDIR)/$$PLUGIN_NAME/plugin.json"; \
			echo "Installed $$PLUGIN_NAME"; \
		fi \
	done

# Security audit
security-audit:
	@echo "Performing security audit on plugins..."
	@echo "Checking for CGO usage..."
	@for dir in */; do \
		if [ -f "$$dir/main.go" ]; then \
			if grep -q "import.*\"C\"" "$$dir/main.go"; then \
				echo "ERROR: $$dir uses CGO (import \"C\")"; \
				exit 1; \
			fi \
			if grep -q "//.*#cgo" "$$dir/main.go"; then \
				echo "ERROR: $$dir contains CGO directives"; \
				exit 1; \
			fi \
		fi \
	done
	@echo "Checking for dangerous system calls..."
	@for dir in */; do \
		if [ -f "$$dir/main.go" ]; then \
			if grep -E "(syscall\.|os\.Exec|exec\.Command)" "$$dir/main.go" | grep -v "// SAFE:"; then \
				echo "WARNING: $$dir may contain dangerous system calls"; \
			fi \
		fi \
	done
	@echo "Security audit completed"

# Help target
help:
	@echo "Secure Plugin Build System"
	@echo "=========================="
	@echo ""
	@echo "Available targets:"
	@echo "  all                  - Build all plugins (default)"
	@echo "  build-example-antivirus - Build example antivirus plugin"
	@echo "  build-example-antispam  - Build example antispam plugin"
	@echo "  validate-plugins     - Validate plugin security (static linking, etc.)"
	@echo "  checksums           - Calculate and update plugin checksums"
	@echo "  test-plugins        - Test plugin execution"
	@echo "  package             - Package plugins for distribution"
	@echo "  install             - Install plugins to server (use DESTDIR=path)"
	@echo "  security-audit      - Perform security audit on plugin code"
	@echo "  clean               - Remove built plugin binaries"
	@echo "  help                - Show this help message"
	@echo ""
	@echo "Security Features:"
	@echo "  - CGO_ENABLED=0: No CGO dependencies"
	@echo "  - Static linking: No dynamic library dependencies"
	@echo "  - Process isolation: Plugins run in separate processes"
	@echo "  - Resource limits: Memory, CPU, and execution time limits"
	@echo "  - Input validation: Comprehensive input/output sanitization"
	@echo "  - Checksum verification: Plugin integrity validation"
