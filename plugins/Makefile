.PHONY: all clean build-clamav build-rspamd

# Default target
all: build-clamav build-rspamd

# Build ClamAV plugin
build-clamav:
	@echo "Building ClamAV plugin..."
	go build -buildmode=plugin -o clamav.so ./clamav

# Build Rspamd plugin
build-rspamd:
	@echo "Building Rspamd plugin..."
	go build -buildmode=plugin -o rspamd.so ./rspamd

# Clean built plugins
clean:
	@echo "Cleaning plugins..."
	rm -f clamav.so
	rm -f rspamd.so

# Help target
help:
	@echo "Available targets:"
	@echo "  all           - Build all plugins (default)"
	@echo "  build-clamav  - Build ClamAV plugin"
	@echo "  build-rspamd  - Build Rspamd plugin"
	@echo "  clean         - Remove built plugins"
	@echo "  help          - Show this help message" 