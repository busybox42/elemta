.PHONY: all clean build-antivirus build-antispam

# Default target
all: build-antivirus build-antispam

# Build antivirus plugin
build-antivirus:
	@echo "Building antivirus plugin..."
	go build -buildmode=plugin -o ../../plugins/example_antivirus.so example_antivirus.go

# Build antispam plugin
build-antispam:
	@echo "Building antispam plugin..."
	go build -buildmode=plugin -o ../../plugins/example_antispam.so example_antispam.go

# Clean built plugins
clean:
	@echo "Cleaning plugins..."
	rm -f ../../plugins/example_antivirus.so
	rm -f ../../plugins/example_antispam.so

# Help target
help:
	@echo "Available targets:"
	@echo "  all            - Build all plugins (default)"
	@echo "  build-antivirus - Build antivirus plugin"
	@echo "  build-antispam  - Build antispam plugin"
	@echo "  clean          - Remove built plugins"
	@echo "  help           - Show this help message" 