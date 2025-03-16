.PHONY: all clean build-antivirus build-antispam build-policy

# Default target
all: build-antivirus build-antispam build-policy

# Build antivirus plugin
build-antivirus:
	@echo "Building antivirus plugin..."
	go build -buildmode=plugin -o ../../plugins/example_antivirus.so example_antivirus.go

# Build antispam plugin
build-antispam:
	@echo "Building antispam plugin..."
	go build -buildmode=plugin -o ../../plugins/example_antispam.so example_antispam.go

# Build policy plugin
build-policy:
	@echo "Building policy plugin..."
	go build -buildmode=plugin -o ../../plugins/example_policy.so example_policy.go

# Clean built plugins
clean:
	@echo "Cleaning plugins..."
	rm -f ../../plugins/example_antivirus.so
	rm -f ../../plugins/example_antispam.so
	rm -f ../../plugins/example_policy.so

# Help target
help:
	@echo "Available targets:"
	@echo "  all            - Build all plugins (default)"
	@echo "  build-antivirus - Build antivirus plugin"
	@echo "  build-antispam  - Build antispam plugin"
	@echo "  build-policy    - Build policy plugin"
	@echo "  clean          - Remove built plugins"
	@echo "  help           - Show this help message" 