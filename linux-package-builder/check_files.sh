#!/bin/bash

PACKAGE_NAME="elemta"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Script directory: $SCRIPT_DIR"
echo "Parent directory: $PARENT_DIR"

# Check binary file
if [ -f "$PARENT_DIR/bin/$PACKAGE_NAME" ]; then
    echo "Binary file exists: $PARENT_DIR/bin/$PACKAGE_NAME"
else
    echo "Binary file does not exist: $PARENT_DIR/bin/$PACKAGE_NAME"
    # Create a dummy binary file for testing
    mkdir -p "$PARENT_DIR/bin"
    echo "#!/bin/bash" > "$PARENT_DIR/bin/$PACKAGE_NAME"
    echo "echo \"This is a dummy $PACKAGE_NAME binary\"" >> "$PARENT_DIR/bin/$PACKAGE_NAME"
    chmod +x "$PARENT_DIR/bin/$PACKAGE_NAME"
    echo "Created dummy binary file"
fi

# Check config file
if [ -f "$PARENT_DIR/config/$PACKAGE_NAME.conf" ]; then
    echo "Config file exists: $PARENT_DIR/config/$PACKAGE_NAME.conf"
else
    echo "Config file does not exist: $PARENT_DIR/config/$PACKAGE_NAME.conf"
    # Create a dummy config file for testing
    mkdir -p "$PARENT_DIR/config"
    echo "# Dummy config file for $PACKAGE_NAME" > "$PARENT_DIR/config/$PACKAGE_NAME.conf"
    echo "port = 8080" >> "$PARENT_DIR/config/$PACKAGE_NAME.conf"
    echo "log_level = info" >> "$PARENT_DIR/config/$PACKAGE_NAME.conf"
    echo "Created dummy config file"
fi

# Check data directory
if [ -d "$PARENT_DIR/data" ]; then
    echo "Data directory exists: $PARENT_DIR/data"
else
    echo "Data directory does not exist: $PARENT_DIR/data"
    # Create a dummy data directory for testing
    mkdir -p "$PARENT_DIR/data"
    echo "This is a dummy data file" > "$PARENT_DIR/data/dummy.txt"
    echo "Created dummy data directory and file"
fi

# Check if Docker is available
if command -v docker &> /dev/null; then
    echo "Docker is available"
else
    echo "Docker is not available"
fi

# Make all build scripts executable
chmod +x "$SCRIPT_DIR"/*.sh
echo "Made all build scripts executable"

# List all build scripts
echo "Build scripts:"
ls -la "$SCRIPT_DIR"/*.sh 