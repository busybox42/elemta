#!/bin/bash
set -e

# Cross-distribution package builder
# This script builds packages for multiple Linux distributions using Docker

# Default values
CONFIG_FILE="./config/package.yml"
OUTPUT_DIR="./dist"
VERSION=""
VERBOSE=0
BUILD_ALL=1
BUILD_RHEL8=0
BUILD_RHEL9=0
BUILD_DEBIAN=0
BUILD_UBUNTU=0

# Display help message
show_help() {
    echo "Usage: $0 [options]"
    echo
    echo "Options:"
    echo "  -c, --config FILE     Specify config file (default: $CONFIG_FILE)"
    echo "  -o, --output DIR      Specify output directory (default: $OUTPUT_DIR)"
    echo "  -v, --version VERSION Specify package version (required)"
    echo "  --rhel8               Build only for RHEL/CentOS 8"
    echo "  --rhel9               Build only for RHEL/CentOS 9"
    echo "  --debian              Build only for Debian (latest stable)"
    echo "  --ubuntu              Build only for Ubuntu (latest LTS)"
    echo "  --verbose             Enable verbose output"
    echo "  -h, --help            Show this help message"
    echo
    exit 1
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -v|--version)
            VERSION="$2"
            shift 2
            ;;
        --rhel8)
            BUILD_RHEL8=1
            BUILD_ALL=0
            shift
            ;;
        --rhel9)
            BUILD_RHEL9=1
            BUILD_ALL=0
            shift
            ;;
        --debian)
            BUILD_DEBIAN=1
            BUILD_ALL=0
            shift
            ;;
        --ubuntu)
            BUILD_UBUNTU=1
            BUILD_ALL=0
            shift
            ;;
        --verbose)
            VERBOSE=1
            shift
            ;;
        -h|--help)
            show_help
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            ;;
    esac
done

# Check if version is provided
if [ -z "$VERSION" ]; then
    echo "Error: Version is required. Use -v or --version to specify."
    show_help
fi

# Check if config file exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: Config file not found: $CONFIG_FILE"
    exit 1
fi

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Function to log messages
log() {
    local level=$1
    shift
    if [ "$level" = "INFO" ] || [ "$VERBOSE" -eq 1 ]; then
        echo "[$level] $@"
    fi
}

# Function to parse YAML config (basic implementation)
parse_config() {
    local key=$1
    grep "^$key:" "$CONFIG_FILE" | cut -d ':' -f 2- | sed 's/^[ \t]*//'
}

# Get package information from config
PACKAGE_NAME=$(parse_config "package_name")
PACKAGE_DESCRIPTION=$(parse_config "package_description")
PACKAGE_MAINTAINER=$(parse_config "package_maintainer")
PACKAGE_LICENSE=$(parse_config "package_license")

# Use version from command line instead of config file
log "INFO" "Building $PACKAGE_NAME version $VERSION"
log "DEBUG" "Using config file: $CONFIG_FILE"
log "DEBUG" "Output directory: $OUTPUT_DIR"

# Build for RHEL/CentOS 8
build_rhel8() {
    log "INFO" "Building package for RHEL/CentOS 8..."
    
    # Create temporary build directory
    local build_dir="./build_tmp/rhel8"
    rm -rf "$build_dir"
    mkdir -p "$build_dir"
    mkdir -p "$build_dir/SOURCES"
    mkdir -p "$build_dir/SPECS"
    mkdir -p "$build_dir/BUILD"
    mkdir -p "$build_dir/RPMS"
    mkdir -p "$build_dir/SRPMS"
    mkdir -p "$build_dir/BUILDROOT"
    
    log "INFO" "Creating directory structure..."
    # Create directory structure for the package
    mkdir -p "$build_dir/SOURCES/$PACKAGE_NAME-$VERSION"
    mkdir -p "$build_dir/SOURCES/$PACKAGE_NAME-$VERSION/usr/local/bin"
    mkdir -p "$build_dir/SOURCES/$PACKAGE_NAME-$VERSION/etc/$PACKAGE_NAME"
    mkdir -p "$build_dir/SOURCES/$PACKAGE_NAME-$VERSION/usr/share/$PACKAGE_NAME"
    mkdir -p "$build_dir/SOURCES/$PACKAGE_NAME-$VERSION/usr/lib/systemd/system"
    
    log "INFO" "Copying application files..."
    # Copy application files
    if [ -f "../bin/$PACKAGE_NAME" ]; then
        cp "../bin/$PACKAGE_NAME" "$build_dir/SOURCES/$PACKAGE_NAME-$VERSION/usr/local/bin/"
        log "INFO" "Copied binary file"
    else
        log "ERROR" "Binary file not found: ../bin/$PACKAGE_NAME"
        exit 1
    fi
    
    if [ -f "../config/$PACKAGE_NAME.conf" ]; then
        cp "../config/$PACKAGE_NAME.conf" "$build_dir/SOURCES/$PACKAGE_NAME-$VERSION/etc/$PACKAGE_NAME/"
        log "INFO" "Copied config file"
    else
        log "ERROR" "Config file not found: ../config/$PACKAGE_NAME.conf"
        exit 1
    fi
    
    if [ -d "../data" ]; then
        cp -r ../data/* "$build_dir/SOURCES/$PACKAGE_NAME-$VERSION/usr/share/$PACKAGE_NAME/"
        log "INFO" "Copied data files"
    else
        log "ERROR" "Data directory not found: ../data"
        exit 1
    fi
    
    log "INFO" "Creating systemd service file..."
    # Create systemd service file
    cat > "$build_dir/SOURCES/$PACKAGE_NAME-$VERSION/usr/lib/systemd/system/$PACKAGE_NAME.service" << EOF
[Unit]
Description=$PACKAGE_DESCRIPTION
After=network.target

[Service]
Type=simple
User=$PACKAGE_NAME
Group=$PACKAGE_NAME
ExecStart=/usr/local/bin/$PACKAGE_NAME --config /etc/$PACKAGE_NAME/$PACKAGE_NAME.conf
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
    
    log "INFO" "Creating tarball..."
    # Create tarball
    tar -czf "$build_dir/SOURCES/$PACKAGE_NAME-$VERSION.tar.gz" -C "$build_dir/SOURCES" "$PACKAGE_NAME-$VERSION"
    
    log "INFO" "Copying spec file template..."
    # Copy spec file template
    cp ./scripts/rhel8/package.spec "$build_dir/SPECS/"
    
    log "INFO" "Replacing placeholders in spec file..."
    # Replace placeholders in spec file
    sed -i "s|__PACKAGE_NAME__|$PACKAGE_NAME|g" "$build_dir/SPECS/package.spec"
    sed -i "s|__PACKAGE_VERSION__|$VERSION|g" "$build_dir/SPECS/package.spec"
    sed -i "s|__PACKAGE_DESCRIPTION__|$PACKAGE_DESCRIPTION|g" "$build_dir/SPECS/package.spec"
    sed -i "s|__PACKAGE_MAINTAINER__|$PACKAGE_MAINTAINER|g" "$build_dir/SPECS/package.spec"
    sed -i "s|__PACKAGE_LICENSE__|$PACKAGE_LICENSE|g" "$build_dir/SPECS/package.spec"
    
    # Replace __DATE__ with current date in format: Day Month Year
    local current_date=$(date "+%a %b %d %Y")
    sed -i "s|__DATE__|$current_date|g" "$build_dir/SPECS/package.spec"
    
    log "INFO" "Extracting dependencies from config file..."
    # Extract dependencies from config file and format them correctly
    local deps=$(grep -A 100 "rhel8_dependencies:" "$CONFIG_FILE" | grep -B 100 "rhel8_dependencies_end" | grep -v "rhel8_dependencies" | grep -v "^$" | sed 's/^[ \t]*- //' | tr '\n' ' ' | sed 's/[ ]*$//')
    log "INFO" "Dependencies: $deps"
    sed -i "s|__PACKAGE_DEPENDENCIES__|$deps|g" "$build_dir/SPECS/package.spec"
    
    log "INFO" "Running Docker container to build the package..."
    # Run Docker container to build the package
    docker run --rm -v "$(pwd)/$build_dir:/build" -v "$(pwd)/$OUTPUT_DIR:/output" \
        almalinux:8 /bin/bash -c "
            set -x
            cd /build && \
            dnf install -y rpm-build rpmdevtools && \
            rpmbuild --define '_topdir /build' -ba SPECS/package.spec && \
            cp /build/RPMS/*/*.rpm /output/ || { echo 'Build failed'; find /build -name '*.log' -exec cat {} \; 2>/dev/null || echo 'No build logs found'; exit 1; }"
    
    log "INFO" "RHEL/CentOS 8 package built successfully"
}

# Build for RHEL/CentOS 9
build_rhel9() {
    log "INFO" "Building package for RHEL/CentOS 9..."
    
    # Create temporary build directory
    local build_dir="./build_tmp/rhel9"
    rm -rf "$build_dir"
    mkdir -p "$build_dir"
    mkdir -p "$build_dir/SOURCES"
    mkdir -p "$build_dir/SPECS"
    mkdir -p "$build_dir/BUILD"
    mkdir -p "$build_dir/RPMS"
    mkdir -p "$build_dir/SRPMS"
    mkdir -p "$build_dir/BUILDROOT"
    
    log "INFO" "Creating directory structure..."
    # Create directory structure for the package
    mkdir -p "$build_dir/SOURCES/$PACKAGE_NAME-$VERSION"
    mkdir -p "$build_dir/SOURCES/$PACKAGE_NAME-$VERSION/usr/local/bin"
    mkdir -p "$build_dir/SOURCES/$PACKAGE_NAME-$VERSION/etc/$PACKAGE_NAME"
    mkdir -p "$build_dir/SOURCES/$PACKAGE_NAME-$VERSION/usr/share/$PACKAGE_NAME"
    mkdir -p "$build_dir/SOURCES/$PACKAGE_NAME-$VERSION/usr/lib/systemd/system"
    
    log "INFO" "Copying application files..."
    # Copy application files
    if [ -f "../bin/$PACKAGE_NAME" ]; then
        cp "../bin/$PACKAGE_NAME" "$build_dir/SOURCES/$PACKAGE_NAME-$VERSION/usr/local/bin/"
        log "INFO" "Copied binary file"
    else
        log "ERROR" "Binary file not found: ../bin/$PACKAGE_NAME"
        exit 1
    fi
    
    if [ -f "../config/$PACKAGE_NAME.conf" ]; then
        cp "../config/$PACKAGE_NAME.conf" "$build_dir/SOURCES/$PACKAGE_NAME-$VERSION/etc/$PACKAGE_NAME/"
        log "INFO" "Copied config file"
    else
        log "ERROR" "Config file not found: ../config/$PACKAGE_NAME.conf"
        exit 1
    fi
    
    if [ -d "../data" ]; then
        cp -r ../data/* "$build_dir/SOURCES/$PACKAGE_NAME-$VERSION/usr/share/$PACKAGE_NAME/"
        log "INFO" "Copied data files"
    else
        log "ERROR" "Data directory not found: ../data"
        exit 1
    fi
    
    log "INFO" "Creating systemd service file..."
    # Create systemd service file
    cat > "$build_dir/SOURCES/$PACKAGE_NAME-$VERSION/usr/lib/systemd/system/$PACKAGE_NAME.service" << EOF
[Unit]
Description=$PACKAGE_DESCRIPTION
After=network.target

[Service]
Type=simple
User=$PACKAGE_NAME
Group=$PACKAGE_NAME
ExecStart=/usr/local/bin/$PACKAGE_NAME --config /etc/$PACKAGE_NAME/$PACKAGE_NAME.conf
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
    
    log "INFO" "Creating tarball..."
    # Create tarball
    tar -czf "$build_dir/SOURCES/$PACKAGE_NAME-$VERSION.tar.gz" -C "$build_dir/SOURCES" "$PACKAGE_NAME-$VERSION"
    
    log "INFO" "Copying spec file template..."
    # Copy spec file template
    cp ./scripts/rhel9/package.spec "$build_dir/SPECS/"
    
    log "INFO" "Replacing placeholders in spec file..."
    # Replace placeholders in spec file
    sed -i "s|__PACKAGE_NAME__|$PACKAGE_NAME|g" "$build_dir/SPECS/package.spec"
    sed -i "s|__PACKAGE_VERSION__|$VERSION|g" "$build_dir/SPECS/package.spec"
    sed -i "s|__PACKAGE_DESCRIPTION__|$PACKAGE_DESCRIPTION|g" "$build_dir/SPECS/package.spec"
    sed -i "s|__PACKAGE_MAINTAINER__|$PACKAGE_MAINTAINER|g" "$build_dir/SPECS/package.spec"
    sed -i "s|__PACKAGE_LICENSE__|$PACKAGE_LICENSE|g" "$build_dir/SPECS/package.spec"
    
    # Replace __DATE__ with current date in format: Day Month Year
    local current_date=$(date "+%a %b %d %Y")
    sed -i "s|__DATE__|$current_date|g" "$build_dir/SPECS/package.spec"
    
    log "INFO" "Extracting dependencies from config file..."
    # Extract dependencies from config file and format them correctly
    local deps=$(grep -A 100 "rhel9_dependencies:" "$CONFIG_FILE" | grep -B 100 "rhel9_dependencies_end" | grep -v "rhel9_dependencies" | grep -v "^$" | sed 's/^[ \t]*- //' | tr '\n' ' ' | sed 's/[ ]*$//')
    sed -i "s|__PACKAGE_DEPENDENCIES__|$deps|g" "$build_dir/SPECS/package.spec"
    
    log "INFO" "Running Docker container to build the package..."
    # Run Docker container to build the package
    docker run --rm -v "$(pwd)/$build_dir:/build" -v "$(pwd)/$OUTPUT_DIR:/output" \
        almalinux:9 /bin/bash -c "
            set -x
            cd /build && \
            dnf install -y rpm-build rpmdevtools && \
            rpmbuild --define '_topdir /build' -ba SPECS/package.spec && \
            cp /build/RPMS/*/*.rpm /output/ || { echo 'Build failed'; find /build -name '*.log' -exec cat {} \; 2>/dev/null || echo 'No build logs found'; exit 1; }"
    
    log "INFO" "RHEL/CentOS 9 package built successfully"
    rm -rf "$build_dir"
}

# Build for Debian
build_debian() {
    log "INFO" "Building package for Debian..."
    
    # Create temporary build directory
    local build_dir="./build_tmp/debian"
    rm -rf "$build_dir"
    mkdir -p "$build_dir/DEBIAN"
    mkdir -p "$build_dir/usr/local/bin"
    mkdir -p "$build_dir/etc/$PACKAGE_NAME"
    mkdir -p "$build_dir/usr/share/$PACKAGE_NAME"
    mkdir -p "$build_dir/usr/lib/systemd/system"
    
    log "INFO" "Copying application files..."
    # Copy application files
    if [ -f "../bin/$PACKAGE_NAME" ]; then
        cp "../bin/$PACKAGE_NAME" "$build_dir/usr/local/bin/"
        log "INFO" "Copied binary file"
    else
        log "ERROR" "Binary file not found: ../bin/$PACKAGE_NAME"
        exit 1
    fi
    
    if [ -f "../config/$PACKAGE_NAME.conf" ]; then
        cp "../config/$PACKAGE_NAME.conf" "$build_dir/etc/$PACKAGE_NAME/"
        log "INFO" "Copied config file"
    else
        log "ERROR" "Config file not found: ../config/$PACKAGE_NAME.conf"
        exit 1
    fi
    
    if [ -d "../data" ]; then
        cp -r ../data/* "$build_dir/usr/share/$PACKAGE_NAME/"
        log "INFO" "Copied data files"
    else
        log "ERROR" "Data directory not found: ../data"
        exit 1
    fi
    
    # Copy and prepare DEBIAN control files
    cp -r ./scripts/debian/DEBIAN/* "$build_dir/DEBIAN/"
    
    # Replace placeholders in control files
    sed -i "s|__PACKAGE_NAME__|$PACKAGE_NAME|g" "$build_dir/DEBIAN/control"
    sed -i "s|__PACKAGE_VERSION__|$VERSION|g" "$build_dir/DEBIAN/control"
    sed -i "s|__PACKAGE_DESCRIPTION__|$PACKAGE_DESCRIPTION|g" "$build_dir/DEBIAN/control"
    sed -i "s|__PACKAGE_MAINTAINER__|$PACKAGE_MAINTAINER|g" "$build_dir/DEBIAN/control"
    
    # Replace placeholders in scripts
    for script in "$build_dir/DEBIAN"/*; do
        if [ -f "$script" ]; then
            sed -i "s|__PACKAGE_NAME__|$PACKAGE_NAME|g" "$script"
        fi
    done
    
    # Extract dependencies from config file and format them correctly
    local deps=$(grep -A 100 "debian_dependencies:" "$CONFIG_FILE" | grep -B 100 "debian_dependencies_end" | grep -v "debian_dependencies" | grep -v "^$" | sed 's/^[ \t]*- //' | tr '\n' ', ' | sed 's/,[ ]*$//')
    sed -i "s|__PACKAGE_DEPENDENCIES__|$deps|g" "$build_dir/DEBIAN/control"
    
    # Ensure there's a newline at the end of the control file
    sed -i -e '$a\' "$build_dir/DEBIAN/control"
    
    # Create systemd service file
    cat > "$build_dir/usr/lib/systemd/system/$PACKAGE_NAME.service" << EOF
[Unit]
Description=$PACKAGE_DESCRIPTION
After=network.target

[Service]
Type=simple
User=$PACKAGE_NAME
Group=$PACKAGE_NAME
ExecStart=/usr/local/bin/$PACKAGE_NAME --config /etc/$PACKAGE_NAME/$PACKAGE_NAME.conf
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
    
    log "INFO" "Running Docker container to build the package..."
    # Run Docker container to build the package
    docker run --rm -v "$(pwd)/$build_dir:/build" -v "$(pwd)/$OUTPUT_DIR:/output" \
        debian:stable /bin/bash -c "
            set -x
            apt-get update && \
            apt-get install -y dpkg-dev && \
            dpkg-deb --build /build /output/${PACKAGE_NAME}_${VERSION}_amd64.deb || { echo 'Build failed'; exit 1; }"
    
    log "INFO" "Debian package built successfully"
    rm -rf "$build_dir"
}

# Build for Ubuntu
build_ubuntu() {
    log "INFO" "Building package for Ubuntu..."
    
    # Create temporary build directory
    local build_dir="./build_tmp/ubuntu"
    rm -rf "$build_dir"
    mkdir -p "$build_dir/DEBIAN"
    mkdir -p "$build_dir/usr/local/bin"
    mkdir -p "$build_dir/etc/$PACKAGE_NAME"
    mkdir -p "$build_dir/usr/share/$PACKAGE_NAME"
    mkdir -p "$build_dir/usr/lib/systemd/system"
    
    log "INFO" "Copying application files..."
    # Copy application files
    if [ -f "../bin/$PACKAGE_NAME" ]; then
        cp "../bin/$PACKAGE_NAME" "$build_dir/usr/local/bin/"
        log "INFO" "Copied binary file"
    else
        log "ERROR" "Binary file not found: ../bin/$PACKAGE_NAME"
        exit 1
    fi
    
    if [ -f "../config/$PACKAGE_NAME.conf" ]; then
        cp "../config/$PACKAGE_NAME.conf" "$build_dir/etc/$PACKAGE_NAME/"
        log "INFO" "Copied config file"
    else
        log "ERROR" "Config file not found: ../config/$PACKAGE_NAME.conf"
        exit 1
    fi
    
    if [ -d "../data" ]; then
        cp -r ../data/* "$build_dir/usr/share/$PACKAGE_NAME/"
        log "INFO" "Copied data files"
    else
        log "ERROR" "Data directory not found: ../data"
        exit 1
    fi
    
    # Copy and prepare DEBIAN control files
    cp -r ./scripts/ubuntu/DEBIAN/* "$build_dir/DEBIAN/"
    
    # Replace placeholders in control files
    sed -i "s|__PACKAGE_NAME__|$PACKAGE_NAME|g" "$build_dir/DEBIAN/control"
    sed -i "s|__PACKAGE_VERSION__|$VERSION|g" "$build_dir/DEBIAN/control"
    sed -i "s|__PACKAGE_DESCRIPTION__|$PACKAGE_DESCRIPTION|g" "$build_dir/DEBIAN/control"
    sed -i "s|__PACKAGE_MAINTAINER__|$PACKAGE_MAINTAINER|g" "$build_dir/DEBIAN/control"
    
    # Replace placeholders in scripts
    for script in "$build_dir/DEBIAN"/*; do
        if [ -f "$script" ]; then
            sed -i "s|__PACKAGE_NAME__|$PACKAGE_NAME|g" "$script"
        fi
    done
    
    # Extract dependencies from config file and format them correctly
    local deps=$(grep -A 100 "ubuntu_dependencies:" "$CONFIG_FILE" | grep -B 100 "ubuntu_dependencies_end" | grep -v "ubuntu_dependencies" | grep -v "^$" | sed 's/^[ \t]*- //' | tr '\n' ', ' | sed 's/,[ ]*$//')
    sed -i "s|__PACKAGE_DEPENDENCIES__|$deps|g" "$build_dir/DEBIAN/control"
    
    # Ensure there's a newline at the end of the control file
    sed -i -e '$a\' "$build_dir/DEBIAN/control"
    
    # Create systemd service file
    cat > "$build_dir/usr/lib/systemd/system/$PACKAGE_NAME.service" << EOF
[Unit]
Description=$PACKAGE_DESCRIPTION
After=network.target

[Service]
Type=simple
User=$PACKAGE_NAME
Group=$PACKAGE_NAME
ExecStart=/usr/local/bin/$PACKAGE_NAME --config /etc/$PACKAGE_NAME/$PACKAGE_NAME.conf
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
    
    log "INFO" "Running Docker container to build the package..."
    # Run Docker container to build the package
    docker run --rm -v "$(pwd)/$build_dir:/build" -v "$(pwd)/$OUTPUT_DIR:/output" \
        ubuntu:22.04 /bin/bash -c "
            set -x
            apt-get update && \
            apt-get install -y dpkg-dev && \
            dpkg-deb --build /build /output/${PACKAGE_NAME}_${VERSION}_amd64.deb || { echo 'Build failed'; exit 1; }"
    
    log "INFO" "Ubuntu package built successfully"
    rm -rf "$build_dir"
}

# Build packages based on command line options
if [ "$BUILD_ALL" -eq 1 ] || [ "$BUILD_RHEL8" -eq 1 ]; then
    build_rhel8
fi

if [ "$BUILD_ALL" -eq 1 ] || [ "$BUILD_RHEL9" -eq 1 ]; then
    build_rhel9
fi

if [ "$BUILD_ALL" -eq 1 ] || [ "$BUILD_DEBIAN" -eq 1 ]; then
    build_debian
fi

if [ "$BUILD_ALL" -eq 1 ] || [ "$BUILD_UBUNTU" -eq 1 ]; then
    build_ubuntu
fi

log "INFO" "All packages built successfully"
log "INFO" "Packages are available in $OUTPUT_DIR" 

# Clean up temporary build directories
log "INFO" "Cleaning up temporary build directories..."
rm -rf ./build_tmp
log "INFO" "Cleanup completed" 