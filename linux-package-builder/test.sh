#!/bin/bash
set -e

# Package testing script
# This script tests the packages built by build.sh

# Default values
OUTPUT_DIR="./dist"
VERBOSE=0
TEST_ALL=1
TEST_RHEL8=0
TEST_RHEL9=0
TEST_DEBIAN=0
TEST_UBUNTU=0
CLEANUP=1

# Display help message
show_help() {
    echo "Usage: $0 [options]"
    echo
    echo "Options:"
    echo "  -o, --output DIR      Specify output directory with packages (default: $OUTPUT_DIR)"
    echo "  --rhel8               Test only RHEL/CentOS 8 package"
    echo "  --rhel9               Test only RHEL/CentOS 9 package"
    echo "  --debian              Test only Debian package"
    echo "  --ubuntu              Test only Ubuntu package"
    echo "  --no-cleanup          Don't remove test containers after testing"
    echo "  --verbose             Enable verbose output"
    echo "  -h, --help            Show this help message"
    echo
    exit 1
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --rhel8)
            TEST_RHEL8=1
            TEST_ALL=0
            shift
            ;;
        --rhel9)
            TEST_RHEL9=1
            TEST_ALL=0
            shift
            ;;
        --debian)
            TEST_DEBIAN=1
            TEST_ALL=0
            shift
            ;;
        --ubuntu)
            TEST_UBUNTU=1
            TEST_ALL=0
            shift
            ;;
        --no-cleanup)
            CLEANUP=0
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

# Check if output directory exists
if [ ! -d "$OUTPUT_DIR" ]; then
    echo "Error: Output directory not found: $OUTPUT_DIR"
    exit 1
fi

# Function to log messages
log() {
    local level=$1
    shift
    if [ "$level" = "INFO" ] || [ "$VERBOSE" -eq 1 ]; then
        echo "[$level] $@"
    fi
}

# Function to find the latest package in the output directory
find_latest_package() {
    local pattern=$1
    find "$OUTPUT_DIR" -name "$pattern" -type f -printf "%T@ %p\n" | sort -n | tail -1 | cut -f2- -d" "
}

# Test RHEL/CentOS 8 package
test_rhel8() {
    log "INFO" "Testing package for RHEL/CentOS 8..."
    
    # Find the latest RPM package
    local package=$(find_latest_package "*.rpm")
    if [ -z "$package" ]; then
        log "ERROR" "No RPM package found in $OUTPUT_DIR"
        return 1
    fi
    
    log "INFO" "Found package: $package"
    local package_name=$(basename "$package")
    
    # Create a unique container name
    local container_name="test-rhel8-$(date +%s)"
    
    # Run Docker container to test the package
    log "INFO" "Starting test container..."
    docker run --name "$container_name" -d centos:8 sleep infinity
    
    # Copy the package to the container
    log "INFO" "Copying package to container..."
    docker cp "$package" "$container_name:/tmp/$package_name"
    
    # Install the package
    log "INFO" "Installing package..."
    docker exec "$container_name" bash -c "
        dnf install -y /tmp/$package_name && 
        echo 'Package installed successfully' && 
        systemctl status myapp.service || true"
    
    # Verify the installation
    log "INFO" "Verifying installation..."
    docker exec "$container_name" bash -c "
        if [ -f /usr/local/bin/myapp ]; then
            echo 'Binary exists: OK'
        else
            echo 'Binary not found: FAIL'
            exit 1
        fi
        
        if [ -f /etc/myapp/myapp.conf ]; then
            echo 'Config exists: OK'
        else
            echo 'Config not found: FAIL'
            exit 1
        fi
        
        if getent passwd myapp > /dev/null; then
            echo 'User created: OK'
        else
            echo 'User not created: FAIL'
            exit 1
        fi"
    
    # Cleanup
    if [ "$CLEANUP" -eq 1 ]; then
        log "INFO" "Cleaning up test container..."
        docker stop "$container_name" > /dev/null
        docker rm "$container_name" > /dev/null
    else
        log "INFO" "Test container '$container_name' left running for inspection"
    fi
    
    log "INFO" "RHEL/CentOS 8 package test completed successfully"
}

# Test RHEL/CentOS 9 package
test_rhel9() {
    log "INFO" "Testing package for RHEL/CentOS 9..."
    
    # Find the latest RPM package
    local package=$(find_latest_package "*.rpm")
    if [ -z "$package" ]; then
        log "ERROR" "No RPM package found in $OUTPUT_DIR"
        return 1
    fi
    
    log "INFO" "Found package: $package"
    local package_name=$(basename "$package")
    
    # Create a unique container name
    local container_name="test-rhel9-$(date +%s)"
    
    # Run Docker container to test the package
    log "INFO" "Starting test container..."
    docker run --name "$container_name" -d almalinux:9 sleep infinity
    
    # Copy the package to the container
    log "INFO" "Copying package to container..."
    docker cp "$package" "$container_name:/tmp/$package_name"
    
    # Install the package
    log "INFO" "Installing package..."
    docker exec "$container_name" bash -c "
        dnf install -y /tmp/$package_name && 
        echo 'Package installed successfully' && 
        systemctl status myapp.service || true"
    
    # Verify the installation
    log "INFO" "Verifying installation..."
    docker exec "$container_name" bash -c "
        if [ -f /usr/local/bin/myapp ]; then
            echo 'Binary exists: OK'
        else
            echo 'Binary not found: FAIL'
            exit 1
        fi
        
        if [ -f /etc/myapp/myapp.conf ]; then
            echo 'Config exists: OK'
        else
            echo 'Config not found: FAIL'
            exit 1
        fi
        
        if getent passwd myapp > /dev/null; then
            echo 'User created: OK'
        else
            echo 'User not created: FAIL'
            exit 1
        fi"
    
    # Cleanup
    if [ "$CLEANUP" -eq 1 ]; then
        log "INFO" "Cleaning up test container..."
        docker stop "$container_name" > /dev/null
        docker rm "$container_name" > /dev/null
    else
        log "INFO" "Test container '$container_name' left running for inspection"
    fi
    
    log "INFO" "RHEL/CentOS 9 package test completed successfully"
}

# Test Debian package
test_debian() {
    log "INFO" "Testing package for Debian..."
    
    # Find the latest DEB package
    local package=$(find_latest_package "*.deb")
    if [ -z "$package" ]; then
        log "ERROR" "No DEB package found in $OUTPUT_DIR"
        return 1
    fi
    
    log "INFO" "Found package: $package"
    local package_name=$(basename "$package")
    
    # Create a unique container name
    local container_name="test-debian-$(date +%s)"
    
    # Run Docker container to test the package
    log "INFO" "Starting test container..."
    docker run --name "$container_name" -d debian:stable sleep infinity
    
    # Copy the package to the container
    log "INFO" "Copying package to container..."
    docker cp "$package" "$container_name:/tmp/$package_name"
    
    # Install the package
    log "INFO" "Installing package..."
    docker exec "$container_name" bash -c "
        apt-get update && 
        apt-get install -y /tmp/$package_name && 
        echo 'Package installed successfully' && 
        systemctl status myapp.service || true"
    
    # Verify the installation
    log "INFO" "Verifying installation..."
    docker exec "$container_name" bash -c "
        if [ -f /usr/local/bin/myapp ]; then
            echo 'Binary exists: OK'
        else
            echo 'Binary not found: FAIL'
            exit 1
        fi
        
        if [ -f /etc/myapp/myapp.conf ]; then
            echo 'Config exists: OK'
        else
            echo 'Config not found: FAIL'
            exit 1
        fi
        
        if getent passwd myapp > /dev/null; then
            echo 'User created: OK'
        else
            echo 'User not created: FAIL'
            exit 1
        fi"
    
    # Cleanup
    if [ "$CLEANUP" -eq 1 ]; then
        log "INFO" "Cleaning up test container..."
        docker stop "$container_name" > /dev/null
        docker rm "$container_name" > /dev/null
    else
        log "INFO" "Test container '$container_name' left running for inspection"
    fi
    
    log "INFO" "Debian package test completed successfully"
}

# Test Ubuntu package
test_ubuntu() {
    log "INFO" "Testing package for Ubuntu..."
    
    # Find the latest DEB package
    local package=$(find_latest_package "*.deb")
    if [ -z "$package" ]; then
        log "ERROR" "No DEB package found in $OUTPUT_DIR"
        return 1
    fi
    
    log "INFO" "Found package: $package"
    local package_name=$(basename "$package")
    
    # Create a unique container name
    local container_name="test-ubuntu-$(date +%s)"
    
    # Run Docker container to test the package
    log "INFO" "Starting test container..."
    docker run --name "$container_name" -d ubuntu:22.04 sleep infinity
    
    # Copy the package to the container
    log "INFO" "Copying package to container..."
    docker cp "$package" "$container_name:/tmp/$package_name"
    
    # Install the package
    log "INFO" "Installing package..."
    docker exec "$container_name" bash -c "
        apt-get update && 
        apt-get install -y /tmp/$package_name && 
        echo 'Package installed successfully' && 
        systemctl status myapp.service || true"
    
    # Verify the installation
    log "INFO" "Verifying installation..."
    docker exec "$container_name" bash -c "
        if [ -f /usr/local/bin/myapp ]; then
            echo 'Binary exists: OK'
        else
            echo 'Binary not found: FAIL'
            exit 1
        fi
        
        if [ -f /etc/myapp/myapp.conf ]; then
            echo 'Config exists: OK'
        else
            echo 'Config not found: FAIL'
            exit 1
        fi
        
        if getent passwd myapp > /dev/null; then
            echo 'User created: OK'
        else
            echo 'User not created: FAIL'
            exit 1
        fi"
    
    # Cleanup
    if [ "$CLEANUP" -eq 1 ]; then
        log "INFO" "Cleaning up test container..."
        docker stop "$container_name" > /dev/null
        docker rm "$container_name" > /dev/null
    else
        log "INFO" "Test container '$container_name' left running for inspection"
    fi
    
    log "INFO" "Ubuntu package test completed successfully"
}

# Run tests based on command line options
if [ "$TEST_ALL" -eq 1 ] || [ "$TEST_RHEL8" -eq 1 ]; then
    test_rhel8
fi

if [ "$TEST_ALL" -eq 1 ] || [ "$TEST_RHEL9" -eq 1 ]; then
    test_rhel9
fi

if [ "$TEST_ALL" -eq 1 ] || [ "$TEST_DEBIAN" -eq 1 ]; then
    test_debian
fi

if [ "$TEST_ALL" -eq 1 ] || [ "$TEST_UBUNTU" -eq 1 ]; then
    test_ubuntu
fi

log "INFO" "All tests completed successfully" 