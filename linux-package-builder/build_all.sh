#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/dist"

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Function to run a build script and track its success/failure
run_build_script() {
    local script_name="$1"
    local package_type="$2"
    local distribution="$3"
    
    echo -e "\n${YELLOW}Building $package_type package for $distribution...${NC}"
    
    if [ -x "$SCRIPT_DIR/$script_name" ]; then
        if "$SCRIPT_DIR/$script_name"; then
            echo -e "${GREEN}✓ Successfully built $package_type package for $distribution${NC}"
            return 0
        else
            echo -e "${RED}✗ Failed to build $package_type package for $distribution${NC}"
            return 1
        fi
    else
        echo -e "${RED}✗ Build script $script_name not found or not executable${NC}"
        chmod +x "$SCRIPT_DIR/$script_name"
        echo -e "${YELLOW}Made $script_name executable, trying again...${NC}"
        
        if "$SCRIPT_DIR/$script_name"; then
            echo -e "${GREEN}✓ Successfully built $package_type package for $distribution${NC}"
            return 0
        else
            echo -e "${RED}✗ Failed to build $package_type package for $distribution${NC}"
            return 1
        fi
    fi
}

# Check for required files
echo -e "${YELLOW}Checking for required files...${NC}"
if [ -x "$SCRIPT_DIR/check_files.sh" ]; then
    "$SCRIPT_DIR/check_files.sh"
else
    chmod +x "$SCRIPT_DIR/check_files.sh"
    "$SCRIPT_DIR/check_files.sh"
fi

# Initialize counters
total=0
success=0
failed=0
failed_builds=""

# Build RPM package for RHEL/CentOS 8
total=$((total+1))
if run_build_script "build_rpm.sh" "RPM" "RHEL/CentOS 8"; then
    success=$((success+1))
else
    failed=$((failed+1))
    failed_builds="$failed_builds\n- RPM for RHEL/CentOS 8"
fi

# Build RPM package for RHEL/CentOS 9
total=$((total+1))
if run_build_script "build_rhel9.sh" "RPM" "RHEL/CentOS 9"; then
    success=$((success+1))
else
    failed=$((failed+1))
    failed_builds="$failed_builds\n- RPM for RHEL/CentOS 9"
fi

# Build DEB package for Debian 11
total=$((total+1))
if run_build_script "build_debian.sh" "DEB" "Debian 11"; then
    success=$((success+1))
else
    failed=$((failed+1))
    failed_builds="$failed_builds\n- DEB for Debian 11"
fi

# Build DEB package for Ubuntu 22.04
total=$((total+1))
if run_build_script "build_ubuntu.sh" "DEB" "Ubuntu 22.04"; then
    success=$((success+1))
else
    failed=$((failed+1))
    failed_builds="$failed_builds\n- DEB for Ubuntu 22.04"
fi

# Print summary
echo -e "\n${YELLOW}=== Build Summary ===${NC}"
echo -e "Total builds: $total"
echo -e "${GREEN}Successful builds: $success${NC}"
if [ $failed -gt 0 ]; then
    echo -e "${RED}Failed builds: $failed${NC}"
    echo -e "${RED}Failed packages:$failed_builds${NC}"
fi

# List built packages
echo -e "\n${YELLOW}=== Built Packages ===${NC}"
if [ -d "$OUTPUT_DIR/rhel8" ] && [ "$(ls -A "$OUTPUT_DIR/rhel8" 2>/dev/null)" ]; then
    echo -e "${GREEN}RHEL/CentOS 8 packages:${NC}"
    ls -la "$OUTPUT_DIR/rhel8"
fi

if [ -d "$OUTPUT_DIR/rhel9" ] && [ "$(ls -A "$OUTPUT_DIR/rhel9" 2>/dev/null)" ]; then
    echo -e "${GREEN}RHEL/CentOS 9 packages:${NC}"
    ls -la "$OUTPUT_DIR/rhel9"
fi

if [ -d "$OUTPUT_DIR/debian11" ] && [ "$(ls -A "$OUTPUT_DIR/debian11" 2>/dev/null)" ]; then
    echo -e "${GREEN}Debian 11 packages:${NC}"
    ls -la "$OUTPUT_DIR/debian11"
fi

if [ -d "$OUTPUT_DIR/ubuntu2204" ] && [ "$(ls -A "$OUTPUT_DIR/ubuntu2204" 2>/dev/null)" ]; then
    echo -e "${GREEN}Ubuntu 22.04 packages:${NC}"
    ls -la "$OUTPUT_DIR/ubuntu2204"
fi

# Exit with appropriate status code
if [ $failed -gt 0 ]; then
    echo -e "\n${RED}Some builds failed. Please check the logs for details.${NC}"
    exit 1
else
    echo -e "\n${GREEN}All builds completed successfully!${NC}"
    exit 0
fi 