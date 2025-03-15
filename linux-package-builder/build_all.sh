#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/dist"

# Create output directory structure
mkdir -p "$OUTPUT_DIR/rhel8"
mkdir -p "$OUTPUT_DIR/rhel9"
mkdir -p "$OUTPUT_DIR/debian11"
mkdir -p "$OUTPUT_DIR/ubuntu2204"

echo -e "${YELLOW}Building all packages for elemta version 0.0.1${NC}"
echo -e "${YELLOW}Output directory: $OUTPUT_DIR${NC}"

# Function to run a build script and report success/failure
run_build() {
    local script=$1
    local name=$2
    
    echo -e "\n${YELLOW}Building $name package...${NC}"
    
    if [ -f "$SCRIPT_DIR/$script" ]; then
        chmod +x "$SCRIPT_DIR/$script"
        if "$SCRIPT_DIR/$script"; then
            echo -e "${GREEN}✓ $name package built successfully${NC}"
            return 0
        else
            echo -e "${RED}✗ $name package build failed${NC}"
            return 1
        fi
    else
        echo -e "${RED}✗ Build script not found: $script${NC}"
        return 1
    fi
}

# Build all packages
failed=0

run_build "build_rpm.sh" "RHEL 8" || ((failed++))
run_build "build_rhel9.sh" "RHEL 9" || ((failed++))
run_build "build_debian.sh" "Debian 11" || ((failed++))
run_build "build_ubuntu.sh" "Ubuntu 22.04" || ((failed++))

# Summary
echo -e "\n${YELLOW}Build Summary:${NC}"
if [ -d "$OUTPUT_DIR" ]; then
    echo -e "${GREEN}Available packages:${NC}"
    
    # List packages by distribution
    echo -e "\n${YELLOW}RHEL 8 packages:${NC}"
    ls -la "$OUTPUT_DIR/rhel8" 2>/dev/null || echo "No packages found"
    
    echo -e "\n${YELLOW}RHEL 9 packages:${NC}"
    ls -la "$OUTPUT_DIR/rhel9" 2>/dev/null || echo "No packages found"
    
    echo -e "\n${YELLOW}Debian 11 packages:${NC}"
    ls -la "$OUTPUT_DIR/debian11" 2>/dev/null || echo "No packages found"
    
    echo -e "\n${YELLOW}Ubuntu 22.04 packages:${NC}"
    ls -la "$OUTPUT_DIR/ubuntu2204" 2>/dev/null || echo "No packages found"
else
    echo -e "${RED}No output directory found${NC}"
fi

if [ $failed -eq 0 ]; then
    echo -e "\n${GREEN}All packages built successfully!${NC}"
    exit 0
else
    echo -e "\n${RED}$failed package builds failed${NC}"
    exit 1
fi 