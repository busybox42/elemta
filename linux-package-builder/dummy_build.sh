#!/bin/bash
set -ex

# Package information
PACKAGE_NAME="elemta"
VERSION="0.0.1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/dist"

echo "Script directory: $SCRIPT_DIR"
echo "Output directory: $OUTPUT_DIR"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Create dummy RHEL8 RPM file
mkdir -p "$OUTPUT_DIR/rhel8"
touch "$OUTPUT_DIR/rhel8/$PACKAGE_NAME-$VERSION-1.el8.x86_64.rpm"
echo "Created dummy RHEL8 package: $OUTPUT_DIR/rhel8/$PACKAGE_NAME-$VERSION-1.el8.x86_64.rpm"

# Create dummy RHEL9 RPM file
mkdir -p "$OUTPUT_DIR/rhel9"
touch "$OUTPUT_DIR/rhel9/$PACKAGE_NAME-$VERSION-1.el9.x86_64.rpm"
echo "Created dummy RHEL9 package: $OUTPUT_DIR/rhel9/$PACKAGE_NAME-$VERSION-1.el9.x86_64.rpm"

# Create dummy Debian 11 package
mkdir -p "$OUTPUT_DIR/debian11"
touch "$OUTPUT_DIR/debian11/${PACKAGE_NAME}_${VERSION}_amd64.deb"
echo "Created dummy Debian 11 package: $OUTPUT_DIR/debian11/${PACKAGE_NAME}_${VERSION}_amd64.deb"

# Create dummy Ubuntu 22.04 package
mkdir -p "$OUTPUT_DIR/ubuntu2204"
touch "$OUTPUT_DIR/ubuntu2204/${PACKAGE_NAME}_${VERSION}_amd64.deb"
echo "Created dummy Ubuntu 22.04 package: $OUTPUT_DIR/ubuntu2204/${PACKAGE_NAME}_${VERSION}_amd64.deb"

# List all packages
echo "All packages:"
find "$OUTPUT_DIR" -type f | sort 