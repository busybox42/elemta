#!/bin/bash
set -ex

# Create the directory structure
mkdir -p dist/rhel8
mkdir -p dist/rhel9
mkdir -p dist/debian11
mkdir -p dist/ubuntu2204

# Create dummy files
touch dist/rhel8/elemta-0.0.1-1.el8.x86_64.rpm
touch dist/rhel9/elemta-0.0.1-1.el9.x86_64.rpm
touch dist/debian11/elemta_0.0.1_amd64.deb
touch dist/ubuntu2204/elemta_0.0.1_amd64.deb

# List the directory structure
echo "Directory structure created:"
find dist -type d | sort

echo "Dummy files created:"
find dist -type f | sort 