#!/bin/bash

# Set error handling
set -e

# Color definitions
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Project root directory
ROOT_DIR="$(pwd)"
VENV_DIR="$ROOT_DIR/venv"

echo -e "${BLUE}===================================${NC}"
echo -e "${BLUE}   Elemta Test Suite Runner        ${NC}"
echo -e "${BLUE}===================================${NC}"

# ===== Run Go unit tests =====
echo -e "\n${YELLOW}Running Go unit tests...${NC}\n"
start_time=$(date +%s)
go test -v ./...
end_time=$(date +%s)
duration=$((end_time - start_time))
echo -e "\n${GREEN}✓ Go tests completed in ${duration}s${NC}\n"

# ===== Set up Python environment =====
echo -e "${YELLOW}Setting up Python environment...${NC}"

# Check if venv exists, create if it doesn't
if [ ! -d "$VENV_DIR" ]; then
    echo -e "Creating virtual environment..."
    python -m venv "$VENV_DIR"
fi

# Activate virtual environment
source "$VENV_DIR/bin/activate"

# Install required packages
echo -e "Installing required Python packages..."
pip install -q pytest python-dotenv requests pytest-timeout

# ===== Run Python e2e tests =====
echo -e "\n${YELLOW}Running Python e2e tests...${NC}\n"
start_time=$(date +%s)
cd "$ROOT_DIR"
python -m pytest -v tests/python/e2e/
e2e_result=$?
end_time=$(date +%s)
duration=$((end_time - start_time))

if [ $e2e_result -eq 0 ]; then
    echo -e "\n${GREEN}✓ Python e2e tests completed in ${duration}s${NC}"
else
    echo -e "\n${RED}✗ Python e2e tests failed${NC}"
    deactivate
    exit 1
fi

# Deactivate Python virtual environment
deactivate

echo -e "\n${GREEN}===================================${NC}"
echo -e "${GREEN}   All Tests Passed Successfully!   ${NC}"
echo -e "${GREEN}===================================${NC}"

exit 0 