#!/bin/bash

# Elemta SMTP Server - Swaks Corpus Test Script
# Runs a set of email samples against the local Elemta server using swaks

SERVER="localhost"
PORT="2525"
CORPUS_DIR="tests/corpus"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Starting Swaks Corpus Test against $SERVER:$PORT${NC}"
echo "=================================================="

# Check if swaks is installed
if ! command -v swaks &> /dev/null; then
    echo -e "${RED}Error: swaks is not installed.${NC}"
    exit 1
fi

# Check if corpus directory exists
if [ ! -d "$CORPUS_DIR" ]; then
    echo -e "${RED}Error: Corpus directory $CORPUS_DIR not found.${NC}"
    exit 1
fi

# Function to run test
run_test() {
    local file=$1
    local expected_result=$2 # "accept" or "reject"
    local description=$3

    echo -e "\n${YELLOW}Testing: $description ($file)${NC}"
    
    # Run swaks
    # We use --data - to read from stdin
    # We use sed to dynamically update the Subject header to match the test description
    output=$(cat "$file" | sed "s/^Subject: .*/Subject: $description/" | swaks --server "$SERVER" --port "$PORT" --from "test@example.com" --to "demo@example.com" --data - 2>&1)
    exit_code=$?
    
    # Check result
    if [ "$expected_result" == "accept" ]; then
        if [[ "$output" == *"250 2.0.0 Message accepted"* ]]; then
            echo -e "${GREEN}✅ PASSED: Message accepted as expected.${NC}"
        else
            echo -e "${RED}❌ FAILED: Message rejected or error occurred.${NC}"
            echo "$output" | grep -E "^\<|^ \*" | tail -n 5
        fi
    else # expected reject
        if [[ "$output" == *"554"* ]] || [[ "$output" == *"550"* ]] || [[ "$output" == *"REJECT"* ]]; then
             echo -e "${GREEN}✅ PASSED: Message rejected as expected.${NC}"
             echo "$output" | grep -E "^\<" | tail -n 1
        else
             echo -e "${RED}❌ FAILED: Message accepted but should have been rejected.${NC}"
             echo "$output" | grep -E "^\<|^ \*" | tail -n 5
        fi
    fi
}

# Run tests
run_test "$CORPUS_DIR/clean-text.eml" "accept" "Clean Text Message"
run_test "$CORPUS_DIR/clean-html.eml" "accept" "Clean HTML Message"
run_test "$CORPUS_DIR/spam-gtube.eml" "reject" "GTUBE Spam Message"
run_test "$CORPUS_DIR/virus-eicar.eml" "reject" "EICAR Virus Message"

echo -e "\n${YELLOW}Test run complete.${NC}"
