#!/bin/bash

# Elemta SMTP Server - Swaks Load Test Script
# Runs concurrent swaks instances to generate load

SERVER="localhost"
PORT="2525"
CORPUS_FILE="tests/corpus/clean-text.eml"
CONCURRENCY=10
TOTAL_MESSAGES=100
EXPECTED="accept"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--concurrency)
            CONCURRENCY="$2"
            shift 2
            ;;
        -n|--total)
            TOTAL_MESSAGES="$2"
            shift 2
            ;;
        -f|--file)
            CORPUS_FILE="$2"
            shift 2
            ;;
        -e|--expect)
            EXPECTED="$2"
            if [[ "$EXPECTED" != "accept" && "$EXPECTED" != "reject" ]]; then
                echo "Error: --expect must be 'accept' or 'reject'"
                exit 1
            fi
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [-c concurrency] [-n total_messages] [-f corpus_file] [-e accept|reject]"
            exit 0
            ;;
        *)
            echo "Unknown argument: $1"
            exit 1
            ;;
    esac
done

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Starting Swaks Load Test against $SERVER:$PORT${NC}"
echo "Concurrency: $CONCURRENCY"
echo "Total Messages: $TOTAL_MESSAGES"
echo "Corpus File: $CORPUS_FILE"
echo "Expected Result: $EXPECTED"
echo "=================================================="

# Check if swaks is installed
if ! command -v swaks &> /dev/null; then
    echo -e "${RED}Error: swaks is not installed.${NC}"
    exit 1
fi

# Create a temporary directory for logs
LOG_DIR=$(mktemp -d)
echo "Logs will be stored in $LOG_DIR"

start_time=$(date +%s.%N)
count=0

# Function to run a single message
run_message() {
    local i=$1
    local subject="Load Test Msg $i ($EXPECTED)"
    
    # Run swaks and capture output
    if cat "$CORPUS_FILE" | sed "s/^Subject: .*/Subject: $subject/" | swaks --server "$SERVER" --port "$PORT" --from "loadtest@example.com" --to "demo@example.com" --data - > "$LOG_DIR/$i.log" 2>&1; then
        # Swaks exit code 0 usually means SMTP transaction completed (even if rejected)
        :
    fi
    
    # Check the log file for the result
    if [ "$EXPECTED" == "accept" ]; then
        if grep -q "250 2.0.0 Message accepted" "$LOG_DIR/$i.log"; then
            echo -n "."
        else
            echo -n "F"
        fi
    else # expect reject
        if grep -qE "554|550|REJECT" "$LOG_DIR/$i.log"; then
            echo -n "."
        else
            echo -n "F"
        fi
    fi
}

# Run load with concurrency
run_load() {
    local active_jobs=0
    
    for ((i=1; i<=TOTAL_MESSAGES; i++)); do
        ( run_message "$i" ) &
        
        ((active_jobs++))
        
        if [[ $active_jobs -ge $CONCURRENCY ]]; then
            wait -n
            ((active_jobs--))
        fi
    done
    
    wait
}

echo "Sending messages..."
run_load
echo ""

end_time=$(date +%s.%N)
duration=$(echo "$end_time - $start_time" | bc)
rate=$(echo "$TOTAL_MESSAGES / $duration" | bc)

# Analyze results
if [ "$EXPECTED" == "accept" ]; then
    success_count=$(grep -l "250 2.0.0 Message accepted" "$LOG_DIR"/*.log | wc -l)
else
    success_count=$(grep -lE "554|550|REJECT" "$LOG_DIR"/*.log | wc -l)
fi

fail_count=$((TOTAL_MESSAGES - success_count))

echo "=================================================="
echo -e "${YELLOW}Test Complete${NC}"
echo "Duration: $(printf "%.2f" $duration)s"
echo "Throughput: $(printf "%.2f" $rate) msgs/sec"
echo -e "Successful ($EXPECTED): ${GREEN}$success_count${NC}"
echo -e "Failed: ${RED}$fail_count${NC}"

if [ $fail_count -gt 0 ]; then
    echo -e "${RED}Some messages failed to match expectation. Check logs in $LOG_DIR${NC}"
    echo "Sample failure:"
    if [ "$EXPECTED" == "accept" ]; then
        grep -L "250 2.0.0 Message accepted" "$LOG_DIR"/*.log | head -1 | xargs cat
    else
        grep -L -E "554|550|REJECT" "$LOG_DIR"/*.log | head -1 | xargs cat
    fi
else
    echo -e "${GREEN}All messages matched expectation!${NC}"
    rm -rf "$LOG_DIR"
fi
