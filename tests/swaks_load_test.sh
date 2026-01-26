#!/bin/bash

# Elemta SMTP Server - Swaks Load Test Script
# Runs concurrent swaks instances to generate load

SERVER="localhost"
PORT="2525"
CORPUS_FILE="tests/corpus/clean-text.eml"
CONCURRENCY=10
TOTAL_MESSAGES=100

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
        -h|--help)
            echo "Usage: $0 [-c concurrency] [-n total_messages]"
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
pids=()

# Function to run a batch
run_batch() {
    local batch_size=$1
    local batch_id=$2
    
    for ((i=1; i<=batch_size; i++)); do
        # Use a unique subject for tracking
        local subject="Load Test Batch $batch_id Msg $i"
        
        # Run swaks in background
        (
            if cat "$CORPUS_FILE" | sed "s/^Subject: .*/Subject: $subject/" | swaks --server "$SERVER" --port "$PORT" --from "loadtest@example.com" --to "demo@example.com" --data - --hide-all --quit-after DATA > "$LOG_DIR/$batch_id-$i.log" 2>&1; then
                echo -n "."
            else
                echo -n "E"
            fi
        ) &
        
        pids+=($!)
        
        # Limit concurrency
        if [[ ${#pids[@]} -ge $CONCURRENCY ]]; then
            wait -n
            # Remove finished PID from array (simplified approach: just wait for one slot)
            # In bash, managing the exact array of running PIDs is tricky without 'wait -n' which is available in newer bash.
            # Assuming bash 4.3+ which has wait -n
            
            # Actually, a simpler way to manage concurrency in bash is using xargs or GNU parallel.
            # But since we want to stick to pure bash if possible, let's use a semaphore approach or just batches.
        fi
    done
}

# Better approach for concurrency in bash without external tools:
# Use a semaphore loop
run_load() {
    local active_jobs=0
    
    for ((i=1; i<=TOTAL_MESSAGES; i++)); do
        local subject="Load Test Msg $i"
        
        (
            if cat "$CORPUS_FILE" | sed "s/^Subject: .*/Subject: $subject/" | swaks --server "$SERVER" --port "$PORT" --from "loadtest@example.com" --to "demo@example.com" --data - > "$LOG_DIR/$i.log" 2>&1; then
                echo -n "."
            else
                echo -n "E"
            fi
        ) &
        
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
success_count=$(grep -l "250 2.0.0 Message accepted" "$LOG_DIR"/*.log | wc -l)
fail_count=$((TOTAL_MESSAGES - success_count))

echo "=================================================="
echo -e "${YELLOW}Test Complete${NC}"
echo "Duration: $(printf "%.2f" $duration)s"
echo "Throughput: $(printf "%.2f" $rate) msgs/sec"
echo -e "Successful: ${GREEN}$success_count${NC}"
echo -e "Failed: ${RED}$fail_count${NC}"

if [ $fail_count -gt 0 ]; then
    echo -e "${RED}Some messages failed. Check logs in $LOG_DIR${NC}"
    echo "Sample error:"
    grep -L "250 2.0.0 Message accepted" "$LOG_DIR"/*.log | head -1 | xargs cat
else
    echo -e "${GREEN}All messages accepted!${NC}"
    rm -rf "$LOG_DIR"
fi
