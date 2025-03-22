#!/bin/bash
# elemta-api.sh - Shell script for interacting with Elemta API

# Default settings
API_URL="http://localhost:8081"
FORMAT="text"  # can be text, json, yaml
VERBOSE=false

# Color codes for output formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_help() {
    echo -e "${BLUE}Elemta API Helper Script${NC}"
    echo
    echo "Usage: $0 [options] <command> [args]"
    echo
    echo "Options:"
    echo "  -u, --url URL        API URL (default: $API_URL)"
    echo "  -f, --format FORMAT  Output format: text, json, yaml (default: $FORMAT)"
    echo "  -v, --verbose        Verbose output"
    echo "  -h, --help           Show this help message"
    echo
    echo "Commands:"
    echo "  status               Show server status"
    echo "  stats                Show queue statistics"
    echo "  list [queue]         List messages (optional: specify queue)"
    echo "  show ID              Show message details"
    echo "  delete ID            Delete message"
    echo "  flush [queue]        Flush a queue (or all queues)"
    echo
    echo "Examples:"
    echo "  $0 status"
    echo "  $0 stats"
    echo "  $0 list active"
    echo "  $0 --format json list"
    echo "  $0 show msg-12345"
    echo "  $0 delete msg-12345"
    echo "  $0 flush active"
    echo "  $0 flush all"
}

log() {
    if [ "$VERBOSE" = true ]; then
        echo -e "${YELLOW}[INFO]${NC} $1"
    fi
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    exit 1
}

format_output() {
    local data
    data=$(cat) # Read all input into a variable
    
    if [ "$FORMAT" = "json" ]; then
        # If output is already valid JSON, just pass it through
        if echo "$data" | jq -e . >/dev/null 2>&1; then
            echo "$data"
        else
            # Not JSON, convert to JSON
            echo "$data" | jq -R -s '{message: .}'
        fi
    elif [ "$FORMAT" = "yaml" ]; then
        # Try to convert JSON to YAML if possible
        if echo "$data" | jq -e . >/dev/null 2>&1; then
            echo "$data" | python3 -c 'import sys, yaml, json; print(yaml.dump(json.load(sys.stdin), default_flow_style=False))' 2>/dev/null || echo "$data"
        else
            # Not JSON, just output as is
            echo "$data"
        fi
    else
        # Text format, pretty print it
        if echo "$data" | jq -e . >/dev/null 2>&1; then
            echo "$data" | format_json_as_text
        else
            echo "$data"
        fi
    fi
}

format_json_as_text() {
    local data
    data=$(cat) # Read all input into a variable
    
    # Check if the input looks like queue stats
    if echo "$data" | jq -e 'has("active") and has("deferred")' >/dev/null 2>&1; then
        echo "Queue     Count"
        echo "------    ------"
        echo "$data" | jq -r 'to_entries | .[] | [.key, .value] | "\(.[0])    \(.[1])"' | sort
        echo "------    ------"
        echo "$data" | jq -r 'to_entries | map(.value) | add | "Total     \(.)"'
    # Check if it looks like a message list
    elif echo "$data" | jq -e 'if type == "array" and (.[0] | has("id") and has("from")) then true else false end' >/dev/null 2>&1; then
        echo "$data" | jq -r '["ID", "From", "To", "Subject", "Queue", "Size"], 
               (["------","------","------","------","------","------"]), 
               (.[] | [.id, .from, (.to[0] // "-"), .subject, (.queue_type // ""), .size]) | 
               @tsv' | column -t
    else
        # Default formatting for other JSON
        echo "$data" | jq -r '.'
    fi
}

check_dependencies() {
    # Check for curl
    if ! command -v curl &> /dev/null; then
        error "curl is required but not installed"
    fi
    
    # Check for jq
    if ! command -v jq &> /dev/null; then
        error "jq is required but not installed"
    fi
    
    # Check for Python if using YAML format
    if [ "$FORMAT" = "yaml" ] && ! command -v python3 &> /dev/null; then
        error "python3 is required for YAML output but not installed"
    fi
}

make_request() {
    local endpoint="$1"
    local method="${2:-GET}"
    local data="$3"
    
    log "Making $method request to $API_URL$endpoint"
    
    if [ -n "$data" ]; then
        curl -s -X "$method" "$API_URL$endpoint" -H "Content-Type: application/json" -d "$data"
    else
        curl -s -X "$method" "$API_URL$endpoint"
    fi
}

cmd_status() {
    log "Checking server status"
    make_request "/api/queue/stats" | format_output
}

cmd_stats() {
    log "Getting queue statistics"
    make_request "/api/queue/stats" | format_output
}

cmd_list() {
    local queue="$1"
    
    if [ -n "$queue" ]; then
        log "Listing messages in queue: $queue"
        make_request "/api/queue/$queue" | format_output
    else
        log "Listing all messages"
        make_request "/api/queue" | format_output
    fi
}

cmd_show() {
    local id="$1"
    
    if [ -z "$id" ]; then
        error "Message ID is required"
    fi
    
    log "Showing message: $id"
    make_request "/api/queue/message/$id" | format_output
}

cmd_delete() {
    local id="$1"
    
    if [ -z "$id" ]; then
        error "Message ID is required"
    fi
    
    log "Deleting message: $id"
    make_request "/api/queue/message/$id" "DELETE" | format_output
}

cmd_flush() {
    local queue="${1:-all}"
    
    log "Flushing queue: $queue"
    make_request "/api/queue/$queue/flush" "POST" | format_output
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -u|--url)
            API_URL="$2"
            shift 2
            ;;
        -f|--format)
            FORMAT="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            print_help
            exit 0
            ;;
        *)
            break
            ;;
    esac
done

# Check for command
if [ $# -eq 0 ]; then
    print_help
    exit 0
fi

COMMAND="$1"
shift

# Check dependencies
check_dependencies

# Execute command
case "$COMMAND" in
    status)
        cmd_status
        ;;
    stats)
        cmd_stats
        ;;
    list)
        cmd_list "$1"
        ;;
    show)
        cmd_show "$1"
        ;;
    delete)
        cmd_delete "$1"
        ;;
    flush)
        cmd_flush "$1"
        ;;
    *)
        error "Unknown command: $COMMAND"
        ;;
esac 