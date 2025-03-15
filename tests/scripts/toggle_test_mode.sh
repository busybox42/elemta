#!/bin/bash

# Script to toggle test mode for Rspamd
# Usage: ./toggle_test_mode.sh [enable|disable]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONFIG_DIR="$PROJECT_ROOT/config/rspamd/local.d"
TEST_MODE_CONFIG="$PROJECT_ROOT/config/rspamd/test-mode.conf"

enable_test_mode() {
    echo "Enabling test mode for Rspamd..."
    
    # Create backup of current configuration if it doesn't exist
    if [ ! -f "$CONFIG_DIR/options.inc.bak" ]; then
        [ -f "$CONFIG_DIR/options.inc" ] && cp "$CONFIG_DIR/options.inc" "$CONFIG_DIR/options.inc.bak"
    fi
    
    if [ ! -f "$CONFIG_DIR/rbl.conf.bak" ]; then
        [ -f "$CONFIG_DIR/rbl.conf" ] && cp "$CONFIG_DIR/rbl.conf" "$CONFIG_DIR/rbl.conf.bak"
    fi
    
    if [ ! -f "$CONFIG_DIR/actions.conf.bak" ]; then
        [ -f "$CONFIG_DIR/actions.conf" ] && cp "$CONFIG_DIR/actions.conf" "$CONFIG_DIR/actions.conf.bak"
    fi
    
    # Apply test mode configuration
    cat > "$CONFIG_DIR/options.inc" << EOF
# Disable DNS checks for testing
disable_monitoring = true;
dns {
  enable_dnssec = false;
}
EOF

    cat > "$CONFIG_DIR/rbl.conf" << EOF
# Disable RBL checks for testing
enabled = false;
EOF

    cat > "$CONFIG_DIR/actions.conf" << EOF
# Set higher spam threshold for testing
reject = 15.0;
add_header = 8.0;
greylist = 6.0;
EOF
    
    echo "Test mode enabled. You may need to restart the containers for changes to take effect."
}

disable_test_mode() {
    echo "Disabling test mode for Rspamd..."
    
    # Restore backups if they exist
    [ -f "$CONFIG_DIR/options.inc.bak" ] && cp "$CONFIG_DIR/options.inc.bak" "$CONFIG_DIR/options.inc"
    [ -f "$CONFIG_DIR/rbl.conf.bak" ] && cp "$CONFIG_DIR/rbl.conf.bak" "$CONFIG_DIR/rbl.conf"
    [ -f "$CONFIG_DIR/actions.conf.bak" ] && cp "$CONFIG_DIR/actions.conf.bak" "$CONFIG_DIR/actions.conf"
    
    echo "Test mode disabled. You may need to restart the containers for changes to take effect."
}

case "$1" in
    enable)
        enable_test_mode
        ;;
    disable)
        disable_test_mode
        ;;
    *)
        echo "Usage: $0 [enable|disable]"
        exit 1
        ;;
esac 