#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT_DIR="$(dirname "$SCRIPT_DIR")"

# Required files and directories
BINARY_FILE="$PARENT_DIR/bin/elemta"
CONFIG_FILE="$PARENT_DIR/config/elemta.conf"
DATA_DIR="$PARENT_DIR/data"

# Check if files exist
echo -e "${YELLOW}Checking for required files...${NC}"

# Check binary file
if [ -f "$BINARY_FILE" ]; then
    echo -e "${GREEN}✓ Binary file exists: $BINARY_FILE${NC}"
else
    echo -e "${RED}✗ Binary file not found: $BINARY_FILE${NC}"
    echo -e "${YELLOW}Creating dummy binary file...${NC}"
    
    # Create directory if it doesn't exist
    mkdir -p "$(dirname "$BINARY_FILE")"
    
    # Create dummy binary file
    cat > "$BINARY_FILE" << 'EOF'
#!/bin/bash
echo "Elemta SMTP Server v0.0.1"
echo "This is a dummy binary file for testing package building."
echo "In a real deployment, this would be the actual Elemta binary."
EOF
    
    # Make it executable
    chmod +x "$BINARY_FILE"
    echo -e "${GREEN}✓ Created dummy binary file: $BINARY_FILE${NC}"
fi

# Check config file
if [ -f "$CONFIG_FILE" ]; then
    echo -e "${GREEN}✓ Config file exists: $CONFIG_FILE${NC}"
else
    echo -e "${RED}✗ Config file not found: $CONFIG_FILE${NC}"
    echo -e "${YELLOW}Creating dummy config file...${NC}"
    
    # Create directory if it doesn't exist
    mkdir -p "$(dirname "$CONFIG_FILE")"
    
    # Create dummy config file
    cat > "$CONFIG_FILE" << 'EOF'
# Elemta SMTP Server Configuration
# This is a dummy configuration file for testing package building.

[server]
hostname = mail.example.com
port = 25
tls_port = 465
submission_port = 587

[security]
tls_cert = /etc/elemta/certs/cert.pem
tls_key = /etc/elemta/certs/key.pem

[storage]
queue_dir = /var/lib/elemta/queue
data_dir = /var/lib/elemta/data

[logging]
log_level = info
log_file = /var/log/elemta/elemta.log

[plugins]
enabled_plugins = antivirus,antispam,dkim
plugin_dir = /usr/lib/elemta/plugins
EOF
    
    echo -e "${GREEN}✓ Created dummy config file: $CONFIG_FILE${NC}"
fi

# Check data directory
if [ -d "$DATA_DIR" ]; then
    echo -e "${GREEN}✓ Data directory exists: $DATA_DIR${NC}"
else
    echo -e "${RED}✗ Data directory not found: $DATA_DIR${NC}"
    echo -e "${YELLOW}Creating dummy data directory...${NC}"
    
    # Create data directory
    mkdir -p "$DATA_DIR"
    
    # Create a dummy file in the data directory
    cat > "$DATA_DIR/README.txt" << 'EOF'
This is a dummy data directory for testing package building.
In a real deployment, this directory would contain data files for the Elemta SMTP server.
EOF
    
    echo -e "${GREEN}✓ Created dummy data directory: $DATA_DIR${NC}"
fi

echo -e "${GREEN}All required files are available.${NC}"
exit 0 