#!/bin/bash
# Elemta Update Script
# This script allows updating a running Elemta environment with new configuration

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}     Elemta Update Script       ${NC}"
    echo -e "${BLUE}================================${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -e, --env-file FILE    Use specific .env file (default: .env)"
    echo "  -c, --config-only      Only update configuration, don't restart services"
    echo "  -r, --restart-only     Only restart services with current configuration"
    echo "  -b, --backup           Create backup before updating"
    echo "  -f, --force            Force update without confirmation"
    echo "  -h, --help             Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                     # Update with default .env file"
    echo "  $0 -e .env.prod        # Update with specific .env file"
    echo "  $0 -c                  # Only update configuration"
    echo "  $0 -r                  # Only restart services"
    echo "  $0 -b -f               # Backup and force update"
}

# Function to backup current configuration
backup_config() {
    local backup_dir="backups/$(date +%Y%m%d_%H%M%S)"
    print_info "Creating backup in $backup_dir..."
    
    mkdir -p "$backup_dir"
    
    # Backup .env file
    if [ -f "$ENV_FILE" ]; then
        cp "$ENV_FILE" "$backup_dir/"
        print_success "Backed up $ENV_FILE"
    fi
    
    # Backup generated config
    if [ -f "config/elemta-generated.toml" ]; then
        cp "config/elemta-generated.toml" "$backup_dir/"
        print_success "Backed up config/elemta-generated.toml"
    fi
    
    # Backup users.txt
    if [ -f "config/users.txt" ]; then
        cp "config/users.txt" "$backup_dir/"
        print_success "Backed up config/users.txt"
    fi
    
    # Backup docker-compose logs
    if command -v docker-compose >/dev/null 2>&1; then
        docker-compose -f docker-compose.yml logs > "$backup_dir/docker-logs.txt" 2>/dev/null || true
        print_success "Backed up Docker logs"
    fi
    
    print_success "Backup completed: $backup_dir"
}

# Function to check if services are running
check_services() {
    if ! command -v docker-compose >/dev/null 2>&1; then
        print_error "docker-compose not found!"
        return 1
    fi
    
    if [ ! -f "docker-compose.yml" ]; then
        print_error "docker-compose.yml not found!"
        return 1
    fi
    
    return 0
}

# Function to update configuration
update_config() {
    print_info "Updating configuration from $ENV_FILE..."
    
    # Check if .env file exists
    if [ ! -f "$ENV_FILE" ]; then
        print_error "Environment file $ENV_FILE not found!"
        echo "Available .env files:"
        ls -la .env* 2>/dev/null || echo "No .env files found"
        exit 1
    fi
    
    # Clean up old config
    print_info "Cleaning up old configuration..."
    rm -f config/elemta-generated.toml
    
    # Generate new configuration
    print_info "Generating new configuration..."
    ./generate-config-alt.sh "$ENV_FILE"
    
    if [ ! -f "config/elemta-generated.toml" ]; then
        print_error "Failed to generate configuration!"
        exit 1
    fi
    
    print_success "Configuration updated successfully"
}

# Function to restart services
restart_services() {
    print_info "Restarting Elemta services..."
    
    # Stop services
    print_info "Stopping services..."
    docker-compose -f docker-compose.yml down
    
    # Start services
    print_info "Starting services..."
    docker-compose -f docker-compose.yml --env-file "$ENV_FILE" up -d
    
    # Wait for services to start
    print_info "Waiting for services to start..."
    sleep 10
    
    # Check service status
    print_info "Checking service status..."
    docker-compose -f docker-compose.yml ps
    
    print_success "Services restarted successfully"
}

# Function to show service status
show_status() {
    print_info "Service Status:"
    docker-compose -f docker-compose.yml ps
    
    echo ""
    print_info "Recent logs from elemta service:"
    docker-compose -f docker-compose.yml logs --tail=10 elemta
}

# Function to validate configuration
validate_config() {
    print_info "Validating configuration..."
    
    # Check if required files exist
    if [ ! -f "$ENV_FILE" ]; then
        print_error "Environment file $ENV_FILE not found!"
        return 1
    fi
    
    if [ ! -f "config/elemta-generated.toml" ]; then
        print_error "Generated configuration file not found!"
        return 1
    fi
    
    # Check if docker-compose file exists
    if [ ! -f "docker-compose.yml" ]; then
        print_error "docker-compose.yml not found!"
        return 1
    fi
    
    print_success "Configuration validation passed"
    return 0
}

# Default values
ENV_FILE=".env"
CONFIG_ONLY=false
RESTART_ONLY=false
CREATE_BACKUP=false
FORCE=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -e|--env-file)
            ENV_FILE="$2"
            shift 2
            ;;
        -c|--config-only)
            CONFIG_ONLY=true
            shift
            ;;
        -r|--restart-only)
            RESTART_ONLY=true
            shift
            ;;
        -b|--backup)
            CREATE_BACKUP=true
            shift
            ;;
        -f|--force)
            FORCE=true
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

print_header

# Change to the parent directory (Elemta project root)
cd "$(dirname "$0")/.."

# Check if we're in the right directory
if [ ! -f "docker-compose.yml" ] || [ ! -f "generate-config-alt.sh" ]; then
    print_error "Not in Elemta directory. Please run this from the Elemta project root."
    exit 1
fi

# Check if services are available
if ! check_services; then
    exit 1
fi

# Show current status
print_info "Current service status:"
docker-compose -f docker-compose.yml ps 2>/dev/null || print_warning "No services currently running"

echo ""

# Confirmation (unless forced)
if [ "$FORCE" = false ]; then
    echo "This will update your Elemta configuration and restart services."
    echo "Environment file: $ENV_FILE"
    echo ""
    
    if [ "$CONFIG_ONLY" = true ]; then
        echo "Mode: Configuration update only"
    elif [ "$RESTART_ONLY" = true ]; then
        echo "Mode: Service restart only"
    else
        echo "Mode: Full update (configuration + restart)"
    fi
    
    echo ""
    read -p "Do you want to continue? (y/N): " confirm
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        print_info "Update cancelled."
        exit 0
    fi
fi

# Create backup if requested
if [ "$CREATE_BACKUP" = true ]; then
    backup_config
    echo ""
fi

# Update configuration (unless restart-only)
if [ "$RESTART_ONLY" = false ]; then
    update_config
    echo ""
fi

# Restart services (unless config-only)
if [ "$CONFIG_ONLY" = false ]; then
    restart_services
    echo ""
fi

# Validate final configuration
if validate_config; then
    echo ""
    show_status
    echo ""
    print_success "Update completed successfully!"
    echo ""
    echo -e "${BLUE}📋 Useful commands:${NC}"
    echo "  View logs: docker-compose -f docker-compose.yml logs -f elemta"
    echo "  Check status: docker-compose -f docker-compose.yml ps"
    echo "  Stop services: docker-compose -f docker-compose.yml down"
    echo "  Restart services: ./update.sh -r"
    echo ""
    echo -e "${GREEN}🎉 Elemta is updated and running!${NC}"
else
    print_error "Update completed but configuration validation failed!"
    exit 1
fi
