#!/bin/bash
# Elemta Uninstaller
# This script removes Elemta installation and cleans up resources

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}      Elemta Uninstaller        ${NC}"
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

print_header

# Change to the parent directory (Elemta project root)
cd "$(dirname "$0")/.."

# Check if we're in the right directory
if [ ! -f "docker-compose.yml" ]; then
    print_error "Not in Elemta directory. Please run this from the Elemta project root."
    exit 1
fi

# Check if .env exists
if [ ! -f ".env" ]; then
    print_warning "No .env file found. Elemta may not be installed."
    read -p "Continue with cleanup anyway? (y/N): " continue_cleanup
    if [[ ! $continue_cleanup =~ ^[Yy]$ ]]; then
        print_info "Uninstall cancelled."
        exit 0
    fi
fi

print_warning "This will completely remove Elemta and all associated data!"
echo ""
echo "The following will be removed:"
echo "  🐳 All Docker containers and images"
echo "  📁 All volumes and persistent data"
echo "  🔧 Configuration files (.env, generated configs)"
echo "  📊 All logs and queue data"
echo "  🔐 All certificates and keys"
echo ""

read -p "Are you sure you want to continue? (y/N): " confirm_uninstall
if [[ ! $confirm_uninstall =~ ^[Yy]$ ]]; then
    print_info "Uninstall cancelled."
    exit 0
fi

echo ""
print_info "Starting Elemta uninstall process..."

# Stop and remove all containers
print_info "Stopping and removing Docker containers..."
docker-compose -f docker-compose.yml down -v 2>/dev/null || true

# Remove Docker images
print_info "Removing Docker images..."
docker rmi elemta:config-security 2>/dev/null || true
docker rmi elemta_dovecot:latest 2>/dev/null || true

# Remove volumes
print_info "Removing Docker volumes..."
docker volume rm elemta_elemta_queue 2>/dev/null || true
docker volume rm elemta_elemta_logs 2>/dev/null || true
docker volume rm elemta_rspamd_data 2>/dev/null || true
docker volume rm elemta_ldap_data 2>/dev/null || true
docker volume rm elemta_ldap_config 2>/dev/null || true
docker volume rm elemta_dovecot_data 2>/dev/null || true
docker volume rm elemta_roundcube_data 2>/dev/null || true
docker volume rm elemta_clamav_data 2>/dev/null || true

# Remove networks
print_info "Removing Docker networks..."
docker network rm elemta_elemta_network 2>/dev/null || true

# Clean up configuration files
print_info "Removing configuration files..."
rm -f .env
rm -f config/elemta-generated.toml
rm -f config/users.txt

# Clean up logs
print_info "Removing log files..."
rm -rf logs/
rm -rf config/queue/

# Clean up certificates (optional)
print_warning "Certificate files in config/ will be preserved."
print_info "If you want to remove certificates, run: rm -f config/*.crt config/*.key"

# Clean up any remaining Docker resources
print_info "Cleaning up remaining Docker resources..."
docker system prune -f 2>/dev/null || true

echo ""
print_success "Elemta uninstall completed successfully!"
echo ""
echo -e "${BLUE}📋 What was removed:${NC}"
echo "  🐳 All Docker containers and images"
echo "  📁 All volumes and persistent data"
echo "  🔧 Configuration files (.env, generated configs)"
echo "  📊 All logs and queue data"
echo "  🧹 Docker system cleanup completed"
echo ""
echo -e "${BLUE}📁 What was preserved:${NC}"
echo "  🔐 Certificate files (config/*.crt, config/*.key)"
echo "  📝 Source code and scripts"
echo "  🐳 Docker Compose files"
echo ""
echo -e "${GREEN}🎉 Elemta has been completely removed from your system!${NC}"
echo ""
echo -e "${YELLOW}💡 To reinstall Elemta, run:${NC}"
echo "  make install      # Interactive installation"
echo "  make install-dev  # Development environment"
echo ""
