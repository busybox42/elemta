#!/bin/bash

# Set error handling
set -e

# Color definitions
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}===================================${NC}"
echo -e "${BLUE}  Elemta Database Tests Runner     ${NC}"
echo -e "${BLUE}===================================${NC}"

# Function to run a Docker container if it's not already running
start_container() {
  local name=$1
  local image=$2
  local port=$3
  shift 3
  local extra_args=("$@")

  if ! docker ps | grep -q $name; then
    echo -e "\n${YELLOW}Starting $name container...${NC}"
    docker run --name $name -d -p $port ${extra_args[@]} $image
    # Wait for container to be ready
    sleep 5
  else
    echo -e "\n${YELLOW}Container $name is already running${NC}"
  fi
}

# MySQL tests
if [[ "$1" == "mysql" || "$1" == "all" ]]; then
  echo -e "\n${YELLOW}Setting up MySQL for tests...${NC}"
  
  # Start MySQL container if not already running
  start_container elemta-test-mysql mysql:8.0 "3306:3306" \
    -e MYSQL_ROOT_PASSWORD=elemta_test \
    -e MYSQL_DATABASE=elemta_test

  # Run MySQL tests
  echo -e "\n${YELLOW}Running MySQL tests...${NC}"
  TEST_MYSQL_HOST=localhost \
  TEST_MYSQL_PORT=3306 \
  TEST_MYSQL_USER=root \
  TEST_MYSQL_PASSWORD=elemta_test \
  TEST_MYSQL_DATABASE=elemta_test \
  go test -v ./internal/datasource/... -run "TestMySQL|TestIntegrationMySQL"
fi

# PostgreSQL tests
if [[ "$1" == "postgres" || "$1" == "all" ]]; then
  echo -e "\n${YELLOW}Setting up PostgreSQL for tests...${NC}"
  
  # Start PostgreSQL container if not already running
  start_container elemta-test-postgres postgres:14.0 "5432:5432" \
    -e POSTGRES_PASSWORD=elemta_test \
    -e POSTGRES_USER=postgres \
    -e POSTGRES_DB=elemta_test

  # Run PostgreSQL tests
  echo -e "\n${YELLOW}Running PostgreSQL tests...${NC}"
  TEST_PG_HOST=localhost \
  TEST_PG_PORT=5432 \
  TEST_PG_USER=postgres \
  TEST_PG_PASSWORD=elemta_test \
  TEST_PG_DATABASE=elemta_test \
  go test -v ./internal/datasource/... -run "TestPostgres|TestIntegrationPostgres"
fi

# Let's Encrypt test (doesn't actually connect to Let's Encrypt, just tests the setup)
if [[ "$1" == "letsencrypt" || "$1" == "all" ]]; then
  echo -e "\n${YELLOW}Running Let's Encrypt tests...${NC}"
  ELEMTA_TEST_LETSENCRYPT=true go test -v ./internal/smtp/... -run "TestLetsEncryptSetup"
fi

# LDAP tests
if [[ "$1" == "ldap" || "$1" == "all" ]]; then
  echo -e "\n${YELLOW}Setting up OpenLDAP for tests...${NC}"
  
  # Start OpenLDAP container if not already running
  start_container elemta-test-ldap osixia/openldap:1.5.0 "389:389" "636:636" \
    -e LDAP_ORGANISATION="Elemta" \
    -e LDAP_DOMAIN="example.com" \
    -e LDAP_ADMIN_PASSWORD="admin"

  # Wait for OpenLDAP to be ready
  sleep 5

  # Run LDAP tests
  echo -e "\n${YELLOW}Running LDAP tests...${NC}"
  TEST_LDAP_HOST=localhost \
  TEST_LDAP_PORT=389 \
  TEST_LDAP_BINDDN="cn=admin,dc=example,dc=com" \
  TEST_LDAP_BINDPW="admin" \
  TEST_LDAP_BASEDN="dc=example,dc=com" \
  go test -v ./internal/datasource/... -run "TestLDAP"
fi

# If no argument is provided, show usage
if [[ -z "$1" ]]; then
  echo -e "\n${YELLOW}Usage:${NC}"
  echo -e "  $0 mysql      - Run MySQL tests"
  echo -e "  $0 postgres   - Run PostgreSQL tests"
  echo -e "  $0 letsencrypt - Run Let's Encrypt tests"
  echo -e "  $0 ldap       - Run LDAP tests"
  echo -e "  $0 all        - Run all database tests"
fi

echo -e "\n${GREEN}===================================${NC}"
echo -e "${GREEN}   Tests Completed                 ${NC}"
echo -e "${GREEN}===================================${NC}"

exit 0 