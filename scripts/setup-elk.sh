#!/bin/bash

# Elemta ELK Stack Setup Script
# Sets up Elasticsearch, Logstash, Kibana for SMTP log analysis

set -e

echo "🔍 Setting up ELK Stack for Elemta SMTP Log Analysis..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to check if service is healthy
check_service_health() {
    local service_name=$1
    local max_attempts=30
    local attempt=1
    
    echo -e "${BLUE}Waiting for $service_name to become healthy...${NC}"
    
    while [ $attempt -le $max_attempts ]; do
        if docker-compose ps $service_name | grep -q "healthy"; then
            echo -e "${GREEN}✅ $service_name is healthy${NC}"
            return 0
        fi
        
        echo -e "${YELLOW}⏳ Attempt $attempt/$max_attempts - $service_name not ready yet...${NC}"
        sleep 10
        attempt=$((attempt + 1))
    done
    
    echo -e "${RED}❌ $service_name failed to become healthy after $max_attempts attempts${NC}"
    return 1
}

# Function to wait for service to be ready
wait_for_service() {
    local service_name=$1
    local port=$2
    local max_attempts=30
    local attempt=1
    
    echo -e "${BLUE}Waiting for $service_name to be ready on port $port...${NC}"
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s -f http://localhost:$port > /dev/null 2>&1; then
            echo -e "${GREEN}✅ $service_name is ready on port $port${NC}"
            return 0
        fi
        
        echo -e "${YELLOW}⏳ Attempt $attempt/$max_attempts - $service_name not ready yet...${NC}"
        sleep 10
        attempt=$((attempt + 1))
    done
    
    echo -e "${RED}❌ $service_name failed to become ready after $max_attempts attempts${NC}"
    return 1
}

# Start ELK services
echo -e "${BLUE}🚀 Starting ELK Stack services...${NC}"
docker-compose up -d elemta-elasticsearch elemta-logstash elemta-kibana elemta-filebeat

# Wait for Elasticsearch to be ready
echo -e "${BLUE}📊 Waiting for Elasticsearch...${NC}"
check_service_health "elemta-elasticsearch"
wait_for_service "Elasticsearch" "9200"

# Check Elasticsearch cluster health
echo -e "${BLUE}🔍 Checking Elasticsearch cluster health...${NC}"
curl -s http://localhost:9200/_cluster/health?pretty

# Wait for Logstash to be ready
echo -e "${BLUE}📝 Waiting for Logstash...${NC}"
check_service_health "elemta-logstash"
wait_for_service "Logstash" "9600"

# Wait for Kibana to be ready
echo -e "${BLUE}📈 Waiting for Kibana...${NC}"
check_service_health "elemta-kibana"
wait_for_service "Kibana" "5601"

# Create index pattern in Kibana
echo -e "${BLUE}🔧 Setting up Kibana index pattern...${NC}"
sleep 30  # Give Kibana time to fully initialize

# Create index pattern
curl -X POST "localhost:5601/api/saved_objects/index-pattern/elemta-logs-*" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "attributes": {
      "title": "elemta-logs-*",
      "timeFieldName": "@timestamp"
    }
  }' || echo "Index pattern may already exist"

# Import dashboard if it exists
if [ -f "elk/kibana/dashboards/elemta-smtp-dashboard.json" ]; then
    echo -e "${BLUE}📊 Importing Kibana dashboard...${NC}"
    curl -X POST "localhost:5601/api/saved_objects/_import" \
      -H "kbn-xsrf: true" \
      -F "file=@elk/kibana/dashboards/elemta-smtp-dashboard.json" || echo "Dashboard import may have failed"
fi

# Generate some test logs to populate the system
echo -e "${BLUE}📧 Generating test SMTP traffic for log analysis...${NC}"
if [ -f "scripts/realistic-smtp-test.py" ]; then
    python3 scripts/realistic-smtp-test.py --test-type normal --count 10 &
    python3 scripts/realistic-smtp-test.py --test-type suspicious --count 5 &
    wait
fi

# Show service status
echo -e "${GREEN}🎉 ELK Stack setup complete!${NC}"
echo -e "${BLUE}📊 Service URLs:${NC}"
echo -e "  • Elasticsearch: ${YELLOW}http://localhost:9200${NC}"
echo -e "  • Kibana: ${YELLOW}http://localhost:5601${NC}"
echo -e "  • Logstash: ${YELLOW}http://localhost:9600${NC}"

echo -e "${BLUE}📈 Access your dashboards:${NC}"
echo -e "  • Kibana Dashboard: ${YELLOW}http://localhost:5601/app/dashboards${NC}"
echo -e "  • Discover Logs: ${YELLOW}http://localhost:5601/app/discover${NC}"

echo -e "${BLUE}🔍 Useful queries for log analysis:${NC}"
echo -e "  • SMTP Connections: ${YELLOW}event_type:smtp_connection${NC}"
echo -e "  • Error Messages: ${YELLOW}level:ERROR${NC}"
echo -e "  • Queue Processing: ${YELLOW}event_type:queue_processing${NC}"
echo -e "  • Message Delivery: ${YELLOW}event_type:message_delivery${NC}"

# Show container status
echo -e "${BLUE}📦 Container Status:${NC}"
docker-compose ps elemta-elasticsearch elemta-logstash elemta-kibana elemta-filebeat

echo -e "${GREEN}✅ ELK Stack is ready for Elemta SMTP log analysis!${NC}" 