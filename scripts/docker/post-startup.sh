#!/bin/bash

# Post-startup script for Elemta Docker deployment
# This runs after all containers are healthy to set up Kibana data views

set -e

echo "🚀 Elemta Post-Startup Configuration"
echo "===================================="

# Wait a bit for all services to fully stabilize
echo "⏳ Waiting for services to stabilize..."
sleep 10

# Check if we're in Docker environment
if [ -f /.dockerenv ] || grep -q 'docker\|lxc' /proc/1/cgroup 2>/dev/null; then
    echo "📦 Running inside Docker container"
    KIBANA_URL="http://elemta-kibana:5601"
    ELASTICSEARCH_URL="http://elemta-elasticsearch:9200"
else
    echo "🖥️  Running on host system"
    KIBANA_URL="http://localhost:5601"
    ELASTICSEARCH_URL="http://localhost:9200"
fi

# Setup Kibana data views
echo ""
echo "📊 Setting up Kibana Data Views..."
export KIBANA_URL ELASTICSEARCH_URL

# Run the data views setup script
if [ -f "/app/scripts/setup-kibana-data-views.sh" ]; then
    /app/scripts/setup-kibana-data-views.sh
elif [ -f "./scripts/setup-kibana-data-views.sh" ]; then
    ./scripts/setup-kibana-data-views.sh
else
    echo "❌ Data views setup script not found!"
    exit 1
fi

echo ""
echo "🎉 Post-startup configuration complete!"
echo ""
echo "🔗 Access Points:"
echo "   • Kibana: $KIBANA_URL"
echo "   • Grafana: http://localhost:3000"
echo "   • Web Admin: http://localhost:8025"
echo "   • Prometheus: http://localhost:9090" 