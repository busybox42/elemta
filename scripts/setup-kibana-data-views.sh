#!/bin/bash

# Setup Kibana Data Views for Elemta MTA Logging
# This script creates data views for all MTA flow indices

set -e

KIBANA_URL="${KIBANA_URL:-http://localhost:5601}"
ELASTICSEARCH_URL="${ELASTICSEARCH_URL:-http://localhost:9200}"

echo "🔧 Setting up Kibana Data Views for Elemta MTA"
echo "Kibana URL: $KIBANA_URL"
echo "Elasticsearch URL: $ELASTICSEARCH_URL"

# Wait for Kibana to be ready
echo "⏳ Waiting for Kibana to be available..."
until curl -s "$KIBANA_URL/api/status" | grep -q "available"; do
    echo "   Waiting for Kibana..."
    sleep 5
done
echo "✅ Kibana is ready"

# Wait for Elasticsearch to be ready
echo "⏳ Waiting for Elasticsearch to be available..."
until curl -s "$ELASTICSEARCH_URL/_cluster/health" | grep -q "yellow\|green"; do
    echo "   Waiting for Elasticsearch..."
    sleep 5
done
echo "✅ Elasticsearch is ready"

# Function to create data view
create_data_view() {
    local name="$1"
    local pattern="$2"
    local title="$3"
    
    echo "📊 Creating data view: $name ($pattern)"
    
    # Check if data view already exists
    existing_id=$(curl -s "$KIBANA_URL/api/data_views" -H "kbn-xsrf: true" | jq -r ".data_view[] | select(.title == \"$pattern\") | .id")
    
    if [ -n "$existing_id" ] && [ "$existing_id" != "null" ]; then
        echo "   ⚠️  Data view already exists (ID: $existing_id)"
        return 0
    fi
    
    result=$(curl -X POST "$KIBANA_URL/api/data_views/data_view" \
        -H "Content-Type: application/json" \
        -H "kbn-xsrf: true" \
        -d "{
            \"data_view\": {
                \"title\": \"$pattern\",
                \"name\": \"$title\",
                \"timeFieldName\": \"@timestamp\"
            }
        }" -s)
    
    new_id=$(echo "$result" | jq -r '.data_view.id // "Error"')
    if [ "$new_id" != "Error" ] && [ "$new_id" != "null" ]; then
        echo "   ✅ Created (ID: $new_id)"
    else
        echo "   ❌ Failed: $(echo "$result" | jq -r '.message // "Unknown error"')"
    fi
}

# Create MTA Data Views
echo ""
echo "🚀 Creating MTA Data Views..."

# Reception - Incoming SMTP sessions
create_data_view "elemta-reception" "elemta-reception-*" "Elemta Reception (Incoming SMTP)"

# Delivery - Successful deliveries  
create_data_view "elemta-delivery" "elemta-delivery-*" "Elemta Delivery (Successful)"

# Rejection - Policy blocks, spam, auth failures
create_data_view "elemta-rejection" "elemta-rejection-*" "Elemta Rejection (Blocked/Failed)"

# Tempfail - Temporary failures, retries
create_data_view "elemta-tempfail" "elemta-tempfail-*" "Elemta Tempfail (Retries)"

# Bounce - Permanent failures
create_data_view "elemta-bounce" "elemta-bounce-*" "Elemta Bounce (Permanent Failures)"

# System logs (legacy)
create_data_view "elemta-system" "elemta-system-*" "Elemta System (Legacy)"

# Unclassified logs
create_data_view "elemta-unclassified" "elemta-unclassified-*" "Elemta Unclassified"

echo ""
echo "📋 Listing created data views..."
curl -s "$KIBANA_URL/api/data_views" -H "kbn-xsrf: true" | jq -r '.data_view[] | select(.title | startswith("elemta-")) | "✅ " + .title + " (" + .name + ")"'

echo ""
echo "🎉 Kibana Data Views setup complete!"
echo ""
echo "🔗 Access your data:"
echo "   • Discover: $KIBANA_URL/app/discover"
echo "   • Data Views: $KIBANA_URL/app/management/kibana/dataViews"
echo "   • Dashboard: $KIBANA_URL/app/dashboards"
echo ""
echo "💡 Next steps:"
echo "   1. Import MTA dashboards: ./scripts/import-mta-dashboards.sh"
echo "   2. Create index patterns if needed"
echo "   3. Set up alerts and monitoring" 