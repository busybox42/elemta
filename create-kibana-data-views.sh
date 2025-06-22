#!/bin/bash

echo "Creating Kibana Data Views for Enhanced Email Indexing..."

KIBANA_URL="http://localhost:5601"

# Wait for Kibana to be ready
echo "Waiting for Kibana to be ready..."
until curl -s "$KIBANA_URL/api/status" | grep -q '"level":"available"'; do
    echo "Waiting for Kibana..."
    sleep 5
done

echo "✅ Kibana is ready!"

# Function to create data view
create_data_view() {
    local name="$1"
    local pattern="$2"
    local title="$3"
    
    echo "Creating data view: $title"
    
    curl -X POST "$KIBANA_URL/api/data_views/data_view" \
        -H "Content-Type: application/json" \
        -H "kbn-xsrf: true" \
        -d "{
            \"data_view\": {
                \"id\": \"$name\",
                \"name\": \"$title\",
                \"title\": \"$pattern\",
                \"timeFieldName\": \"@timestamp\"
            }
        }" | jq -r '.data_view.id // "Error"'
    
    sleep 1
}

# Create MTA Flow Data Views
echo ""
echo "📧 Creating MTA Flow Data Views..."

create_data_view "elemta-reception" "elemta-reception-*" "📨 MTA Reception (Incoming SMTP)"
create_data_view "elemta-delivery" "elemta-delivery-*" "📤 MTA Delivery (Outgoing Email)"  
create_data_view "elemta-rejection" "elemta-rejection-*" "🚫 MTA Rejection (Blocked Email)"
create_data_view "elemta-tempfail" "elemta-tempfail-*" "⏳ MTA Tempfail (Retry Queue)"
create_data_view "elemta-bounce" "elemta-bounce-*" "💥 MTA Bounce (Permanent Failures)"

# Create System Data Views
echo ""
echo "🔧 Creating System Data Views..."

create_data_view "elemta-system" "elemta-system-*" "⚙️ System Operations"
create_data_view "elemta-unclassified" "elemta-unclassified-*" "📋 Unclassified Logs"

# Create Combined Views
echo ""
echo "📊 Creating Combined Data Views..."

create_data_view "elemta-all-mta" "elemta-reception-*,elemta-delivery-*,elemta-rejection-*,elemta-tempfail-*,elemta-bounce-*" "📧 All MTA Flows"
create_data_view "elemta-all-logs" "elemta-*" "🌐 All Elemta Logs"

echo ""
echo "🎉 All Kibana Data Views Created Successfully!"
echo ""
echo "📊 Access your email analytics at: http://localhost:5601"
echo ""
