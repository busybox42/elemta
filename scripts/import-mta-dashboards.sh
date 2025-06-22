#!/bin/bash

# Import MTA-focused dashboards into Kibana
# This script replaces the old mixed dashboard with focused email flow dashboards

KIBANA_URL="http://localhost:5601"
DASHBOARD_DIR="elk/kibana/dashboards"

echo "🚀 Importing MTA-focused dashboards into Kibana..."
echo "📍 Kibana URL: $KIBANA_URL"
echo ""

# Wait for Kibana to be ready
echo "⏳ Waiting for Kibana to be ready..."
until curl -s "$KIBANA_URL/api/status" >/dev/null 2>&1; do
    echo "   Waiting for Kibana..."
    sleep 5
done
echo "✅ Kibana is ready!"
echo ""

# Import each MTA dashboard
declare -a dashboards=(
    "mta-reception-dashboard.ndjson"
    "mta-delivery-dashboard.ndjson" 
    "mta-rejection-dashboard.ndjson"
    "mta-tempfail-dashboard.ndjson"
    "mta-bounce-dashboard.ndjson"
)

success_count=0
total_count=${#dashboards[@]}

for dashboard in "${dashboards[@]}"; do
    dashboard_file="$DASHBOARD_DIR/$dashboard"
    dashboard_name=$(echo "$dashboard" | sed 's/-dashboard.ndjson//' | sed 's/mta-//' | tr '-' ' ' | sed 's/\b\w/\u&/g')
    
    echo "📊 Importing $dashboard_name Dashboard..."
    
    if [[ ! -f "$dashboard_file" ]]; then
        echo "❌ Dashboard file not found: $dashboard_file"
        continue
    fi
    
    # Import dashboard using Kibana saved objects API
    response=$(curl -s -w "\n%{http_code}" \
        -X POST "$KIBANA_URL/api/saved_objects/_import" \
        -H "kbn-xsrf: true" \
        -F "file=@$dashboard_file" 2>/dev/null)
    
    http_code=$(echo "$response" | tail -n1)
    response_body=$(echo "$response" | head -n -1)
    
    if [[ "$http_code" == "200" ]]; then
        echo "✅ Successfully imported $dashboard_name Dashboard"
        ((success_count++))
    else
        echo "❌ Failed to import $dashboard_name Dashboard (HTTP $http_code)"
        echo "   Response: $response_body"
    fi
    echo ""
done

echo "📈 Import Summary:"
echo "   Successfully imported: $success_count/$total_count dashboards"
echo ""

if [[ $success_count -eq $total_count ]]; then
    echo "🎉 All MTA dashboards imported successfully!"
    echo ""
    echo "📱 Available Dashboards:"
    echo "   🔵 Reception Dashboard  - Incoming SMTP sessions & message acceptance"
    echo "   🟢 Delivery Dashboard   - Successful message delivery & routing"
    echo "   🔴 Rejection Dashboard  - Policy blocks, spam & security rejections"  
    echo "   🟡 Tempfail Dashboard   - Temporary failures & retry tracking"
    echo "   🟠 Bounce Dashboard     - Permanent failures & bounce generation"
    echo ""
    echo "🌐 Access at: $KIBANA_URL/app/dashboards"
else
    echo "⚠️  Some dashboards failed to import. Check the errors above."
    exit 1
fi 