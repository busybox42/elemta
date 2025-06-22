#!/bin/bash

# Create MTA-focused index patterns in Kibana
# This script creates 6 index patterns for the enhanced MTA logging structure

KIBANA_URL="http://localhost:5601"

echo "🔧 Creating MTA Index Patterns in Kibana..."

# Wait for Kibana to be ready
echo "⏳ Waiting for Kibana to be ready..."
until curl -s "$KIBANA_URL/api/status" | grep -q '"level":"available"'; do
  echo "   Waiting for Kibana..."
  sleep 5
done

echo "✅ Kibana is ready!"

# Function to create index pattern
create_index_pattern() {
  local pattern_id="$1"
  local pattern_title="$2"
  local description="$3"
  
  echo "📊 Creating index pattern: $pattern_title"
  
  curl -X POST "$KIBANA_URL/api/saved_objects/index-pattern/$pattern_id" \
    -H 'Content-Type: application/json' \
    -H 'kbn-xsrf: true' \
    -d "{
      \"attributes\": {
        \"title\": \"$pattern_title\",
        \"timeFieldName\": \"@timestamp\",
        \"description\": \"$description\"
      }
    }" -s | jq '.id // "Failed"'
}

echo ""
echo "🚀 Creating MTA Flow Index Patterns..."

# 1. Reception Index Pattern
create_index_pattern "elemta-reception-pattern" \
  "elemta-reception-*" \
  "SMTP reception logs - incoming connections, message acceptance, and initial processing"

# 2. Delivery Index Pattern  
create_index_pattern "elemta-delivery-pattern" \
  "elemta-delivery-*" \
  "Message delivery logs - successful LMTP/SMTP deliveries and queue processing completion"

# 3. Rejection Index Pattern
create_index_pattern "elemta-rejection-pattern" \
  "elemta-rejection-*" \
  "Message rejection logs - spam blocks, security rejections, and policy violations"

# 4. Tempfail Index Pattern
create_index_pattern "elemta-tempfail-pattern" \
  "elemta-tempfail-*" \
  "Temporary failure logs - queue deferrals, retry attempts, and temporary delivery issues"

# 5. Bounce Index Pattern
create_index_pattern "elemta-bounce-pattern" \
  "elemta-bounce-*" \
  "Bounce logs - permanent delivery failures and bounce message generation"

# 6. System Monitoring Index Pattern
create_index_pattern "elemta-system-pattern" \
  "elemta-system-*" \
  "System monitoring logs - infrastructure services, LDAP, RSpamd, Dovecot, and monitoring stack"

echo ""
echo "📈 Index Pattern Creation Complete!"
echo ""
echo "🔍 Available Data Views:"
echo "   • elemta-reception-* - SMTP reception and message acceptance"
echo "   • elemta-delivery-*  - Successful message deliveries"  
echo "   • elemta-rejection-* - Security blocks and spam rejections"
echo "   • elemta-tempfail-*  - Temporary failures and retries"
echo "   • elemta-bounce-*    - Permanent failures and bounces"
echo "   • elemta-system-*    - Infrastructure and monitoring logs"
echo ""
echo "🎯 Access Kibana at: http://localhost:5601"
echo "📊 Navigate to Analytics > Discover to explore the data views" 