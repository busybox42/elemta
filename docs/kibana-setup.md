# Kibana Setup for Elemta MTA

This document explains how to set up Kibana data views for Elemta's MTA-focused logging structure.

## Overview

Elemta uses a specialized logging structure that separates email processing into distinct flows based on the MTA (Mail Transfer Agent) lifecycle:

- **Reception**: Incoming SMTP sessions and message acceptance
- **Delivery**: Successful email deliveries
- **Rejection**: Policy blocks, spam detection, authentication failures
- **Tempfail**: Temporary failures requiring retries
- **Bounce**: Permanent failures and bounce messages

## Automatic Setup (Recommended)

### Using Docker Compose

The easiest way is to use the automated setup:

```bash
# Start the full stack with automatic Kibana setup
make docker-setup

# Or manually
docker-compose up -d
```

The `elemta-setup` container will automatically:
1. Wait for Kibana and Elasticsearch to be healthy
2. Create all required data views
3. Configure proper time field mappings
4. Exit cleanly after setup

### Manual Setup

If you need to set up data views manually:

```bash
# Setup Kibana data views
make setup-kibana

# Or run the script directly
./scripts/setup-kibana-data-views.sh
```

## Data Views Created

The setup script creates the following data views:

| Data View | Index Pattern | Description |
|-----------|---------------|-------------|
| `elemta-reception-*` | Reception logs | Incoming SMTP sessions, message acceptance |
| `elemta-delivery-*` | Delivery logs | Successful email deliveries |
| `elemta-rejection-*` | Rejection logs | Policy blocks, spam, auth failures |
| `elemta-tempfail-*` | Tempfail logs | Temporary failures, retries |
| `elemta-bounce-*` | Bounce logs | Permanent failures, bounces |
| `elemta-system-*` | System logs | Legacy system logs |
| `elemta-unclassified-*` | Unclassified | Logs not matching MTA patterns |

## Accessing Your Data

Once setup is complete, you can access:

- **Kibana**: http://localhost:5601
- **Discover**: http://localhost:5601/app/discover
- **Data Views Management**: http://localhost:5601/app/management/kibana/dataViews
- **Dashboards**: http://localhost:5601/app/dashboards

## Troubleshooting

### Data Views Missing After Restart

If Kibana data views disappear after a restart:

```bash
# Re-run the setup script
./scripts/setup-kibana-data-views.sh
```

### Connection Issues

Check if services are running:

```bash
# Check container status
docker-compose ps

# Check Kibana logs
docker logs elemta-kibana --tail 20

# Test connectivity
curl http://localhost:5601/api/status
curl http://localhost:9200/_cluster/health
```

### Script Permissions

If you get permission errors:

```bash
chmod +x scripts/setup-kibana-data-views.sh
chmod +x scripts/docker/post-startup.sh
```

## Index Patterns vs Data Views

- **Data Views** (modern): Kibana 8.x+ uses data views for index patterns
- **Index Patterns** (legacy): Older Kibana versions used index patterns

The setup script creates data views compatible with Kibana 8.11.0.

## Configuration

Environment variables for customization:

```bash
export KIBANA_URL="http://localhost:5601"
export ELASTICSEARCH_URL="http://localhost:9200"
./scripts/setup-kibana-data-views.sh
```

## Integration with Docker

The setup is integrated into docker-compose.yml:

- `elemta-setup` service runs once after all services are healthy
- Automatically creates data views on first startup
- Uses proper service discovery (elemta-kibana:5601, elemta-elasticsearch:9200)
- Exits cleanly after completion

## Next Steps

After data views are set up:

1. **Import Dashboards**: Run `./scripts/import-mta-dashboards.sh`
2. **Explore Data**: Use Kibana Discover to browse your email logs
3. **Create Visualizations**: Build custom charts and graphs
4. **Set Up Alerts**: Configure monitoring and alerting rules 