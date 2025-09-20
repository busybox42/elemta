FROM prom/prometheus:latest

# Copy our configuration files
COPY prometheus.yml /etc/prometheus/prometheus.yml
COPY rules/ /etc/prometheus/rules/
COPY alerting/ /etc/prometheus/alerting/

# Create empty console directories to avoid errors
RUN mkdir -p /etc/prometheus/consoles /etc/prometheus/console_libraries

# Set proper permissions - skip user change for now

EXPOSE 9090
