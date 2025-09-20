FROM docker.elastic.co/beats/filebeat:8.11.0

WORKDIR /usr/share/filebeat

# Copy custom Filebeat configuration
COPY config/filebeat.yml /usr/share/filebeat/filebeat.yml

# Set permissions
USER root
RUN chmod 644 /usr/share/filebeat/filebeat.yml

# Switch back to filebeat user
USER filebeat

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/docker-entrypoint"]
CMD ["/usr/share/filebeat/filebeat", "-e", "-strict.perms=false"]
