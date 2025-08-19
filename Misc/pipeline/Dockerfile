FROM gitea/gitea:latest

# Install additional dependencies if needed
RUN apk add --no-cache \
    git \
    openssh-client \
    curl \
    wget

# Copy custom configuration files
COPY custom/ /custom/

# Set proper permissions
RUN chmod +x /custom/entrypoint.sh

# Use custom entrypoint
ENTRYPOINT ["/custom/entrypoint.sh"]
CMD ["/bin/s6-svscan", "/etc/s6"] 