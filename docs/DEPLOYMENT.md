# Docker Compose Deployment Guide

This guide explains how to deploy Nginx Log Analyzer using Docker Compose with Traefik reverse proxy.

## Prerequisites

1. **Docker and Docker Compose** installed on your server
2. **Traefik** running and managing the `proxy` network
3. **DNS record** pointing to your server
4. **SSH keys** for SFTP access to Pantheon servers

## Quick Start

### 1. Copy Files to Server

```bash
# On your server
mkdir -p /opt/nginx-loganalyzer
cd /opt/nginx-loganalyzer

# Copy docker-compose.yml and .env.example
# You can use git clone or scp
git clone https://github.com/curthayman/nginx-loganalyzer.git .
# Or manually copy docker-compose.yml and .env.example
```

### 2. Configure Environment

```bash
# Copy the example environment file
cp .env.example .env

# Edit with your values
nano .env
```

**Required configuration:**

```bash
HOSTNAME=logs.example.com  # Your domain name
```

**Optional configuration:**

```bash
CERT_RESOLVER=letsencrypt  # Your Traefik cert resolver name
SSH_KEY_PATH=/path/to/.ssh  # Path to SSH keys
LOGS_DIR=/data/site-logs    # Custom logs directory
```

### 3. Ensure Traefik Network Exists

```bash
# Check if proxy network exists
docker network ls | grep proxy

# If it doesn't exist, create it
docker network create proxy
```

### 4. Start the Application

```bash
# Pull the latest image
docker compose pull

# Start in detached mode
docker compose up -d

# View logs
docker compose logs -f
```

### 5. Access the Application

Open your browser and navigate to `https://your-hostname` (e.g., `https://logs.example.com`)

Traefik will automatically:

- Route traffic to the container
- Obtain SSL certificates from Let's Encrypt
- Redirect HTTP to HTTPS

## Configuration Options

### Basic Authentication

To add password protection:

1. Generate password hash:

```bash
echo $(htpasswd -nb admin yourpassword) | sed -e s/\\$/\\$\\$/g
```

2. Add to `.env`:

```bash
BASIC_AUTH_USERS=admin:$$apr1$$xyz123$$abc...
```

3. Uncomment auth labels in `docker-compose.yml`:

```yaml
- "traefik.http.routers.nginx-loganalyzer.middlewares=auth"
- "traefik.http.middlewares.auth.basicauth.users=${BASIC_AUTH_USERS}"
```

4. Restart:

```bash
docker compose up -d
```

### Custom Volumes

Mount additional directories as needed:

```yaml
volumes:
  - /custom/path/to/.ssh:/home/appuser/.ssh:ro
  - /mnt/large-drive/logs:/home/appuser/site-logs
  - /path/to/custom-config.toml:/home/appuser/.streamlit/config.toml:ro
```

### Resource Limits

Adjust in `docker-compose.yml` under `deploy.resources`:

```yaml
deploy:
  resources:
    limits:
      cpus: "4"
      memory: 4G
    reservations:
      cpus: "1"
      memory: 1G
```

## Traefik Configuration

### Example Traefik docker-compose.yml

If you don't have Traefik set up yet, here's a minimal configuration:

```yaml
version: "3.8"

services:
  traefik:
    image: traefik:v3.0
    container_name: traefik
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    networks:
      - proxy
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./traefik.yml:/traefik.yml:ro
      - ./acme.json:/acme.json
    labels:
      - "traefik.enable=true"

networks:
  proxy:
    external: true
```

### Example traefik.yml

```yaml
api:
  dashboard: true

entryPoints:
  web:
    address: ":80"
  websecure:
    address: ":443"

certificatesResolvers:
  letsencrypt:
    acme:
      email: your-email@example.com
      storage: /acme.json
      httpChallenge:
        entryPoint: web

providers:
  docker:
    exposedByDefault: false
    network: proxy
```

## Management Commands

### View Logs

```bash
docker compose logs -f
docker compose logs -f nginx-loganalyzer
```

### Restart Service

```bash
docker compose restart
```

### Update to Latest Version

```bash
docker compose pull
docker compose up -d
```

### Stop Service

```bash
docker compose down
```

### Stop and Remove Volumes

```bash
docker compose down -v
```

### Check Status

```bash
docker compose ps
docker compose top
```

### Access Container Shell

```bash
docker compose exec nginx-loganalyzer /bin/bash
```

## Troubleshooting

### Container Not Starting

1. Check logs:

```bash
docker compose logs nginx-loganalyzer
```

2. Verify network exists:

```bash
docker network ls | grep proxy
```

3. Check Traefik is running:

```bash
docker ps | grep traefik
```

### SSL Certificate Issues

1. Verify DNS points to server:

```bash
dig +short your-hostname.com
```

2. Check Traefik logs:

```bash
docker logs traefik
```

3. Verify cert resolver name matches:

```bash
# In .env
CERT_RESOLVER=letsencrypt  # Must match Traefik config
```

### Cannot Access Application

1. Check if container is running:

```bash
docker compose ps
```

2. Test container health:

```bash
docker compose exec nginx-loganalyzer curl -f http://localhost:8501/_stcore/health
```

3. Verify Traefik routing:

```bash
docker compose logs | grep -i traefik
```

4. Check firewall rules:

```bash
sudo ufw status
# Ensure ports 80 and 443 are open
```

### SSH/SFTP Connection Issues

1. Verify SSH keys are mounted:

```bash
docker compose exec nginx-loganalyzer ls -la /home/appuser/.ssh
```

2. Check key permissions (should be readable):

```bash
docker compose exec nginx-loganalyzer stat /home/appuser/.ssh/id_rsa
```

3. Test SFTP manually:

```bash
docker compose exec nginx-loganalyzer sftp -o Port=2222 user@host
```

### High Resource Usage

1. Check current usage:

```bash
docker stats nginx-loganalyzer
```

2. Adjust limits in docker-compose.yml

3. Restart with new limits:

```bash
docker compose up -d
```

## Security Best Practices

1. **Use Basic Auth** for public-facing deployments
2. **Keep SSH keys secure** with read-only mounts
3. **Regular updates**:
   ```bash
   docker compose pull
   docker compose up -d
   ```
4. **Monitor logs** for suspicious activity
5. **Set resource limits** to prevent DoS
6. **Use strong passwords** for basic auth
7. **Restrict network access** with firewall rules

## Backup and Restore

### Backup Configuration

```bash
# Backup .env and any custom configs
tar -czf nginx-loganalyzer-backup.tar.gz .env docker-compose.yml
```

### Backup Logs

```bash
# Backup downloaded logs
tar -czf site-logs-backup.tar.gz site-logs/
```

### Restore

```bash
# Extract backup
tar -xzf nginx-loganalyzer-backup.tar.gz

# Start services
docker compose up -d
```

## Monitoring

### Health Check

```bash
# Manual health check
curl https://your-hostname/_stcore/health

# Automated monitoring with cron
*/5 * * * * curl -f https://logs.example.com/_stcore/health || echo "Service down" | mail -s "Alert" admin@example.com
```

### Resource Monitoring

```bash
# Live stats
docker stats nginx-loganalyzer

# Historical data (requires monitoring stack)
# Use Prometheus + Grafana for production monitoring
```

## Scaling Considerations

For high-traffic deployments:

1. **Increase resources** in docker-compose.yml
2. **Use dedicated volume** for logs storage
3. **Enable rate limiting** in Traefik labels
4. **Consider load balancing** multiple instances
5. **Monitor performance** with observability tools

## Support

- **GitHub Issues**: https://github.com/curthayman/nginx-loganalyzer/issues
- **Documentation**: Check README.md and .github/workflows/README.md
- **Docker Hub**: https://hub.docker.com/r/curthayman/nginx-loganalyzer
