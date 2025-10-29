# Docker Compose Quick Reference

Quick command reference for managing the Nginx Log Analyzer deployment.

## Initial Setup

```bash
# Run the automated setup script
./docker-deploy.sh

# Or manually:
cp .env.example .env
nano .env  # Configure HOSTNAME
docker network create proxy  # If needed
docker compose pull
docker compose up -d
```

## Service Management

```bash
# Start services
docker compose up -d

# Stop services
docker compose down

# Restart services
docker compose restart

# Stop and remove everything (including volumes)
docker compose down -v
```

## Viewing Logs

```bash
# Follow all logs
docker compose logs -f

# Follow logs for specific service
docker compose logs -f nginx-loganalyzer

# Last 100 lines
docker compose logs --tail=100

# Logs since specific time
docker compose logs --since 10m
docker compose logs --since "2024-01-01T00:00:00"
```

## Status and Monitoring

```bash
# View running services
docker compose ps

# View resource usage
docker compose top

# Live resource stats
docker stats nginx-loganalyzer

# Health check
docker compose exec nginx-loganalyzer curl http://localhost:8501/_stcore/health
```

## Updates

```bash
# Pull latest image
docker compose pull

# Update and restart (zero-downtime)
docker compose up -d --force-recreate

# View current version
docker compose images
```

## Debugging

```bash
# Access container shell
docker compose exec nginx-loganalyzer /bin/bash

# Run command in container
docker compose exec nginx-loganalyzer ls -la /home/appuser/.ssh

# View container environment
docker compose exec nginx-loganalyzer env

# Inspect container
docker compose inspect nginx-loganalyzer

# View container config
docker compose config
```

## Backup and Restore

```bash
# Backup configuration
tar -czf backup-$(date +%Y%m%d).tar.gz .env docker-compose.yml

# Backup logs
tar -czf logs-backup-$(date +%Y%m%d).tar.gz site-logs/

# Restore
tar -xzf backup-*.tar.gz
docker compose up -d
```

## Network Management

```bash
# List networks
docker network ls

# Inspect proxy network
docker network inspect proxy

# List containers on proxy network
docker network inspect proxy | grep -A 10 Containers
```

## Troubleshooting

```bash
# Check if Traefik is running
docker ps | grep traefik

# View Traefik logs
docker logs traefik

# Restart service with new config
docker compose up -d --force-recreate

# Remove and recreate
docker compose down
docker compose up -d

# Check DNS resolution
dig +short your-hostname.com

# Test internal connectivity
docker compose exec nginx-loganalyzer ping -c 3 google.com

# View Docker events
docker events --filter 'container=nginx-loganalyzer'
```

## Resource Management

```bash
# View current resource usage
docker stats nginx-loganalyzer --no-stream

# Prune unused images
docker image prune -a

# Prune unused volumes
docker volume prune

# Clean everything
docker system prune -a --volumes
```

## Configuration Changes

```bash
# After changing .env
docker compose up -d

# After changing docker-compose.yml
docker compose up -d --force-recreate

# View rendered configuration
docker compose config
```

## Common Issues

### Service won't start

```bash
docker compose logs nginx-loganalyzer  # Check logs
docker compose ps  # Check status
docker network ls | grep proxy  # Verify network
```

### Can't access via domain

```bash
dig +short your-hostname.com  # Check DNS
docker logs traefik | grep your-hostname  # Check Traefik
curl -H "Host: your-hostname.com" http://localhost:8501  # Test direct
```

### High resource usage

```bash
docker stats  # Monitor resources
# Adjust limits in docker-compose.yml
docker compose up -d --force-recreate
```

### SSL certificate issues

```bash
docker logs traefik | grep -i acme  # Check cert requests
docker logs traefik | grep -i error  # Check errors
# Verify CERT_RESOLVER in .env matches Traefik config
```

## One-Liners

```bash
# Full update cycle
docker compose pull && docker compose up -d --force-recreate && docker compose logs -f

# Quick health check
curl -f https://your-hostname.com/_stcore/health && echo "✓ Healthy" || echo "✗ Unhealthy"

# View all Traefik-related labels
docker inspect nginx-loganalyzer | jq '.[0].Config.Labels'

# Count log entries
docker compose exec nginx-loganalyzer find /home/appuser/site-logs -name "*.log" | wc -l

# Check last startup time
docker inspect -f '{{.State.StartedAt}}' nginx-loganalyzer
```

## Production Best Practices

```bash
# Enable logging driver
docker compose --log-level INFO up -d

# Monitor with watch
watch -n 5 'docker compose ps'

# Auto-restart on failure (already configured)
docker compose up -d  # Uses restart: unless-stopped

# Regular backups (add to crontab)
0 2 * * * cd /opt/nginx-loganalyzer && tar -czf backup-$(date +\%Y\%m\%d).tar.gz .env site-logs/

# Health monitoring (add to crontab)
*/5 * * * * docker compose exec nginx-loganalyzer curl -f http://localhost:8501/_stcore/health || systemctl restart docker-nginx-loganalyzer
```

## Environment Variables

Set in `.env` file:

| Variable           | Required | Default     | Description                     |
| ------------------ | -------- | ----------- | ------------------------------- |
| `HOSTNAME`         | Yes      | -           | Domain name for Traefik routing |
| `CERT_RESOLVER`    | No       | letsencrypt | Traefik certificate resolver    |
| `SSH_KEY_PATH`     | No       | ~/.ssh      | Path to SSH keys                |
| `LOGS_DIR`         | No       | ./site-logs | Logs storage directory          |
| `BASIC_AUTH_USERS` | No       | -           | Basic auth credentials          |

## Links

- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [Traefik Documentation](https://doc.traefik.io/traefik/)
- [Full Deployment Guide](./DEPLOYMENT.md)
- [GitHub Repository](https://github.com/curthayman/nginx-loganalyzer)
