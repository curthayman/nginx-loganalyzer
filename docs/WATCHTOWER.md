# Watchtower - Automatic Container Updates

## Overview

Watchtower automatically monitors your container registry and updates the nginx-loganalyzer container when new images are available. It's configured to work with both DockerHub and AWS ECR profiles.

## Configuration

### Current Settings

- **Check Interval**: Every 10 minutes (600 seconds)
- **Auto-cleanup**: Enabled (removes old images)
- **Image Retention**: Keeps last 5 tagged images
- **Scope**: Only monitors nginx-loganalyzer container
- **Notifications**: Log-only (no external notifications)

### How It Works

1. Watchtower runs alongside your nginx-loganalyzer container
2. Every 10 minutes, it checks the registry for new image versions
3. If a new version is found:
   - Pulls the new image
   - Gracefully stops the running container
   - Starts a new container with the same configuration
   - Removes old images (keeping last 5 versions)

## Usage

### Starting with Watchtower

Watchtower starts automatically when you use docker compose:

```bash
# DockerHub profile (default)
docker compose --profile dockerhub up -d

# ECR profile
docker compose --profile ecr up -d
```

### Viewing Watchtower Logs

Monitor Watchtower's activity:

```bash
# View recent logs
docker logs watchtower

# Follow logs in real-time
docker logs -f watchtower

# View last 50 lines
docker logs --tail 50 watchtower
```

### Triggering Manual Update Check

Force Watchtower to check for updates immediately:

```bash
# Send SIGHUP signal
docker kill --signal=HUP watchtower

# Or restart Watchtower
docker restart watchtower
```

### Temporarily Stopping Updates

```bash
# Stop Watchtower (container continues running)
docker stop watchtower

# Restart when ready
docker start watchtower
```

### Disabling Watchtower

To completely disable automatic updates:

```bash
# Stop and remove Watchtower
docker stop watchtower
docker rm watchtower

# Or comment out the watchtower service in docker-compose.yml
```

## Registry-Specific Configuration

### DockerHub (Public Registry)

No additional configuration needed. Watchtower automatically monitors:

- Image: `curthayman/nginx-loganalyzer:latest` (or your configured tag)

### AWS ECR (Private Registry)

Requires AWS credentials in your `.env` file:

```bash
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
```

**IAM Permissions Required:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage",
        "ecr:DescribeImages"
      ],
      "Resource": "*"
    }
  ]
}
```

## Rollback Procedure

If an update causes issues, rollback to a previous version:

### 1. Find Available Images

```bash
# List local images (last 5 are kept)
docker images curthayman/nginx-loganalyzer

# Or for ECR
docker images {ECR_REGISTRY}/nginx-loganalyzer
```

### 2. Stop Watchtower

```bash
docker stop watchtower
```

### 3. Rollback Container

```bash
# Stop current container
docker stop nginx-loganalyzer
docker rm nginx-loganalyzer

# Edit docker-compose.yml and change the tag to previous version
# For example: DOCKERHUB_TAG=v1.2.3 instead of latest

# Or manually specify tag in .env file
echo "DOCKERHUB_TAG=v1.2.3" >> .env

# Recreate with old version
docker compose --profile dockerhub up -d nginx-loganalyzer
```

### 4. Resume Watchtower (Optional)

```bash
docker start watchtower
```

## Monitoring Best Practices

### 1. Check Logs Regularly

Set up a cron job or manual check schedule:

```bash
# Add to crontab for daily log review
0 9 * * * docker logs --tail 100 watchtower >> /var/log/watchtower-summary.log
```

### 2. Monitor Application Health

After updates, verify the application is working:

```bash
# Check container status
docker ps | grep nginx-loganalyzer

# Check application health
curl -f http://localhost:8501/_stcore/health

# View application logs
docker logs nginx-loganalyzer
```

### 3. Test Updates in Staging First

For production environments:

1. Use a staging environment with identical Watchtower config
2. Test updates there first
3. Tag stable versions for production
4. Update production to use stable tags only

## Troubleshooting

### Watchtower Not Detecting Updates

**Check registry connectivity:**

```bash
docker exec watchtower ping registry.hub.docker.com  # DockerHub
docker exec watchtower aws ecr describe-images       # ECR
```

**Verify credentials (ECR):**

```bash
docker logs watchtower | grep -i auth
```

### Updates Failing

**Check disk space:**

```bash
df -h
docker system df
```

**Review Watchtower logs:**

```bash
docker logs --tail 200 watchtower
```

### Container Not Restarting Properly

**Check container logs:**

```bash
docker logs nginx-loganalyzer
```

**Verify health check:**

```bash
docker inspect nginx-loganalyzer | grep -A 10 Health
```

## Advanced Configuration

### Modify Update Settings

Edit `docker-compose.yml` Watchtower service environment:

```yaml
environment:
  - WATCHTOWER_POLL_INTERVAL=600 # Change check interval
  - WATCHTOWER_CLEANUP=true # Enable/disable cleanup
  - WATCHTOWER_KEEP_IMAGETAGS=5 # Number of images to keep
  - WATCHTOWER_MONITOR_ONLY=true # Only notify, don't update
```

### Add Email Notifications

Add to Watchtower environment:

```yaml
environment:
  - WATCHTOWER_NOTIFICATIONS=email
  - WATCHTOWER_NOTIFICATION_EMAIL_FROM=watchtower@example.com
  - WATCHTOWER_NOTIFICATION_EMAIL_TO=admin@example.com
  - WATCHTOWER_NOTIFICATION_EMAIL_SERVER=smtp.gmail.com
  - WATCHTOWER_NOTIFICATION_EMAIL_SERVER_PORT=587
  - WATCHTOWER_NOTIFICATION_EMAIL_SERVER_USER=your-email@gmail.com
  - WATCHTOWER_NOTIFICATION_EMAIL_SERVER_PASSWORD=your-password
```

### Add Slack Notifications

```yaml
environment:
  - WATCHTOWER_NOTIFICATIONS=slack
  - WATCHTOWER_NOTIFICATION_SLACK_HOOK_URL=https://hooks.slack.com/services/YOUR/HOOK/URL
```

## Security Considerations

1. **Credentials**: Store AWS credentials securely (use Docker secrets or AWS IAM roles when possible)
2. **Docker Socket**: Watchtower requires access to `/var/run/docker.sock` (inherent security risk)
3. **Tag Strategy**: Use specific version tags in production (not `latest`) for controlled updates
4. **Testing**: Always test updates in non-production environments first

## References

- [Watchtower Documentation](https://containrrr.dev/watchtower/)
- [Docker Hub - Watchtower](https://hub.docker.com/r/containrrr/watchtower)
- [Watchtower GitHub](https://github.com/containrrr/watchtower)
