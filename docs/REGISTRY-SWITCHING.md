# Docker Registry Switching Guide

This guide explains how to switch between DockerHub (public) and AWS ECR (private) image registries.

## Quick Reference

### Using DockerHub (Default)

```bash
# In .env file
COMPOSE_PROFILES=dockerhub
DOCKERHUB_IMAGE=curthayman/nginx-loganalyzer
DOCKERHUB_TAG=latest
```

```bash
# Deploy
docker compose up -d

# Or explicitly specify profile
docker compose --profile dockerhub up -d
```

### Using AWS ECR

```bash
# In .env file
COMPOSE_PROFILES=ecr
ECR_REGISTRY=123456789012.dkr.ecr.us-east-1.amazonaws.com
ECR_IMAGE=nginx-loganalyzer
ECR_TAG=latest
```

```bash
# Authenticate with ECR first
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin 123456789012.dkr.ecr.us-east-1.amazonaws.com

# Deploy
docker compose up -d

# Or explicitly specify profile
docker compose --profile ecr up -d
```

## Setup AWS ECR Repository

Use the included setup script to create your ECR repository:

```bash
export AWS_REGION=us-east-1
./setup-ecr.sh
```

This will:

- Create the ECR repository with security scanning
- Generate a restrictive IAM policy
- Set up lifecycle policies
- Display next steps

## Environment Variables Reference

### Required for All Deployments

| Variable           | Description        | Example              |
| ------------------ | ------------------ | -------------------- |
| `HOSTNAME`         | Your domain name   | `logs.example.com`   |
| `MACHINE_TOKEN`    | Pantheon API token | `your_token_here`    |
| `COMPOSE_PROFILES` | Registry to use    | `dockerhub` or `ecr` |

### DockerHub Configuration

| Variable          | Description | Default                        |
| ----------------- | ----------- | ------------------------------ |
| `DOCKERHUB_IMAGE` | Image name  | `curthayman/nginx-loganalyzer` |
| `DOCKERHUB_TAG`   | Image tag   | `latest`                       |

### AWS ECR Configuration

| Variable       | Description       | Example                                        |
| -------------- | ----------------- | ---------------------------------------------- |
| `ECR_REGISTRY` | ECR registry URL  | `123456789012.dkr.ecr.us-east-1.amazonaws.com` |
| `ECR_IMAGE`    | Image name in ECR | `nginx-loganalyzer`                            |
| `ECR_TAG`      | Image tag         | `latest`                                       |

## Switching Between Registries

### From DockerHub to ECR

1. Update `.env`:

   ```bash
   COMPOSE_PROFILES=ecr
   ECR_REGISTRY=your-account.dkr.ecr.region.amazonaws.com
   ```

2. Authenticate with ECR:

   ```bash
   aws ecr get-login-password --region us-east-1 | \
     docker login --username AWS --password-stdin your-registry-url
   ```

3. Stop current container:

   ```bash
   docker compose down
   ```

4. Start with ECR image:
   ```bash
   docker compose up -d
   ```

### From ECR to DockerHub

1. Update `.env`:

   ```bash
   COMPOSE_PROFILES=dockerhub
   ```

2. Stop current container:

   ```bash
   docker compose down
   ```

3. Start with DockerHub image:
   ```bash
   docker compose up -d
   ```

## Verification

Check which image is running:

```bash
# View running containers
docker compose ps

# Check image details
docker compose images

# Validate configuration
docker compose config | grep image:
```

## Troubleshooting

### ECR Authentication Errors

**Problem:** `no basic auth credentials` or `authentication required`

**Solution:** Authenticate with ECR:

```bash
aws ecr get-login-password --region YOUR_REGION | \
  docker login --username AWS --password-stdin YOUR_REGISTRY
```

### Wrong Image Pulled

**Problem:** Container starts with wrong image source

**Solution:**

1. Check `.env` file has correct `COMPOSE_PROFILES`
2. Stop container: `docker compose down`
3. Remove old image: `docker rmi $(docker compose config | grep image: | awk '{print $2}')`
4. Pull new image: `docker compose pull`
5. Start: `docker compose up -d`

### ECR Registry Not Set

**Problem:** `ECR_REGISTRY variable is not set`

**Solution:** Set in `.env` file:

```bash
ECR_REGISTRY=123456789012.dkr.ecr.us-east-1.amazonaws.com
```

## GitHub Actions Integration

For automated CI/CD deployments, see `.github/workflows/README.md` for:

- DockerHub publishing workflow
- AWS ECR publishing workflow
- Multi-registry publishing workflow

## Security Best Practices

### DockerHub

- Use specific tags instead of `latest` in production
- Enable Docker Content Trust for signed images

### AWS ECR

- Use the generated restrictive IAM policy from `./setup-ecr.sh`
- Enable image scanning in ECR
- Use lifecycle policies to manage image retention
- Rotate ECR credentials regularly
- Use IAM roles instead of access keys when possible

## Additional Resources

- [Docker Compose Profiles Documentation](https://docs.docker.com/compose/profiles/)
- [AWS ECR Authentication](https://docs.aws.amazon.com/AmazonECR/latest/userguide/getting-started-cli.html)
- [DockerHub Documentation](https://docs.docker.com/docker-hub/)
