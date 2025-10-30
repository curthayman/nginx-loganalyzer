#!/bin/bash
# Deployment setup script for Nginx Log Analyzer with Docker Compose

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  Nginx Log Analyzer - Docker Compose Setup${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker is not installed${NC}"
    echo "Please install Docker first: https://docs.docker.com/get-docker/"
    exit 1
fi
echo -e "${GREEN}✓${NC} Docker is installed"

# Check if Docker Compose is installed
if ! command -v docker compose &> /dev/null; then
    echo -e "${RED}❌ Docker Compose is not installed${NC}"
    echo "Please install Docker Compose: https://docs.docker.com/compose/install/"
    exit 1
fi
echo -e "${GREEN}✓${NC} Docker Compose is installed"

# Check if .env file exists
if [ ! -f .env ]; then
    echo -e "${YELLOW}⚠${NC}  No .env file found"
    
    if [ -f .env.example ]; then
        echo -e "${BLUE}Creating .env from .env.example...${NC}"
        cp .env.example .env
        echo -e "${GREEN}✓${NC} Created .env file"
        echo ""
        echo -e "${YELLOW}⚠ IMPORTANT: Edit .env file with your settings${NC}"
        echo "Required: Set HOSTNAME to your domain name"
        echo ""
        read -p "Press Enter to edit .env now, or Ctrl+C to exit and edit manually..."
        ${EDITOR:-nano} .env
    else
        echo -e "${RED}❌ .env.example not found${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}✓${NC} .env file exists"
fi

# Validate .env configuration
echo ""
echo -e "${BLUE}Validating configuration...${NC}"

if [ -f .env ]; then
    source .env
    
    if [ -z "$HOSTNAME" ] || [ "$HOSTNAME" = "logs.example.com" ]; then
        echo -e "${RED}❌ HOSTNAME not configured in .env${NC}"
        echo "Please set HOSTNAME to your domain name"
        exit 1
    fi
    echo -e "${GREEN}✓${NC} HOSTNAME is configured: $HOSTNAME"
    
    # Check image registry configuration
    PROFILE="${COMPOSE_PROFILES:-dockerhub}"
    echo -e "${BLUE}Image source: $PROFILE${NC}"
    
    if [ "$PROFILE" = "ecr" ]; then
        if [ -z "$ECR_REGISTRY" ]; then
            echo -e "${RED}❌ ECR_REGISTRY not configured in .env${NC}"
            echo "Please set ECR_REGISTRY to your AWS ECR registry URL"
            echo "Example: 123456789012.dkr.ecr.us-east-1.amazonaws.com"
            exit 1
        fi
        echo -e "${GREEN}✓${NC} ECR_REGISTRY is configured: $ECR_REGISTRY"
        echo -e "${YELLOW}⚠${NC}  Make sure you're authenticated with ECR:"
        echo "  aws ecr get-login-password --region {region} | docker login --username AWS --password-stdin $ECR_REGISTRY"
    else
        echo -e "${GREEN}✓${NC} Using DockerHub public image"
    fi
    
    # Check DNS
    echo -e "${BLUE}Checking DNS for $HOSTNAME...${NC}"
    if command -v dig &> /dev/null; then
        DNS_IP=$(dig +short $HOSTNAME | tail -n1)
        if [ -n "$DNS_IP" ]; then
            echo -e "${GREEN}✓${NC} DNS resolves to: $DNS_IP"
        else
            echo -e "${YELLOW}⚠${NC}  DNS does not resolve for $HOSTNAME"
            echo "Make sure your DNS is configured before proceeding"
        fi
    fi
fi

# Check if proxy network exists
echo ""
echo -e "${BLUE}Checking Docker network...${NC}"
if docker network ls | grep -q "proxy"; then
    echo -e "${GREEN}✓${NC} 'proxy' network exists"
else
    echo -e "${YELLOW}⚠${NC}  'proxy' network does not exist"
    read -p "Create 'proxy' network now? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        docker network create proxy
        echo -e "${GREEN}✓${NC} Created 'proxy' network"
    else
        echo -e "${RED}❌ Cannot proceed without 'proxy' network${NC}"
        exit 1
    fi
fi

# Check if Traefik is running
echo ""
echo -e "${BLUE}Checking Traefik...${NC}"
if docker ps | grep -q traefik; then
    echo -e "${GREEN}✓${NC} Traefik is running"
    TRAEFIK_NETWORKS=$(docker inspect traefik --format '{{range $key, $value := .NetworkSettings.Networks}}{{$key}} {{end}}')
    if echo "$TRAEFIK_NETWORKS" | grep -q "proxy"; then
        echo -e "${GREEN}✓${NC} Traefik is connected to 'proxy' network"
    else
        echo -e "${YELLOW}⚠${NC}  Traefik is not connected to 'proxy' network"
        echo "You may need to add Traefik to the proxy network"
    fi
else
    echo -e "${YELLOW}⚠${NC}  Traefik is not running"
    echo "Make sure Traefik is running before starting the application"
fi

# Create logs directory
echo ""
echo -e "${BLUE}Setting up directories...${NC}"
LOGS_DIR="${LOGS_DIR:-./site-logs}"
mkdir -p "$LOGS_DIR"
echo -e "${GREEN}✓${NC} Created logs directory: $LOGS_DIR"

# Check SSH keys
echo ""
echo -e "${BLUE}Checking SSH keys...${NC}"
SSH_PATH="${SSH_KEY_PATH:-~/.ssh}"
SSH_PATH=$(eval echo "$SSH_PATH")  # Expand ~ if present
if [ -d "$SSH_PATH" ]; then
    echo -e "${GREEN}✓${NC} SSH directory exists: $SSH_PATH"
    
    if [ -f "$SSH_PATH/id_rsa" ] || [ -f "$SSH_PATH/id_ed25519" ]; then
        echo -e "${GREEN}✓${NC} SSH keys found"
    else
        echo -e "${YELLOW}⚠${NC}  No SSH keys found in $SSH_PATH"
        echo "You'll need SSH keys to connect to Pantheon SFTP"
    fi
else
    echo -e "${YELLOW}⚠${NC}  SSH directory not found: $SSH_PATH"
    echo "Make sure SSH keys are available for Pantheon SFTP access"
fi

# Summary
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}Setup complete!${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Next steps:"
echo "1. Verify .env configuration: ${YELLOW}cat .env${NC}"
echo "2. Pull the latest image: ${YELLOW}docker compose pull${NC}"
echo "3. Start the service: ${YELLOW}docker compose up -d${NC}"
echo "4. View logs: ${YELLOW}docker compose logs -f${NC}"
echo "5. Access at: ${YELLOW}https://$HOSTNAME${NC}"
echo ""
read -p "Start the service now? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo -e "${BLUE}Pulling latest image...${NC}"
    docker compose pull
    
    echo ""
    echo -e "${BLUE}Starting service...${NC}"
    docker compose up -d
    
    echo ""
    echo -e "${GREEN}✓${NC} Service started!"
    echo ""
    echo "View logs: ${YELLOW}docker compose logs -f${NC}"
    echo "Check status: ${YELLOW}docker compose ps${NC}"
    echo "Access at: ${YELLOW}https://$HOSTNAME${NC}"
    
    sleep 3
    echo ""
    echo "Showing recent logs (Ctrl+C to exit):"
    docker compose logs -f --tail=50
else
    echo ""
    echo -e "${BLUE}Setup complete. Start when ready with:${NC}"
    echo "  ${YELLOW}docker compose up -d${NC}"
fi
