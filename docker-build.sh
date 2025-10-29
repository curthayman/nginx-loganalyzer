#!/bin/bash
# Docker build script with version tagging support

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
IMAGE_NAME="nginx-loganalyzer"
VERSION=${1:-"latest"}
PLATFORMS=${2:-"linux/amd64,linux/arm64"}
PUSH=${3:-false}

echo -e "${GREEN}🐳 Building Nginx Log Analyzer Docker Image${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Image Name: ${IMAGE_NAME}"
echo "Version: ${VERSION}"
echo "Platforms: ${PLATFORMS}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Build the image
echo -e "${YELLOW}📦 Building Docker image...${NC}"
docker build \
    -t ${IMAGE_NAME}:${VERSION} \
    -t ${IMAGE_NAME}:latest \
    .

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Build completed successfully!${NC}"
    echo ""
    echo "Available tags:"
    docker images ${IMAGE_NAME} --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}"
    echo ""
    echo -e "${GREEN}Usage:${NC}"
    echo "  docker run -d -p 8501:8501 ${IMAGE_NAME}:${VERSION}"
    echo ""
else
    echo -e "${RED}❌ Build failed!${NC}"
    exit 1
fi
