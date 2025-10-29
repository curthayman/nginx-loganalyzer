#!/bin/bash
# Test script for Docker build and run

set -e

echo "🐳 Testing Nginx Log Analyzer Docker container..."

# Build the image
echo "📦 Building Docker image..."
docker build -t nginx-loganalyzer:test .

# Check if container from previous test is running
if docker ps -a | grep -q nginx-loganalyzer-test; then
    echo "🧹 Cleaning up previous test container..."
    docker rm -f nginx-loganalyzer-test
fi

# Run the container
echo "🚀 Starting container..."
docker run -d \
    --name nginx-loganalyzer-test \
    -p 8501:8501 \
    nginx-loganalyzer:test

# Wait for container to be ready
echo "⏳ Waiting for application to start..."
sleep 5

# Check if container is running
if docker ps | grep -q nginx-loganalyzer-test; then
    echo "✅ Container is running!"
    echo ""
    echo "📊 Application should be available at: http://localhost:8501"
    echo ""
    echo "To view logs: docker logs -f nginx-loganalyzer-test"
    echo "To stop: docker stop nginx-loganalyzer-test"
    echo "To remove: docker rm -f nginx-loganalyzer-test"
else
    echo "❌ Container failed to start"
    docker logs nginx-loganalyzer-test
    exit 1
fi
