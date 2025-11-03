#!/bin/bash

# Nginx Log Analyzer - Container Startup Script
# This script handles Terminus CLI authentication and starts the Streamlit application

set -e  # Exit on any error

echo "Starting Nginx Log Analyzer..."

# Check if MACHINE_TOKEN is provided
if [ -z "$MACHINE_TOKEN" ]; then
    echo "WARNING: MACHINE_TOKEN environment variable is not set."
    echo "Terminus CLI will not be authenticated. Some features may not work."
    echo "To fix this, set the MACHINE_TOKEN in your .env file."
else
    echo "Authenticating with Terminus CLI..."
    
    # Authenticate with Terminus using the machine token
    if terminus auth:login --machine-token="$MACHINE_TOKEN"; then
        echo "✓ Successfully authenticated with Terminus CLI"
        
        # Verify authentication by checking whoami
        if terminus auth:whoami > /dev/null 2>&1; then
            echo "✓ Terminus authentication verified"
        else
            echo "⚠ Warning: Terminus authentication may have issues"
        fi
    else
        echo "✗ Failed to authenticate with Terminus CLI"
        echo "Please check your MACHINE_TOKEN and try again."
        echo "The application will continue but Pantheon features will not work."
    fi
fi

echo "Starting Streamlit application..."

# Start the Streamlit application
exec streamlit run main.py --server.address=0.0.0.0 --server.port=8501