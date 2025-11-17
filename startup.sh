#!/bin/bash

# Nginx Log Analyzer - Container Startup Script
# This script handles Terminus CLI authentication and starts the Streamlit application

set -e  # Exit on any error

echo "Starting Nginx Log Analyzer..."

# =============================================================================
# DEBUG MODE
# =============================================================================
# Enable debug output by setting DEBUG=true in .env file
# This helps troubleshoot SFTP authentication and other issues

if [ "$DEBUG" = "true" ]; then
    echo ""
    echo "=========================================="
    echo "DEBUG MODE ENABLED"
    echo "=========================================="
    echo ""
    
    # System Information
    echo "--- System Information ---"
    echo "Current user: $(whoami)"
    echo "User ID: $(id -u)"
    echo "Group ID: $(id -g)"
    echo "Home directory: $HOME"
    echo "Current directory: $(pwd)"
    echo ""
    
    # SSH Directory Information
    echo "--- SSH Directory Contents ---"
    if [ -d "$HOME/.ssh" ]; then
        echo "SSH directory exists at: $HOME/.ssh"
        echo ""
        echo "Directory permissions:"
        ls -ld "$HOME/.ssh"
        echo ""
        echo "SSH files (with permissions, size, and date):"
        ls -lhA "$HOME/.ssh" 2>/dev/null || echo "Cannot list .ssh directory contents"
        echo ""
        
        # Check for common SSH key files
        echo "Checking for common SSH key files:"
        for keyfile in id_rsa id_ed25519 id_ecdsa id_dsa; do
            if [ -f "$HOME/.ssh/$keyfile" ]; then
                echo "  ✓ Found: $keyfile"
                ls -lh "$HOME/.ssh/$keyfile"
            else
                echo "  ✗ Not found: $keyfile"
            fi
        done
        echo ""
        
        # Check SSH config
        if [ -f "$HOME/.ssh/config" ]; then
            echo "SSH config file exists:"
            ls -lh "$HOME/.ssh/config"
            echo "Contents:"
            cat "$HOME/.ssh/config"
        else
            echo "No SSH config file found"
        fi
        echo ""
        
        # Check known_hosts
        if [ -f "$HOME/.ssh/known_hosts" ]; then
            echo "known_hosts file exists:"
            ls -lh "$HOME/.ssh/known_hosts"
        else
            echo "No known_hosts file found"
        fi
    else
        echo "ERROR: SSH directory does not exist at $HOME/.ssh"
        echo "This will cause SFTP authentication to fail!"
    fi
    echo ""
    
    # Environment Variables
    echo "--- Environment Variables ---"
    echo "MACHINE_TOKEN: ${MACHINE_TOKEN:+[SET - ${#MACHINE_TOKEN} characters]}"
    echo "MACHINE_TOKEN: ${MACHINE_TOKEN:-[NOT SET]}"
    echo "SSH_KEY_PATH: ${SSH_KEY_PATH:-[NOT SET]}"
    echo "LOGS_DIR: ${LOGS_DIR:-[NOT SET]}"
    echo "HOME: $HOME"
    echo "PATH: $PATH"
    echo ""
    
    # Network connectivity test
    echo "--- Network Connectivity ---"
    echo "Testing DNS resolution for Pantheon:"
    if command -v dig >/dev/null 2>&1; then
        dig +short appserver.dev.drush.in 2>&1 || echo "DNS lookup failed"
    else
        echo "dig command not available"
    fi
    echo ""
    
    # SFTP availability
    echo "--- SFTP Client Check ---"
    if command -v sftp >/dev/null 2>&1; then
        echo "✓ SFTP client is available"
        sftp -V 2>&1 || echo "SFTP version check completed"
    else
        echo "✗ SFTP client not found - this is required for log collection!"
    fi
    echo ""
    
    # SSH agent information
    echo "--- SSH Agent ---"
    if [ -n "$SSH_AUTH_SOCK" ]; then
        echo "SSH_AUTH_SOCK: $SSH_AUTH_SOCK"
        echo "Testing ssh-add:"
        ssh-add -l 2>&1 || echo "No identities in ssh-agent or agent not running"
    else
        echo "SSH agent not running (SSH_AUTH_SOCK not set)"
    fi
    echo ""
    
    echo "=========================================="
    echo "END DEBUG OUTPUT"
    echo "=========================================="
    echo ""
fi

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