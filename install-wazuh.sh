#!/bin/bash

# Wazuh Installation Script
# Following official documentation: https://documentation.wazuh.com/current/quickstart.html

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
    exit 1
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   error "This script should not be run as root for security reasons. Please run as a regular user with sudo privileges."
fi

# Check if running on Debian/Ubuntu
if ! command -v apt-get &> /dev/null; then
    error "This script is designed for Debian/Ubuntu systems only."
fi

log "Starting Wazuh installation following official quickstart guide"

# Update system
log "Updating system packages..."
sudo apt-get update && sudo apt-get upgrade -y

# Install required packages
log "Installing required packages..."
if apt-cache show software-properties-common >/dev/null 2>&1; then
    sudo apt-get install -y curl wget
else
    sudo apt-get install -y curl wget ca-certificates
fi

# Download and run Wazuh installation script (official method)
log "Downloading and running official Wazuh installation script..."
curl -sO https://packages.wazuh.com/4.12/wazuh-install.sh

# Make script executable
chmod +x wazuh-install.sh

# Run Wazuh installation (all-in-one deployment)
log "Installing Wazuh components (this may take several minutes)..."
sudo bash ./wazuh-install.sh -a

# Wait for services to initialize
log "Waiting for Wazuh services to initialize..."
sleep 30

# Check installation status
log "Verifying Wazuh installation..."
for service in wazuh-indexer wazuh-manager wazuh-dashboard; do
    if sudo systemctl is-active --quiet $service; then
        log "$service is running"
    else
        warn "$service status check:"
        sudo systemctl status $service --no-pager -l
    fi
done

# Find password file
log "Locating password file..."
WAZUH_PASSWORDS_FILE=""

# Check common locations for password file
if [ -f "/tmp/wazuh-install-files/wazuh-passwords.txt" ]; then
    WAZUH_PASSWORDS_FILE="/tmp/wazuh-install-files/wazuh-passwords.txt"
elif [ -f "wazuh-install-files.tar" ]; then
    log "Extracting password file from tar archive..."
    sudo tar -tf wazuh-install-files.tar
    WAZUH_PASSWORDS_FILE="wazuh-install-files.tar"
else
    # Search for password file
    SEARCH_RESULT=$(sudo find / -name "wazuh-passwords.txt" 2>/dev/null | head -1)
    if [ -n "$SEARCH_RESULT" ]; then
        WAZUH_PASSWORDS_FILE="$SEARCH_RESULT"
    fi
fi

if [ -n "$WAZUH_PASSWORDS_FILE" ]; then
    log "Password file found at: $WAZUH_PASSWORDS_FILE"
    if [[ $WAZUH_PASSWORDS_FILE == *.tar ]]; then
        warn "Password file is in tar archive. Extract with: tar -xf $WAZUH_PASSWORDS_FILE"
    else
        ADMIN_PASSWORD=$(grep "User: admin" "$WAZUH_PASSWORDS_FILE" 2>/dev/null | awk '{print $NF}' || echo "admin")
    fi
else
    warn "Password file not found. Check installation output above for credentials."
    ADMIN_PASSWORD="admin"
fi

# Configure firewall for Wazuh (following official documentation)
log "Configuring firewall..."
sudo ufw --force enable
sudo ufw allow ssh
sudo ufw allow 443/tcp    # Wazuh dashboard HTTPS
sudo ufw allow 1514/udp   # Wazuh agent communication (UDP)
sudo ufw allow 1514/tcp   # Wazuh agent communication (TCP fallback)
sudo ufw allow 1515/tcp   # Wazuh agent enrollment  
sudo ufw allow 55000/tcp  # Wazuh API

# Get server IP
SERVER_IP=$(hostname -I | awk '{print $1}')

# Enable services
sudo systemctl enable wazuh-indexer
sudo systemctl enable wazuh-manager
sudo systemctl enable wazuh-dashboard

# Final verification
log "Final verification..."
sleep 10

# Check if dashboard is accessible via HTTPS
if curl -k -s -o /dev/null -w "%{http_code}" https://localhost:443 | grep -q "200\|302\|401"; then
    log "Dashboard is accessible via HTTPS"
    DASHBOARD_URL="https://$SERVER_IP"
elif curl -k -s -o /dev/null -w "%{http_code}" https://localhost:5601 | grep -q "200\|302\|401"; then
    log "Dashboard is accessible on port 5601"
    DASHBOARD_URL="https://$SERVER_IP:5601"
    warn "Dashboard is running on port 5601 instead of standard 443"
else
    warn "Dashboard HTTPS accessibility test inconclusive"
    DASHBOARD_URL="https://$SERVER_IP (try port 443 or 5601)"
fi

# Clean up installation files
log "Cleaning up installation files..."
rm -f wazuh-install.sh

# Disable Wazuh repository to prevent unintended updates
log "Disabling Wazuh repository to prevent unintended updates..."
sudo sed -i "s/^deb /#deb /" /etc/apt/sources.list.d/wazuh.list
sudo apt-get update

# Display installation summary
log "Wazuh installation completed!"
echo
echo "============================================="
echo "         WAZUH INSTALLATION SUMMARY"
echo "============================================="
echo "Dashboard URL: $DASHBOARD_URL"
echo "Username: admin"
if [ -n "$ADMIN_PASSWORD" ] && [ "$ADMIN_PASSWORD" != "admin" ]; then
    echo "Password: $ADMIN_PASSWORD"
else
    echo "Password: Check $WAZUH_PASSWORDS_FILE"
fi
echo ""
echo "Server IP: $SERVER_IP"
echo "API Endpoint: https://$SERVER_IP:55000"
echo ""
echo "Agent Registration:"
echo "Server Address: $SERVER_IP"
echo "Registration Port: 1515"
echo "Communication Port: 1514"
echo ""
echo "Password File: $WAZUH_PASSWORDS_FILE"
echo ""
echo "============================================="
echo "Next Steps:"
echo "1. Access dashboard at $DASHBOARD_URL"
echo "2. Accept the self-signed certificate warning"
echo "3. Login with username 'admin' and password above"
echo "4. (Optional) Run ./configure-ssl.sh for custom SSL"
echo "============================================="

warn "IMPORTANT: Save the password file in a secure location!"
if [[ $WAZUH_PASSWORDS_FILE == *.tar ]]; then
    warn "Extract password file: tar -xf $WAZUH_PASSWORDS_FILE"
fi

log "Installation completed successfully!"
log "Access your Wazuh dashboard at: $DASHBOARD_URL"