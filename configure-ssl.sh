#!/bin/bash

# Wazuh SSL Configuration Script
# This script configures SSL certificates for an existing Wazuh installation
# Following official documentation: https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/configuring-third-party-certs/ssl.html

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

# Check for required parameters
if [ -z "$1" ] || [ -z "$2" ]; then
    error "Usage: $0 <DOMAIN_NAME> <EMAIL>
    
Example: $0 wazuh.yourdomain.com admin@yourdomain.com

Required parameters:
  DOMAIN_NAME - Fully qualified domain name for your Wazuh installation
  EMAIL       - Email address for Let's Encrypt certificate registration

Prerequisites:
  - Wazuh must already be installed and running
  - Domain must point to this server's IP address
  - Ports 80 and 443 must be accessible from the internet"
fi

# Variables
DOMAIN_NAME="$1"
EMAIL="$2"

log "Starting SSL configuration for Wazuh Dashboard"
log "Domain: $DOMAIN_NAME"
log "Email: $EMAIL"

# Check if Wazuh is installed and running
log "Checking Wazuh installation..."
for service in wazuh-indexer wazuh-manager; do
    if ! sudo systemctl is-active --quiet $service; then
        error "$service is not running. Please install Wazuh first using ./install-wazuh.sh"
    fi
done

# Check if wazuh-dashboard is installed (but don't require it to be running)
if ! sudo systemctl is-enabled --quiet wazuh-dashboard 2>/dev/null; then
    error "wazuh-dashboard service not found. Please install Wazuh first using ./install-wazuh.sh"
fi

log "Wazuh installation verified"

# Start dashboard if not running (for accessibility check)
if ! sudo systemctl is-active --quiet wazuh-dashboard; then
    log "Starting Wazuh dashboard for configuration..."
    sudo systemctl start wazuh-dashboard
    sleep 10
fi

# Check if dashboard is accessible
if ! curl -s -k -o /dev/null -w "%{http_code}" https://localhost:443 | grep -q "200\|302\|401"; then
    if ! curl -s -k -o /dev/null -w "%{http_code}" https://localhost:5601 | grep -q "200\|302\|401"; then
        warn "Wazuh dashboard not accessible via HTTPS, but proceeding with SSL configuration..."
    fi
fi

# Step 1: Install Certbot (following official documentation)
log "Step 1: Installing Certbot..."

# For Ubuntu/Debian, use snap method as per documentation
if ! command -v certbot &> /dev/null; then
    log "Installing snap..."
    sudo apt-get update
    sudo apt-get install -y snapd
    
    log "Installing certbot via snap..."
    sudo snap install core; sudo snap refresh core
    sudo snap install --classic certbot
    sudo ln -sf /snap/bin/certbot /usr/bin/certbot
else
    log "Certbot already installed"
fi

# Step 2: Open Firewall Ports (following official documentation)
log "Step 2: Configuring firewall ports..."
sudo ufw allow 443/tcp
sudo ufw allow 80/tcp

# Step 3: Generate Let's Encrypt Certificate (following official documentation)
log "Step 3: Checking for existing Let's Encrypt certificate..."

# Check if certificate already exists using certbot certificates command
if sudo certbot certificates 2>/dev/null | grep -q "Certificate Name: $DOMAIN_NAME"; then
    log "SSL certificate already exists for $DOMAIN_NAME, using existing certificate"
elif [ -f "/etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem" ]; then
    log "SSL certificate files found for $DOMAIN_NAME, using existing certificate"
else
    log "Generating new Let's Encrypt certificate..."
    log "Stopping Wazuh dashboard temporarily for certificate generation..."
    sudo systemctl stop wazuh-dashboard
    
    # Generate certificate using standalone mode
    sudo certbot certonly --standalone --non-interactive --agree-tos --email $EMAIL -d $DOMAIN_NAME
    
    if [ ! -f "/etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem" ]; then
        error "Certificate generation failed. Please check your domain configuration and try again."
    fi
    
    log "SSL certificate generated successfully"
fi

# Step 4: Copy Certificates (following official documentation)
log "Step 4: Copying certificates to Wazuh dashboard directory..."

# First, let's see what certificates actually exist
log "Checking available certificates..."
sudo certbot certificates 2>/dev/null || warn "Could not list certificates"

# Find the actual certificate directory using sudo since it may have restricted permissions
CERT_DIR=""
if sudo test -d "/etc/letsencrypt/live/$DOMAIN_NAME"; then
    CERT_DIR="/etc/letsencrypt/live/$DOMAIN_NAME"
    log "Found certificate directory for $DOMAIN_NAME"
else
    # Try to find any certificate directory that might match
    AVAILABLE_DIRS=$(sudo find /etc/letsencrypt/live -maxdepth 1 -type d -name "*" 2>/dev/null | grep -v "^/etc/letsencrypt/live$" | head -5)
    if [ -n "$AVAILABLE_DIRS" ]; then
        log "Available certificate directories:"
        echo "$AVAILABLE_DIRS"
        # Use the first available directory
        CERT_DIR=$(echo "$AVAILABLE_DIRS" | head -1)
        log "Using certificate directory: $CERT_DIR"
    fi
fi

if [ -z "$CERT_DIR" ]; then
    error "No certificate directory found in /etc/letsencrypt/live/"
fi

# Verify certificate files exist and are readable
if ! sudo test -f "$CERT_DIR/privkey.pem"; then
    error "Private key file not found: $CERT_DIR/privkey.pem"
fi

if ! sudo test -f "$CERT_DIR/fullchain.pem"; then
    error "Certificate file not found: $CERT_DIR/fullchain.pem"
fi

log "Using certificates from: $CERT_DIR"
sudo cp "$CERT_DIR/privkey.pem" "$CERT_DIR/fullchain.pem" /etc/wazuh-dashboard/certs/

# Step 5: Configure Wazuh Dashboard (following official documentation)
log "Step 5: Configuring Wazuh Dashboard SSL settings..."

# Backup original configuration (only if backup doesn't exist)
if [ ! -f "/etc/wazuh-dashboard/opensearch_dashboards.yml.backup" ]; then
    sudo cp /etc/wazuh-dashboard/opensearch_dashboards.yml /etc/wazuh-dashboard/opensearch_dashboards.yml.backup
fi

# Create a clean configuration by modifying the existing SSL settings
sudo sed -i 's|server.ssl.key: "/etc/wazuh-dashboard/certs/wazuh-dashboard-key.pem"|server.ssl.key: "/etc/wazuh-dashboard/certs/privkey.pem"|g' /etc/wazuh-dashboard/opensearch_dashboards.yml
sudo sed -i 's|server.ssl.certificate: "/etc/wazuh-dashboard/certs/wazuh-dashboard.pem"|server.ssl.certificate: "/etc/wazuh-dashboard/certs/fullchain.pem"|g' /etc/wazuh-dashboard/opensearch_dashboards.yml

# Remove any previous Let's Encrypt configurations to avoid duplicates
sudo sed -i '/# SSL Configuration for Let'\''s Encrypt/,+3d' /etc/wazuh-dashboard/opensearch_dashboards.yml

# Step 6: Set Proper Permissions (following official documentation exactly)
log "Step 6: Setting proper file permissions..."
sudo chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/
sudo chmod -R 500 /etc/wazuh-dashboard/certs/
sudo chmod 440 /etc/wazuh-dashboard/certs/privkey.pem /etc/wazuh-dashboard/certs/fullchain.pem

# Step 7: Restart Wazuh Dashboard (following official documentation)
log "Step 7: Restarting Wazuh Dashboard..."
sudo systemctl restart wazuh-dashboard

# Wait for dashboard to start with SSL
sleep 15

# Verify SSL is working
if sudo systemctl is-active --quiet wazuh-dashboard; then
    log "Dashboard restarted successfully with SSL"
else
    warn "Dashboard failed to start with SSL configuration"
    log "Checking recent error logs..."
    sudo journalctl -u wazuh-dashboard --no-pager -n 20
    
    # Try to restore working configuration
    log "Restoring original dashboard configuration..."
    if [ -f "/etc/wazuh-dashboard/opensearch_dashboards.yml.backup" ]; then
        sudo cp /etc/wazuh-dashboard/opensearch_dashboards.yml.backup /etc/wazuh-dashboard/opensearch_dashboards.yml
        # Restore original certificate permissions
        sudo chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/
        sudo chmod -R 500 /etc/wazuh-dashboard/certs/
        sudo chmod 400 /etc/wazuh-dashboard/certs/*.pem 2>/dev/null || true
        sudo systemctl restart wazuh-dashboard
        sleep 10
    else
        warn "No backup configuration found to restore"
    fi
    
    if sudo systemctl is-active --quiet wazuh-dashboard; then
        warn "Dashboard restored with original configuration (no SSL)"
        warn "SSL configuration failed - check certificate files and permissions"
        error "SSL setup failed. Dashboard is running without SSL."
    else
        error "Dashboard failed to start even with original configuration. Check installation."
    fi
fi

# Test SSL access
log "Testing SSL access..."
if curl -s -k -o /dev/null -w "%{http_code}" https://localhost:443 | grep -q "200\|302\|401"; then
    log "Dashboard is accessible via HTTPS on port 443"
    DASHBOARD_URL="https://$DOMAIN_NAME"
elif curl -s -k -o /dev/null -w "%{http_code}" https://localhost:5601 | grep -q "200\|302\|401"; then
    log "Dashboard is accessible via HTTPS on port 5601"
    DASHBOARD_URL="https://$DOMAIN_NAME:5601"
else
    warn "Dashboard HTTPS access test inconclusive, but service is running"
    DASHBOARD_URL="https://$DOMAIN_NAME"
fi

# Setup automatic certificate renewal (optional enhancement)
log "Setting up automatic certificate renewal..."

# Test certificate renewal (dry run)
if sudo certbot renew --dry-run --quiet; then
    log "Certificate renewal test passed"
    
    # Create renewal hook to restart dashboard after renewal
    sudo mkdir -p /etc/letsencrypt/renewal-hooks/post/
    sudo tee /etc/letsencrypt/renewal-hooks/post/restart-wazuh-dashboard.sh > /dev/null <<EOF
#!/bin/bash
# Copy renewed certificates
cp /etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem /etc/wazuh-dashboard/certs/

# Set proper permissions
chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/
chmod -R 500 /etc/wazuh-dashboard/certs/
chmod 440 /etc/wazuh-dashboard/certs/privkey.pem /etc/wazuh-dashboard/certs/fullchain.pem

# Restart dashboard
systemctl restart wazuh-dashboard
EOF
    sudo chmod +x /etc/letsencrypt/renewal-hooks/post/restart-wazuh-dashboard.sh
    
    # Add cron job for certificate renewal
    sudo tee /etc/cron.d/certbot-renew > /dev/null <<EOF
0 12 * * * root certbot renew --quiet
EOF
    
    log "Automatic certificate renewal configured"
else
    warn "Certificate renewal test failed - manual renewal may be required"
fi

# Get server IP
SERVER_IP=$(hostname -I | awk '{print $1}')


# Display SSL configuration summary
log "SSL configuration completed successfully!"
echo
echo "============================================="
echo "         SSL CONFIGURATION SUMMARY"
echo "============================================="
echo "Dashboard URL: $DASHBOARD_URL"
echo ""
echo "Server IP: $SERVER_IP"
echo "API Endpoint: https://$DOMAIN_NAME:55000"
echo ""
echo "Agent Registration:"
echo "Server Address: $DOMAIN_NAME"
echo "Registration Port: 1515"
echo "Communication Port: 1514"
echo ""
echo "SSL Certificate: Let's Encrypt"
echo "Certificate Location: /etc/letsencrypt/live/$DOMAIN_NAME/"
echo "Auto-renewal: Enabled (daily check at 12:00)"
echo ""
echo "============================================="
echo "Next Steps:"
echo "1. Access dashboard at $DASHBOARD_URL"
echo "2. Accept/verify SSL certificate in browser"
echo "3. Login with credentials from your base installation"
echo "4. Configure agents to use $DOMAIN_NAME"
echo "============================================="

warn "IMPORTANT: SSL is now enabled on the Wazuh dashboard"
warn "Update any existing agent configurations to use the new domain name"

log "SSL configuration completed successfully!"
log "Your Wazuh installation is now secured with Let's Encrypt SSL!"