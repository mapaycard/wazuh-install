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

log "Starting SSL configuration for Wazuh"
log "Domain: $DOMAIN_NAME"
log "Email: $EMAIL"

# Check if Wazuh is installed and running
log "Checking Wazuh installation..."
for service in wazuh-indexer wazuh-manager wazuh-dashboard; do
    if ! sudo systemctl is-active --quiet $service; then
        error "$service is not running. Please install Wazuh first using ./install-wazuh-base.sh"
    fi
done
log "Wazuh installation verified"

# Check if dashboard is accessible
if ! curl -s -o /dev/null -w "%{http_code}" http://localhost:5601 | grep -q "200\|302"; then
    error "Wazuh dashboard is not accessible on port 5601. Please check the installation."
fi

# Install certbot for SSL certificates
log "Installing Certbot for SSL certificates..."
sudo apt-get update
sudo apt-get install -y certbot

# Configure firewall for SSL
log "Updating firewall configuration for SSL..."
sudo ufw allow http
sudo ufw allow https

# Generate Let's Encrypt certificate
log "Generating Let's Encrypt SSL certificate..."
log "Stopping dashboard temporarily for certificate generation..."
sudo systemctl stop wazuh-dashboard

# Generate certificate using standalone mode
sudo certbot certonly --standalone --non-interactive --agree-tos --email $EMAIL -d $DOMAIN_NAME

if [ ! -f "/etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem" ]; then
    error "Certificate generation failed. Please check your domain configuration and try again."
fi

log "SSL certificate generated successfully"

# Configure SSL on Wazuh Dashboard following official documentation
log "Configuring SSL certificates on Wazuh Dashboard..."

# Step 1: Copy certificates to Wazuh dashboard directory
log "Step 1: Copying certificates to Wazuh dashboard directory..."
sudo cp /etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem /etc/wazuh-dashboard/certs/
sudo cp /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem /etc/wazuh-dashboard/certs/

# Step 2: Backup and configure Wazuh Dashboard SSL settings
log "Step 2: Configuring Wazuh Dashboard SSL settings..."
sudo cp /etc/wazuh-dashboard/opensearch_dashboards.yml /etc/wazuh-dashboard/opensearch_dashboards.yml.backup

# Add SSL configuration to the dashboard config
sudo tee -a /etc/wazuh-dashboard/opensearch_dashboards.yml > /dev/null <<EOF

# SSL Configuration for Let's Encrypt
server.ssl.enabled: true
server.ssl.key: "/etc/wazuh-dashboard/certs/privkey.pem"
server.ssl.certificate: "/etc/wazuh-dashboard/certs/fullchain.pem"
EOF

# Step 3: Set proper permissions following official documentation
log "Step 3: Setting proper file permissions..."
sudo chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/
sudo chmod -R 500 /etc/wazuh-dashboard/certs/
sudo chmod 440 /etc/wazuh-dashboard/certs/privkey.pem /etc/wazuh-dashboard/certs/fullchain.pem

# Step 4: Restart Wazuh Dashboard
log "Step 4: Restarting Wazuh Dashboard with SSL configuration..."
sudo systemctl restart wazuh-dashboard

# Wait for dashboard to start with SSL
sleep 15

# Verify SSL is working
if sudo systemctl is-active --quiet wazuh-dashboard; then
    log "Dashboard restarted successfully with SSL"
else
    error "Dashboard failed to start with SSL. Check logs: sudo journalctl -u wazuh-dashboard"
fi

# Test SSL access
log "Testing SSL access..."
if curl -s -k -o /dev/null -w "%{http_code}" https://localhost:5601 | grep -q "200\|302"; then
    log "Dashboard is accessible via HTTPS on port 5601"
else
    warn "Dashboard HTTPS access test failed, but service is running"
fi

# Install and configure Nginx reverse proxy for better SSL handling
log "Setting up Nginx reverse proxy for optimal SSL performance..."
sudo apt-get install -y nginx

sudo tee /etc/nginx/sites-available/wazuh > /dev/null <<EOF
server {
    listen 80;
    server_name $DOMAIN_NAME;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $DOMAIN_NAME;

    ssl_certificate /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 5m;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;

    location / {
        proxy_pass https://localhost:5601;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
        proxy_redirect off;
        
        # SSL verification settings for backend
        proxy_ssl_verify off;
        proxy_ssl_session_reuse on;
    }

    # API endpoint
    location /api {
        proxy_pass https://localhost:55000;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_ssl_verify off;
    }
}
EOF

# Enable the site and test nginx configuration
sudo ln -sf /etc/nginx/sites-available/wazuh /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default

# Test nginx configuration
if sudo nginx -t; then
    log "Nginx configuration is valid"
    sudo systemctl restart nginx
    sudo systemctl enable nginx
else
    error "Nginx configuration test failed"
fi

# Setup automatic certificate renewal following official documentation
log "Setting up automatic SSL certificate renewal..."

# Create renewal hook directories
sudo mkdir -p /etc/letsencrypt/renewal-hooks/pre/
sudo mkdir -p /etc/letsencrypt/renewal-hooks/post/

# Pre-hook: Stop dashboard before renewal
sudo tee /etc/letsencrypt/renewal-hooks/pre/wazuh-stop.sh > /dev/null <<EOF
#!/bin/bash
systemctl stop wazuh-dashboard
EOF

# Post-hook: Copy certificates and restart services
sudo tee /etc/letsencrypt/renewal-hooks/post/wazuh-restart.sh > /dev/null <<EOF
#!/bin/bash
# Copy new certificates to wazuh directory
cp /etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem /etc/wazuh-dashboard/certs/
cp /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem /etc/wazuh-dashboard/certs/

# Set proper permissions
chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/
chmod -R 500 /etc/wazuh-dashboard/certs/
chmod 440 /etc/wazuh-dashboard/certs/privkey.pem /etc/wazuh-dashboard/certs/fullchain.pem

# Restart services
systemctl restart wazuh-dashboard
systemctl reload nginx
EOF

sudo chmod +x /etc/letsencrypt/renewal-hooks/pre/wazuh-stop.sh
sudo chmod +x /etc/letsencrypt/renewal-hooks/post/wazuh-restart.sh

# Add cron job for certificate renewal
sudo tee /etc/cron.d/certbot-renew > /dev/null <<EOF
0 12 * * * root certbot renew --quiet
EOF

# Test certificate renewal (dry run)
log "Testing certificate renewal process..."
if sudo certbot renew --dry-run --quiet; then
    log "Certificate renewal test passed"
else
    warn "Certificate renewal test failed - check configuration"
fi

# Final service status check
log "Checking final service status..."
sleep 5

for service in wazuh-indexer wazuh-manager wazuh-dashboard nginx; do
    if sudo systemctl is-active --quiet $service; then
        log "$service is running"
    else
        warn "$service is not running - checking status"
        sudo systemctl status $service --no-pager -l
    fi
done

# Get stored passwords
WAZUH_PASSWORDS_FILE="/tmp/wazuh-install-files/wazuh-passwords.txt"
if [ -f "$WAZUH_PASSWORDS_FILE" ]; then
    ADMIN_PASSWORD=$(grep "User: admin" $WAZUH_PASSWORDS_FILE | awk '{print $NF}')
else
    ADMIN_PASSWORD="Check password file"
fi

# Display SSL configuration summary
log "SSL configuration completed successfully!"
echo
echo "============================================="
echo "         SSL CONFIGURATION SUMMARY"
echo "============================================="
echo "Wazuh Dashboard URL: https://$DOMAIN_NAME"
echo "Default Username: admin"
echo "Password: $ADMIN_PASSWORD"
echo ""
echo "API Endpoint: https://$DOMAIN_NAME:55000"
echo "API Username: wazuh-wui"
echo "API Password: Check $WAZUH_PASSWORDS_FILE"
echo ""
echo "Agent Registration:"
echo "Server Address: $DOMAIN_NAME"
echo "Registration Port: 1515"
echo "Communication Port: 1514"
echo ""
echo "SSL Certificate: Let's Encrypt"
echo "Auto-renewal: Enabled (daily check at 12:00)"
echo "Certificate Location: /etc/letsencrypt/live/$DOMAIN_NAME/"
echo ""
echo "Services:"
echo "  - Dashboard: https://localhost:5601 (direct)"
echo "  - Nginx Proxy: https://$DOMAIN_NAME (recommended)"
echo ""
echo "============================================="
echo "Next Steps:"
echo "1. Access dashboard at https://$DOMAIN_NAME"
echo "2. Verify SSL certificate in browser"
echo "3. Configure agents to use $DOMAIN_NAME"
echo "4. Monitor certificate renewal logs"
echo "============================================="

warn "IMPORTANT: SSL is now enabled on the dashboard"
warn "Update any existing agent configurations to use the new domain name"

log "SSL configuration completed successfully!"
log "Your Wazuh installation is now secured with Let's Encrypt SSL!"