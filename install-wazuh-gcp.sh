#!/bin/bash

# Wazuh Installation Script for Debian-based GCP VM with SSL Configuration
# This script installs Wazuh using the official installation assistant with SSL/HTTPS configuration

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
  EMAIL       - Email address for Let's Encrypt certificate registration"
fi

# Variables
WAZUH_VERSION="4.12"
DOMAIN_NAME="$1"
EMAIL="$2"
INSTALL_DIR="/tmp/wazuh-install"

log "Starting Wazuh installation on GCP VM"
log "Domain: $DOMAIN_NAME"
log "Email: $EMAIL"

# Update system
log "Updating system packages..."
sudo apt-get update && sudo apt-get upgrade -y

# Install required packages
log "Installing required packages..."
sudo apt-get install -y curl apt-transport-https lsb-release gnupg2 software-properties-common wget

# Install certbot for SSL certificates
log "Installing Certbot for SSL certificates..."
sudo apt-get install -y certbot

# Create temporary installation directory
log "Creating temporary installation directory..."
mkdir -p $INSTALL_DIR
cd $INSTALL_DIR

# Download Wazuh installation assistant
log "Downloading Wazuh installation assistant..."
curl -sO https://packages.wazuh.com/4.12/wazuh-install.sh
chmod +x wazuh-install.sh

# Generate SSL certificates using Let's Encrypt before installation
log "Generating SSL certificates..."
sudo certbot certonly --standalone --non-interactive --agree-tos --email $EMAIL -d $DOMAIN_NAME

# Install Wazuh using the installation assistant (all-in-one)
log "Installing Wazuh components using installation assistant..."
sudo ./wazuh-install.sh -a

# Wait for services to start
log "Waiting for services to initialize..."
sleep 30

# Get generated passwords
WAZUH_PASSWORDS_FILE="/tmp/wazuh-install-files/wazuh-passwords.txt"
if [ -f "$WAZUH_PASSWORDS_FILE" ]; then
    log "Wazuh passwords saved to: $WAZUH_PASSWORDS_FILE"
    ADMIN_PASSWORD=$(grep "User: admin" $WAZUH_PASSWORDS_FILE | awk '{print $NF}')
else
    warn "Password file not found at expected location. Check /tmp/wazuh-install-files/"
    ADMIN_PASSWORD="admin"
fi

# Configure SSL for Wazuh Dashboard
log "Configuring SSL for Wazuh Dashboard..."

# Stop Wazuh Dashboard to modify configuration
sudo systemctl stop wazuh-dashboard

# Backup original configuration
sudo cp /etc/wazuh-dashboard/opensearch_dashboards.yml /etc/wazuh-dashboard/opensearch_dashboards.yml.backup

# Configure Wazuh Dashboard with SSL
sudo tee /etc/wazuh-dashboard/opensearch_dashboards.yml > /dev/null <<EOF
server.host: 0.0.0.0
server.port: 5601
opensearch.hosts: https://localhost:9200
opensearch.ssl.verificationMode: certificate
opensearch.ssl.certificateAuthorities: ["/etc/ssl/certs/root-ca.pem"]
opensearch.username: kibanaserver
opensearch.password: kibanaserver
opensearch.requestHeadersWhitelist: ["securitytenant","Authorization"]
opensearch_security.multitenancy.enabled: false
opensearch_security.readonly_mode.roles: ["kibana_read_only"]
server.ssl.enabled: true
server.ssl.certificate: /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem
server.ssl.key: /etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem
uiSettings.overrides.defaultRoute: /app/wz-home
EOF

# Configure Wazuh Indexer SSL certificates
log "Configuring SSL for Wazuh Indexer..."

# Stop Wazuh Indexer
sudo systemctl stop wazuh-indexer

# Update indexer configuration for custom SSL
sudo cp /etc/wazuh-indexer/opensearch.yml /etc/wazuh-indexer/opensearch.yml.backup

# Create symbolic links to Let's Encrypt certificates for indexer
sudo ln -sf /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem /etc/wazuh-indexer/certs/node.pem
sudo ln -sf /etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem /etc/wazuh-indexer/certs/node-key.pem
sudo ln -sf /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem /etc/wazuh-indexer/certs/root-ca.pem

# Set proper permissions for certificates
sudo chown wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs/node.pem
sudo chown wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs/node-key.pem
sudo chown wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs/root-ca.pem
sudo chmod 400 /etc/wazuh-indexer/certs/node-key.pem

# Also set permissions for dashboard
sudo chown wazuh-dashboard:wazuh-dashboard /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem
sudo chown wazuh-dashboard:wazuh-dashboard /etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem
sudo chmod 644 /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem
sudo chmod 600 /etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem

# Install and configure Nginx reverse proxy
log "Setting up Nginx reverse proxy..."
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
sudo nginx -t

# Configure firewall
log "Configuring firewall..."
sudo ufw --force enable
sudo ufw allow ssh
sudo ufw allow http
sudo ufw allow https
sudo ufw allow 1514/udp  # Wazuh agent communication
sudo ufw allow 1515/tcp  # Wazuh agent enrollment
sudo ufw allow 55000/tcp # Wazuh API

# Start all services in the correct order
log "Starting Wazuh services..."
sudo systemctl start wazuh-indexer
sleep 10
sudo systemctl start wazuh-manager
sleep 10
sudo systemctl start wazuh-dashboard
sleep 10
sudo systemctl start nginx

# Enable services to start on boot
sudo systemctl enable wazuh-indexer
sudo systemctl enable wazuh-manager
sudo systemctl enable wazuh-dashboard
sudo systemctl enable nginx

# Setup automatic certificate renewal
log "Setting up automatic SSL certificate renewal..."
sudo tee /etc/cron.d/certbot-renew > /dev/null <<EOF
0 12 * * * root certbot renew --quiet --pre-hook "systemctl stop nginx wazuh-dashboard" --post-hook "systemctl start wazuh-dashboard nginx"
EOF

# Create certificate renewal hook script
sudo tee /etc/letsencrypt/renewal-hooks/post/wazuh-restart.sh > /dev/null <<EOF
#!/bin/bash
# Update certificate permissions
chown wazuh-indexer:wazuh-indexer /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem
chown wazuh-indexer:wazuh-indexer /etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem
chown wazuh-dashboard:wazuh-dashboard /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem
chown wazuh-dashboard:wazuh-dashboard /etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem
chmod 644 /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem
chmod 600 /etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem

# Restart services
systemctl restart wazuh-indexer
systemctl restart wazuh-dashboard
systemctl restart nginx
EOF

sudo chmod +x /etc/letsencrypt/renewal-hooks/post/wazuh-restart.sh

# Wait for services to be fully ready
log "Waiting for all services to be ready..."
sleep 30

# Test service status
log "Checking service status..."
for service in wazuh-indexer wazuh-manager wazuh-dashboard nginx; do
    if sudo systemctl is-active --quiet $service; then
        log "$service is running"
    else
        warn "$service is not running - checking status"
        sudo systemctl status $service --no-pager -l
    fi
done

# Clean up installation files
log "Cleaning up installation files..."
cd /
sudo rm -rf $INSTALL_DIR

# Display installation summary
log "Wazuh installation completed successfully!"
echo
echo "============================================="
echo "           INSTALLATION SUMMARY"
echo "============================================="
echo "Wazuh Dashboard URL: https://$DOMAIN_NAME"
echo "Default Username: admin"
if [ -n "$ADMIN_PASSWORD" ] && [ "$ADMIN_PASSWORD" != "admin" ]; then
    echo "Generated Password: $ADMIN_PASSWORD"
else
    echo "Password: Check $WAZUH_PASSWORDS_FILE"
fi
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
echo "SSL Certificate: Let's Encrypt (auto-renewal enabled)"
echo "Password File: $WAZUH_PASSWORDS_FILE"
echo ""
echo "Service Management Commands:"
echo "  sudo systemctl start|stop|restart wazuh-manager"
echo "  sudo systemctl start|stop|restart wazuh-indexer"
echo "  sudo systemctl start|stop|restart wazuh-dashboard"
echo ""
echo "============================================="
echo "Next Steps:"
echo "1. Access the dashboard at https://$DOMAIN_NAME"
echo "2. Login with the credentials shown above"
echo "3. Configure agents using the registration service"
echo "4. Review firewall rules and security settings"
echo "5. Set up regular backups"
echo "============================================="

warn "IMPORTANT: Save the password file $WAZUH_PASSWORDS_FILE in a secure location!"
warn "The generated passwords are unique and cannot be recovered if lost."

log "Installation completed successfully!"