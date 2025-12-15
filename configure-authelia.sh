#!/bin/bash

# Authelia 2FA Configuration Script for Wazuh
# This script deploys Authelia as a Docker container to provide TOTP-based 2FA for Wazuh Dashboard
# Prerequisites: Run install-wazuh.sh and configure-ssl.sh first

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
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

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
}

# Rollback function
rollback() {
    warn "An error occurred. Rolling back Authelia installation..."

    # Stop and remove container
    if command -v docker &> /dev/null; then
        cd /opt/authelia 2>/dev/null && sudo docker compose down 2>/dev/null || true
    fi

    # Restore original Nginx config
    if [ -f "/etc/nginx/sites-available/wazuh-redirect.pre-authelia.backup" ]; then
        sudo rm -f /etc/nginx/sites-enabled/wazuh-authelia 2>/dev/null || true
        sudo ln -sf /etc/nginx/sites-available/wazuh-redirect /etc/nginx/sites-enabled/ 2>/dev/null || true
        sudo systemctl reload nginx 2>/dev/null || true
        warn "Original Nginx configuration restored"
    fi

    # Restore original Wazuh Dashboard config (port 443)
    DASHBOARD_CONFIG="/etc/wazuh-dashboard/opensearch_dashboards.yml"
    if [ -f "${DASHBOARD_CONFIG}.pre-authelia.backup" ]; then
        sudo cp "${DASHBOARD_CONFIG}.pre-authelia.backup" "$DASHBOARD_CONFIG" 2>/dev/null || true
        sudo systemctl restart wazuh-dashboard 2>/dev/null || true
        warn "Original Wazuh Dashboard configuration restored"
    fi

    error "Installation failed. Original configuration restored where possible."
}

# Set trap for cleanup on error
trap rollback ERR

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   error "This script should not be run as root for security reasons. Please run as a regular user with sudo privileges."
fi

# Check if running on Debian/Ubuntu
if ! command -v apt-get &> /dev/null; then
    error "This script is designed for Debian/Ubuntu systems only."
fi

# Check for required parameters
if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
    error "Usage: $0 <DOMAIN_NAME> <ADMIN_EMAIL> <ADMIN_USERNAME>

Example: $0 wazuh.yourdomain.com admin@yourdomain.com admin

Required parameters:
  DOMAIN_NAME     - Base domain for Wazuh (e.g., wazuh.yourdomain.com)
  ADMIN_EMAIL     - Admin email for notifications and certificates
  ADMIN_USERNAME  - Initial admin username for Authelia

Prerequisites:
  - Wazuh must be installed and running (run install-wazuh.sh)
  - SSL must be configured (run configure-ssl.sh)
  - Domain must point to this server"
fi

# Variables
DOMAIN_NAME="$1"
ADMIN_EMAIL="$2"
ADMIN_USERNAME="$3"

# Auth portal path (path-based approach - no separate subdomain needed)
AUTH_PATH="/auth/"
AUTH_URL="https://$DOMAIN_NAME$AUTH_PATH"

AUTHELIA_DIR="/opt/authelia"

log "Starting Authelia 2FA configuration for Wazuh Dashboard"
log "Wazuh Domain: $DOMAIN_NAME"
log "Auth Portal: $AUTH_URL"
log "Admin User: $ADMIN_USERNAME"
log "Admin Email: $ADMIN_EMAIL"

# ============================================
# Step 1: Prerequisites Check
# ============================================
log "Step 1: Checking prerequisites..."

# Check Wazuh is installed and running
for service in wazuh-indexer wazuh-manager wazuh-dashboard; do
    if ! sudo systemctl is-active --quiet $service; then
        error "$service is not running. Please install Wazuh first using ./install-wazuh.sh"
    fi
done
log "Wazuh services verified"

# Check SSL is configured
if ! sudo test -f "/etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem"; then
    # Try to find certificate in alternate location
    if ! sudo test -d "/etc/letsencrypt/live/"; then
        error "SSL certificates not found. Run ./configure-ssl.sh first."
    fi
    warn "Certificate for $DOMAIN_NAME not found, checking available certificates..."
    AVAILABLE_CERTS=$(sudo find /etc/letsencrypt/live -maxdepth 1 -type d 2>/dev/null | grep -v "^/etc/letsencrypt/live$" | head -1)
    if [ -z "$AVAILABLE_CERTS" ]; then
        error "No SSL certificates found. Run ./configure-ssl.sh first."
    fi
    CERT_DOMAIN=$(basename "$AVAILABLE_CERTS")
    warn "Using certificates from: $CERT_DOMAIN"
else
    CERT_DOMAIN="$DOMAIN_NAME"
fi
log "SSL certificates verified: $CERT_DOMAIN"

# Check Nginx is installed
if ! command -v nginx &> /dev/null; then
    error "Nginx is not installed. Run ./configure-ssl.sh first."
fi

# Check Nginx has auth_request module (required for forward auth)
if ! nginx -V 2>&1 | grep -q "http_auth_request_module"; then
    log "Nginx auth_request module not available, upgrading to nginx-full..."
    sudo systemctl stop nginx
    sudo apt-get update
    sudo apt-get install -y nginx-full
    sudo systemctl start nginx

    # Verify module is now available
    if ! nginx -V 2>&1 | grep -q "http_auth_request_module"; then
        error "Failed to install Nginx auth_request module. Please manually install nginx-full or nginx-extras."
    fi
    log "Nginx upgraded to nginx-full with auth_request module"
fi
log "Nginx verified (with auth_request module)"

# Check if Authelia is already running
if command -v docker &> /dev/null && docker ps 2>/dev/null | grep -q authelia; then
    warn "Authelia container is already running"
    echo -n "Do you want to reconfigure? (y/N): "
    read -r reconfigure
    if [[ ! $reconfigure =~ ^[Yy]$ ]]; then
        log "Keeping existing configuration"
        exit 0
    fi
    log "Stopping existing Authelia container..."
    cd "$AUTHELIA_DIR" 2>/dev/null && sudo docker compose down 2>/dev/null || true
fi

# ============================================
# Step 2: Docker Installation
# ============================================
log "Step 2: Checking Docker installation..."

if ! command -v docker &> /dev/null; then
    log "Installing Docker..."
    sudo apt-get update
    sudo apt-get install -y ca-certificates curl gnupg

    # Detect OS (Ubuntu or Debian)
    . /etc/os-release
    OS_ID="$ID"
    OS_VERSION_CODENAME="$VERSION_CODENAME"

    # Add Docker's official GPG key
    sudo install -m 0755 -d /etc/apt/keyrings

    # Remove existing GPG key if present to avoid conflicts
    sudo rm -f /etc/apt/keyrings/docker.gpg 2>/dev/null || true

    if [ "$OS_ID" = "ubuntu" ]; then
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $OS_VERSION_CODENAME stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    elif [ "$OS_ID" = "debian" ]; then
        curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $OS_VERSION_CODENAME stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    else
        error "Unsupported OS: $OS_ID. Only Ubuntu and Debian are supported."
    fi

    sudo chmod a+r /etc/apt/keyrings/docker.gpg
    sudo apt-get update
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

    sudo systemctl enable docker
    sudo systemctl start docker

    # Add current user to docker group
    sudo usermod -aG docker "$USER"
    log "Docker installed successfully"
    warn "You may need to log out and back in for docker group changes to take effect"
else
    log "Docker already installed"
fi

# Ensure docker-compose plugin is available
if ! docker compose version &> /dev/null 2>&1; then
    log "Installing docker-compose-plugin..."
    sudo apt-get install -y docker-compose-plugin
fi

# ============================================
# Step 3: Create Directory Structure
# ============================================
log "Step 3: Creating Authelia directory structure..."

# Backup existing config if present
if [ -d "$AUTHELIA_DIR/config" ]; then
    BACKUP_DATE=$(date +%Y%m%d_%H%M%S)
    sudo cp -r "$AUTHELIA_DIR/config" "$AUTHELIA_DIR/config.backup.$BACKUP_DATE"
    log "Backed up existing config to config.backup.$BACKUP_DATE"
fi

sudo mkdir -p "$AUTHELIA_DIR"/{config,data}
sudo chown -R "$USER":"$USER" "$AUTHELIA_DIR"

# ============================================
# Step 4: Generate Secrets
# ============================================
log "Step 4: Generating secure secrets..."

JWT_SECRET=$(openssl rand -hex 32)
SESSION_SECRET=$(openssl rand -hex 32)
STORAGE_ENCRYPTION_KEY=$(openssl rand -hex 32)

log "Secrets generated"

# ============================================
# Step 5: Create Authelia Configuration
# ============================================
log "Step 5: Creating Authelia configuration..."

cat > "$AUTHELIA_DIR/config/configuration.yml" <<EOF
---
# Authelia Configuration for Wazuh 2FA
# Generated by configure-authelia.sh

theme: dark

server:
  address: 'tcp://0.0.0.0:9091/auth'
  endpoints:
    authz:
      auth-request:
        implementation: 'AuthRequest'

log:
  level: info
  file_path: /config/authelia.log

totp:
  disable: false
  issuer: 'Wazuh - $DOMAIN_NAME'
  algorithm: sha1
  digits: 6
  period: 30
  skew: 1
  secret_size: 32

identity_validation:
  reset_password:
    jwt_secret: '$JWT_SECRET'

authentication_backend:
  file:
    path: /config/users_database.yml
    watch: true
    password:
      algorithm: argon2id
      iterations: 3
      memory: 65536
      parallelism: 4
      key_length: 32
      salt_length: 16

access_control:
  default_policy: deny
  rules:
    # Require 2FA for dashboard access
    - domain: '$DOMAIN_NAME'
      policy: two_factor

session:
  secret: '$SESSION_SECRET'
  name: authelia_session
  same_site: lax
  inactivity: 5m
  expiration: 1h
  remember_me: 1M
  cookies:
    - domain: '$DOMAIN_NAME'
      authelia_url: '$AUTH_URL'
      default_redirection_url: 'https://$DOMAIN_NAME'

regulation:
  max_retries: 3
  find_time: 2m
  ban_time: 5m

storage:
  encryption_key: '$STORAGE_ENCRYPTION_KEY'
  local:
    path: /data/db.sqlite3

notifier:
  # File-based notifications (check /opt/authelia/config/notification.txt for setup links)
  filesystem:
    filename: /config/notification.txt
  # For production, uncomment and configure SMTP:
  # smtp:
  #   address: 'submissions://smtp.example.com:587'
  #   sender: 'Authelia <authelia@$DOMAIN_NAME>'
  #   username: 'smtp_user'
  #   password: 'smtp_password'
EOF

log "Authelia configuration created"

# ============================================
# Step 6: Create Initial Admin User
# ============================================
log "Step 6: Creating initial admin user..."

# Disable xtrace temporarily to prevent password exposure in logs
_xtrace_was_set=0
if [[ "$-" == *x* ]]; then
    set +x
    _xtrace_was_set=1
fi

echo
echo -n "Enter password for $ADMIN_USERNAME: "
IFS= read -rs ADMIN_PASSWORD
echo
echo -n "Confirm password: "
IFS= read -rs ADMIN_PASSWORD_CONFIRM
echo

# Restore xtrace if it was set
if [[ $_xtrace_was_set -eq 1 ]]; then
    set -x
fi

if [ "$ADMIN_PASSWORD" != "$ADMIN_PASSWORD_CONFIRM" ]; then
    error "Passwords do not match"
fi

if [ ${#ADMIN_PASSWORD} -lt 8 ]; then
    error "Password must be at least 8 characters"
fi

log "Generating password hash (this may take a moment)..."

# Pull Authelia image first to ensure it's available
sudo docker pull authelia/authelia:latest

# Generate password hash using Authelia container
# Password is passed via stdin to avoid exposure in process list
HASHED_PASSWORD=$(echo "$ADMIN_PASSWORD" | sudo docker run --rm -i authelia/authelia:latest authelia crypto hash generate argon2 2>/dev/null | grep "Digest:" | awk '{print $2}')

if [ -z "$HASHED_PASSWORD" ]; then
    error "Failed to generate password hash"
fi

# Create users database
cat > "$AUTHELIA_DIR/config/users_database.yml" <<EOF
---
# Authelia Users Database
# Generated by configure-authelia.sh
#
# To add new users:
# 1. Generate password hash:
#    docker run --rm authelia/authelia:latest authelia crypto hash generate argon2 --password 'newpassword'
# 2. Add user entry below following the same format
# 3. Authelia will auto-reload this file

users:
  $ADMIN_USERNAME:
    disabled: false
    displayname: "Wazuh Administrator"
    password: "$HASHED_PASSWORD"
    email: $ADMIN_EMAIL
    groups:
      - admins
      - wazuh
EOF

log "Admin user '$ADMIN_USERNAME' created"

# Clear sensitive variables from memory
unset ADMIN_PASSWORD ADMIN_PASSWORD_CONFIRM HASHED_PASSWORD JWT_SECRET SESSION_SECRET STORAGE_ENCRYPTION_KEY

# ============================================
# Step 7: Create Docker Compose File
# ============================================
log "Step 7: Creating Docker Compose configuration..."

cat > "$AUTHELIA_DIR/docker-compose.yml" <<EOF
---
services:
  authelia:
    image: authelia/authelia:latest
    container_name: authelia
    restart: unless-stopped
    volumes:
      - ./config:/config:rw
      - ./data:/data:rw
    environment:
      - TZ=UTC
    ports:
      - "127.0.0.1:9091:9091"
    healthcheck:
      test: ["CMD-SHELL", "curl -f http://localhost:9091/api/health || wget --no-verbose --tries=1 --spider http://localhost:9091/api/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s
EOF

log "Docker Compose configuration created"

# ============================================
# Step 8: Verify SSL Certificate
# ============================================
log "Step 8: Verifying SSL certificate..."

# Ensure webroot directory exists (should be created by configure-ssl.sh)
if [ ! -d "/var/www/certbot" ]; then
    sudo mkdir -p /var/www/certbot
    log "Created webroot directory for certbot"
fi

# With path-based auth, no additional subdomain certificate is needed
log "Using path-based auth ($AUTH_PATH) - no additional SSL certificate required"

# ============================================
# Step 9: Reconfigure Wazuh Dashboard to listen on port 5601
# ============================================
log "Step 9: Reconfiguring Wazuh Dashboard to listen on port 5601..."

DASHBOARD_CONFIG="/etc/wazuh-dashboard/opensearch_dashboards.yml"

# Backup dashboard config if not already backed up for Authelia
if [ ! -f "${DASHBOARD_CONFIG}.pre-authelia.backup" ]; then
    sudo cp "$DASHBOARD_CONFIG" "${DASHBOARD_CONFIG}.pre-authelia.backup"
    log "Backed up Wazuh Dashboard configuration"
fi

# Check current port configuration
CURRENT_PORT=$(sudo grep -E "^server\.port:" "$DASHBOARD_CONFIG" 2>/dev/null | awk '{print $2}')
if [ -z "$CURRENT_PORT" ]; then
    CURRENT_PORT="443"
fi
log "Current Wazuh Dashboard port: $CURRENT_PORT"

if [ "$CURRENT_PORT" != "5601" ]; then
    log "Changing Wazuh Dashboard port from $CURRENT_PORT to 5601..."

    # Update or add server.port setting
    if sudo grep -q "^server\.port:" "$DASHBOARD_CONFIG"; then
        sudo sed -i 's/^server\.port:.*/server.port: 5601/' "$DASHBOARD_CONFIG"
    else
        # Add server.port if not present
        echo "server.port: 5601" | sudo tee -a "$DASHBOARD_CONFIG" > /dev/null
    fi

    # Update server.host to listen on localhost only (Nginx will handle external traffic)
    if sudo grep -q "^server\.host:" "$DASHBOARD_CONFIG"; then
        sudo sed -i 's/^server\.host:.*/server.host: "127.0.0.1"/' "$DASHBOARD_CONFIG"
    else
        echo 'server.host: "127.0.0.1"' | sudo tee -a "$DASHBOARD_CONFIG" > /dev/null
    fi

    log "Restarting Wazuh Dashboard on port 5601..."
    sudo systemctl restart wazuh-dashboard

    # Wait for dashboard to be ready (it can take up to 60 seconds)
    log "Waiting for Wazuh Dashboard to be ready..."
    for i in {1..30}; do
        # The -k flag is required because Wazuh Dashboard uses a self-signed certificate on localhost
        if curl -s -k -o /dev/null -w "%{http_code}" https://localhost:5601 2>/dev/null | grep -q "200\|302\|401"; then
            log "Wazuh Dashboard now listening on port 5601"
            break
        fi
        sleep 2
        if [ $i -eq 30 ]; then
            error "Wazuh Dashboard did not become accessible on port 5601 after 60 seconds. Please check the dashboard logs (sudo journalctl -u wazuh-dashboard), verify the service status (sudo systemctl status wazuh-dashboard), and resolve any issues before re-running this script."
        fi
    done
else
    log "Wazuh Dashboard already configured on port 5601"
fi

# ============================================
# Step 10: Backup and Update Nginx Configuration
# ============================================
log "Step 10: Configuring Nginx for forward authentication..."

# Backup existing configuration (created by configure-ssl.sh)
if [ -f "/etc/nginx/sites-available/wazuh-redirect" ]; then
    if [ ! -f "/etc/nginx/sites-available/wazuh-redirect.pre-authelia.backup" ]; then
        sudo cp /etc/nginx/sites-available/wazuh-redirect /etc/nginx/sites-available/wazuh-redirect.pre-authelia.backup
        log "Backed up existing Nginx configuration"
    else
        log "Nginx backup already exists, skipping backup"
    fi
else
    error "Nginx configuration /etc/nginx/sites-available/wazuh-redirect not found. Run ./configure-ssl.sh first."
fi

# Create new Nginx configuration with Authelia (path-based)
sudo tee /etc/nginx/sites-available/wazuh-authelia > /dev/null <<EOF
# Authelia + Wazuh Dashboard Configuration (Path-based Auth)
# Generated by configure-authelia.sh
# Auth portal: $AUTH_URL

# Authelia upstream
upstream authelia {
    server 127.0.0.1:9091;
    keepalive 10;
}

# Wazuh Dashboard upstream
upstream wazuh-dashboard {
    server 127.0.0.1:5601;
    keepalive 10;
}

# HTTP to HTTPS redirect
server {
    listen 80;
    server_name $DOMAIN_NAME;

    # ACME challenge for Let's Encrypt
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

# Wazuh Dashboard with Authelia Protection (path-based)
server {
    listen 443 ssl http2;
    server_name $DOMAIN_NAME;

    ssl_certificate /etc/letsencrypt/live/$CERT_DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$CERT_DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Redirect /auth to /auth/ for consistency
    location = /auth {
        return 301 \$scheme://\$host/auth/;
    }

    # Authelia Portal at /auth/ path
    location /auth/ {
        proxy_pass http://authelia/auth/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$http_host;
        proxy_set_header X-Forwarded-URI \$request_uri;

        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";

        proxy_buffers 8 32k;
        proxy_buffer_size 64k;
    }

    # Authelia internal endpoint for auth request
    # Note: Do NOT include /auth path here - Authelia handles both / and /auth paths
    location /internal/authelia/authz {
        internal;

        proxy_pass http://authelia/api/authz/auth-request;

        proxy_set_header X-Original-Method \$request_method;
        proxy_set_header X-Original-URL \$scheme://\$http_host\$request_uri;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$http_host;
        proxy_set_header X-Forwarded-URI \$request_uri;
        proxy_set_header Content-Length "";
        proxy_set_header Connection "";

        proxy_pass_request_body off;
    }

    # Protected Wazuh Dashboard
    location / {
        # Forward authentication to Authelia
        auth_request /internal/authelia/authz;

        # Set variables from Authelia response
        auth_request_set \$user \$upstream_http_remote_user;
        auth_request_set \$groups \$upstream_http_remote_groups;
        auth_request_set \$name \$upstream_http_remote_name;
        auth_request_set \$email \$upstream_http_remote_email;

        # Handle authentication redirects (redirect to /auth path)
        auth_request_set \$redirection_url \$upstream_http_location;
        error_page 401 =302 $AUTH_URL?rd=\$scheme://\$http_host\$request_uri;

        # Proxy to Wazuh Dashboard
        proxy_pass https://wazuh-dashboard;
        proxy_ssl_verify off;

        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # Pass authenticated user info
        proxy_set_header Remote-User \$user;
        proxy_set_header Remote-Groups \$groups;
        proxy_set_header Remote-Name \$name;
        proxy_set_header Remote-Email \$email;

        # WebSocket support for dashboard
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";

        # Buffers for dashboard
        proxy_buffers 8 32k;
        proxy_buffer_size 64k;
        proxy_read_timeout 300;
        proxy_send_timeout 300;
    }
}
EOF

log "Nginx configuration created"

# ============================================
# Step 11: Start Authelia Container
# ============================================
log "Step 11: Starting Authelia container..."

cd "$AUTHELIA_DIR"
sudo docker compose up -d

# Wait for Authelia to be healthy
log "Waiting for Authelia to start..."
for i in {1..30}; do
    # Authelia responds on both / and /auth paths when subpath is configured
    if curl -s http://localhost:9091/api/health 2>/dev/null | grep -q "OK"; then
        log "Authelia is healthy"
        break
    fi
    sleep 2
    if [ $i -eq 30 ]; then
        warn "Authelia health check timed out, but continuing..."
    fi
done

# ============================================
# Step 12: Enable New Nginx Configuration
# ============================================
log "Step 12: Enabling new Nginx configuration..."

# Remove old config from sites-enabled
sudo rm -f /etc/nginx/sites-enabled/wazuh-redirect

# Enable new config
sudo ln -sf /etc/nginx/sites-available/wazuh-authelia /etc/nginx/sites-enabled/

# Test and reload
if sudo nginx -t; then
    sudo systemctl reload nginx
    log "Nginx configuration updated successfully"
else
    error "Nginx configuration test failed. Check the configuration."
fi

# Disable the trap since we succeeded
trap - ERR

# ============================================
# Display Summary
# ============================================
log "Authelia 2FA configuration completed successfully!"
echo
echo "============================================="
echo "      AUTHELIA 2FA CONFIGURATION SUMMARY"
echo "============================================="
echo ""
echo "Wazuh Dashboard: https://$DOMAIN_NAME"
echo "Authelia Portal: $AUTH_URL"
echo ""
echo "Initial Admin User: $ADMIN_USERNAME"
echo "Admin Email: $ADMIN_EMAIL"
echo ""
echo "Configuration Files:"
echo "  - Main Config: $AUTHELIA_DIR/config/configuration.yml"
echo "  - Users Database: $AUTHELIA_DIR/config/users_database.yml"
echo "  - Notifications: $AUTHELIA_DIR/config/notification.txt"
echo ""
echo "Docker Container:"
echo "  - Name: authelia"
echo "  - Restart: sudo docker restart authelia"
echo "  - Logs: sudo docker logs -f authelia"
echo "  - Status: sudo docker ps | grep authelia"
echo ""
echo "============================================="
echo "FIRST LOGIN INSTRUCTIONS:"
echo "1. Navigate to https://$DOMAIN_NAME"
echo "2. You will be redirected to $AUTH_URL"
echo "3. Login with: $ADMIN_USERNAME and your password"
echo "4. You will be prompted to register TOTP"
echo "5. Scan the QR code with Google Authenticator or Authy"
echo "6. Enter the 6-digit code to complete setup"
echo "7. You will be redirected to the Wazuh Dashboard"
echo ""
echo "Wazuh Agent Ports (unchanged - no 2FA required):"
echo "  - 1514 (UDP/TCP): Agent communication"
echo "  - 1515 (TCP): Agent enrollment"
echo "  - 55000 (TCP): API access"
echo "============================================="
echo ""
echo "ADDING NEW USERS:"
echo "1. Generate password hash:"
echo "   sudo docker run --rm authelia/authelia:latest authelia crypto hash generate argon2 --password 'newpassword'"
echo ""
echo "2. Edit users database:"
echo "   sudo nano $AUTHELIA_DIR/config/users_database.yml"
echo ""
echo "3. Add new user entry following the existing format"
echo "   (Authelia auto-reloads the file)"
echo "============================================="

warn "Check $AUTHELIA_DIR/config/notification.txt for password reset links"
warn "For production, configure SMTP in $AUTHELIA_DIR/config/configuration.yml"

log "Authelia 2FA configuration completed successfully!"
log "Access your Wazuh dashboard at: https://$DOMAIN_NAME"
