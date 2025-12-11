#!/bin/bash

# Wazuh Cleanup Script
# This script completely removes all Wazuh components and configurations

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
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   error "This script should not be run as root for security reasons. Please run as a regular user with sudo privileges."
   exit 1
fi

# Confirmation prompt
echo -e "${YELLOW}=============================================${NC}"
echo -e "${YELLOW}           WAZUH CLEANUP SCRIPT${NC}"
echo -e "${YELLOW}=============================================${NC}"
echo
echo "This script will completely remove:"
echo "  ✗ All Wazuh services (indexer, manager, dashboard)"
echo "  ✗ All Wazuh configuration files"
echo "  ✗ All Wazuh data and logs"
echo "  ✗ Authelia 2FA (if configured)"
echo "  ✗ Nginx configuration for Wazuh"
echo "  ✗ Wazuh systemd services"
echo "  ✗ Wazuh installation files"
echo
echo -e "${RED}WARNING: This action cannot be undone!${NC}"
echo -e "${YELLOW}SSL certificates and Docker will be preserved.${NC}"
echo
read -p "Are you sure you want to continue? (y/N): " confirm

if [[ ! $confirm =~ ^[Yy]$ ]]; then
    log "Cleanup cancelled by user."
    exit 0
fi

log "Starting Wazuh cleanup process..."

# ============================================
# Stop and Remove Authelia (if configured)
# ============================================
log "Checking for Authelia installation..."
if [ -d "/opt/authelia" ]; then
    log "Authelia found, stopping and removing..."

    # Stop Authelia container
    if command -v docker &> /dev/null; then
        # Use sudo for docker commands in case user isn't in docker group
        cd /opt/authelia 2>/dev/null && sudo docker compose down --remove-orphans 2>/dev/null || warn "Could not stop Authelia container"

        # Remove Authelia image (optional)
        if sudo docker images 2>/dev/null | grep -q authelia; then
            read -p "Remove Authelia Docker image? (y/N): " remove_image
            if [[ $remove_image =~ ^[Yy]$ ]]; then
                sudo docker rmi authelia/authelia:latest 2>/dev/null || warn "Could not remove Authelia image"
                log "Removed Authelia Docker image"
            fi
        fi
    else
        warn "Docker not installed, skipping container cleanup"
    fi

    # Remove Authelia directory
    sudo rm -rf /opt/authelia
    log "Removed Authelia configuration directory"

    # Remove Authelia Nginx configuration
    if [ -L "/etc/nginx/sites-enabled/wazuh-authelia" ]; then
        sudo rm -f /etc/nginx/sites-enabled/wazuh-authelia
        log "Removed Authelia Nginx symlink"
    fi

    if [ -f "/etc/nginx/sites-available/wazuh-authelia" ]; then
        sudo rm -f /etc/nginx/sites-available/wazuh-authelia
        log "Removed Authelia Nginx configuration"
    fi

    # Restore pre-Authelia Nginx config if it exists (so nginx can still work during cleanup)
    if [ -f "/etc/nginx/sites-available/wazuh-redirect.pre-authelia.backup" ]; then
        # Restore the original wazuh-redirect config
        sudo cp /etc/nginx/sites-available/wazuh-redirect.pre-authelia.backup /etc/nginx/sites-available/wazuh-redirect
        sudo ln -sf /etc/nginx/sites-available/wazuh-redirect /etc/nginx/sites-enabled/wazuh-redirect
        sudo rm -f /etc/nginx/sites-available/wazuh-redirect.pre-authelia.backup
        log "Restored original Nginx configuration from backup"
    fi

    # Restore Wazuh Dashboard configuration (port 443, external access)
    DASHBOARD_CONFIG="/etc/wazuh-dashboard/opensearch_dashboards.yml"
    if [ -f "${DASHBOARD_CONFIG}.pre-authelia.backup" ]; then
        log "Restoring Wazuh Dashboard configuration..."
        sudo cp "${DASHBOARD_CONFIG}.pre-authelia.backup" "$DASHBOARD_CONFIG"
        sudo rm -f "${DASHBOARD_CONFIG}.pre-authelia.backup"
        log "Restored Wazuh Dashboard to original configuration"
    fi
else
    log "Authelia not installed, skipping..."
fi

# ============================================
# Stop all Wazuh services
# ============================================
log "Stopping Wazuh services..."
sudo systemctl stop wazuh-indexer 2>/dev/null || warn "wazuh-indexer service not running"
sudo systemctl stop wazuh-manager 2>/dev/null || warn "wazuh-manager service not running"
sudo systemctl stop wazuh-dashboard 2>/dev/null || warn "wazuh-dashboard service not running"
sudo systemctl stop filebeat 2>/dev/null || warn "filebeat service not running"
sudo systemctl stop wazuh-agent 2>/dev/null || warn "wazuh-agent service not running"
sudo systemctl stop nginx 2>/dev/null || warn "nginx service not running"

# Disable services
log "Disabling Wazuh services..."
sudo systemctl disable wazuh-indexer 2>/dev/null || warn "wazuh-indexer service not installed"
sudo systemctl disable wazuh-manager 2>/dev/null || warn "wazuh-manager service not installed"
sudo systemctl disable wazuh-dashboard 2>/dev/null || warn "wazuh-dashboard service not installed"
sudo systemctl disable filebeat 2>/dev/null || warn "filebeat service not installed"
sudo systemctl disable wazuh-agent 2>/dev/null || warn "wazuh-agent service not installed"

# Remove Wazuh packages
log "Removing Wazuh packages..."
packages_to_remove=(
    "wazuh-indexer"
    "wazuh-manager" 
    "wazuh-dashboard"
    "filebeat"
    "wazuh-agent"
)

for package in "${packages_to_remove[@]}"; do
    if dpkg -l | grep -q "^ii.*$package"; then
        log "Removing package: $package"
        sudo apt-get remove --purge $package -y
    else
        warn "Package $package not installed"
    fi
done

# Clean up package dependencies
log "Cleaning up unused packages..."
sudo apt-get autoremove -y
sudo apt-get autoclean

# Remove configuration directories
log "Removing Wazuh configuration directories..."
directories_to_remove=(
    "/etc/wazuh-indexer"
    "/etc/wazuh-dashboard" 
    "/etc/filebeat"
    "/var/ossec"
    "/var/lib/wazuh-indexer"
    "/var/lib/filebeat"
    "/var/log/wazuh-indexer"
    "/var/log/wazuh-dashboard"
    "/var/log/filebeat"
    "/usr/share/wazuh-indexer"
    "/usr/share/wazuh-dashboard"
    "/usr/share/filebeat"
    "/tmp/wazuh-install-files"
    "/tmp/wazuh-install"
)

# Also check for installation files in current directory
if [ -f "wazuh-install-files.tar" ]; then
    log "Removing installation tar file"
    rm -f wazuh-install-files.tar
fi

if [ -f "wazuh-install.sh" ]; then
    log "Removing installation script"  
    rm -f wazuh-install.sh
fi

for dir in "${directories_to_remove[@]}"; do
    if [ -d "$dir" ]; then
        log "Removing directory: $dir"
        sudo rm -rf "$dir"
    else
        warn "Directory $dir not found"
    fi
done

# Remove Wazuh users
log "Removing Wazuh users..."
users_to_remove=(
    "wazuh-indexer"
    "wazuh-dashboard"
    "ossec"
    "wazuh"
)

for user in "${users_to_remove[@]}"; do
    if id "$user" &>/dev/null; then
        log "Removing user: $user"
        sudo userdel -r "$user" 2>/dev/null || warn "Could not remove user $user completely"
    else
        warn "User $user not found"
    fi
done

# Remove Wazuh groups
log "Removing Wazuh groups..."
groups_to_remove=(
    "wazuh-indexer"
    "wazuh-dashboard" 
    "ossec"
    "wazuh"
)

for group in "${groups_to_remove[@]}"; do
    if getent group "$group" &>/dev/null; then
        log "Removing group: $group"
        sudo groupdel "$group" 2>/dev/null || warn "Could not remove group $group"
    else
        warn "Group $group not found"
    fi
done

# Remove Nginx Wazuh configuration (only if SSL was configured)
log "Removing Nginx Wazuh configuration..."
if [ -f "/etc/nginx/sites-available/wazuh-redirect" ]; then
    sudo rm -f /etc/nginx/sites-available/wazuh-redirect
    log "Removed Nginx Wazuh redirect configuration"
fi

if [ -L "/etc/nginx/sites-enabled/wazuh-redirect" ]; then
    sudo rm -f /etc/nginx/sites-enabled/wazuh-redirect
    log "Removed Nginx Wazuh redirect symlink"
fi

# Also check for old wazuh config names
if [ -f "/etc/nginx/sites-available/wazuh" ]; then
    sudo rm -f /etc/nginx/sites-available/wazuh
    log "Removed Nginx Wazuh site configuration"
fi

if [ -L "/etc/nginx/sites-enabled/wazuh" ]; then
    sudo rm -f /etc/nginx/sites-enabled/wazuh
    log "Removed Nginx Wazuh site symlink"
fi

# Only handle Nginx if it was installed for Wazuh SSL configuration
if command -v nginx &> /dev/null; then
    # Restore default Nginx site if it was removed
    if [ ! -L "/etc/nginx/sites-enabled/default" ] && [ -f "/etc/nginx/sites-available/default" ]; then
        sudo ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default
        log "Restored default Nginx site"
    fi

    # Test and restart Nginx
    log "Testing and restarting Nginx..."
    if sudo nginx -t 2>/dev/null; then
        sudo systemctl restart nginx
        log "Nginx restarted successfully"
    else
        warn "Nginx configuration test failed, you may need to fix manually"
    fi
else
    log "Nginx not installed, skipping configuration cleanup"
fi

# Remove systemd service files
log "Removing Wazuh systemd service files..."
service_files=(
    "/usr/lib/systemd/system/wazuh-indexer.service"
    "/usr/lib/systemd/system/wazuh-manager.service"
    "/usr/lib/systemd/system/wazuh-dashboard.service"
    "/usr/lib/systemd/system/filebeat.service"
    "/usr/lib/systemd/system/wazuh-agent.service"
    "/etc/systemd/system/wazuh.service"
    "/etc/systemd/system/filebeat.service"
)

for service_file in "${service_files[@]}"; do
    if [ -f "$service_file" ]; then
        log "Removing service file: $service_file"
        sudo rm -f "$service_file"
    fi
done

# Reload systemd daemon
sudo systemctl daemon-reload

# Remove certificate renewal hooks for Wazuh (if SSL was configured)
log "Removing Wazuh certificate renewal hooks..."
# Check for the hook created by configure-ssl.sh
if [ -f "/etc/letsencrypt/renewal-hooks/post/restart-wazuh-dashboard.sh" ]; then
    sudo rm -f /etc/letsencrypt/renewal-hooks/post/restart-wazuh-dashboard.sh
    log "Removed Wazuh dashboard certificate renewal hook"
fi

# Also check for alternate naming conventions
if [ -f "/etc/letsencrypt/renewal-hooks/post/wazuh-restart.sh" ]; then
    sudo rm -f /etc/letsencrypt/renewal-hooks/post/wazuh-restart.sh
    log "Removed Wazuh certificate renewal hook"
fi

if [ -f "/etc/letsencrypt/renewal-hooks/pre/wazuh-stop.sh" ]; then
    sudo rm -f /etc/letsencrypt/renewal-hooks/pre/wazuh-stop.sh
    log "Removed Wazuh pre-renewal hook"
fi

# Remove cron jobs created by configure-ssl.sh
log "Removing Wazuh cron jobs..."
if [ -f "/etc/cron.d/certbot-renew" ]; then
    # This cron job was created by configure-ssl.sh for Wazuh certificate renewal
    sudo rm -f /etc/cron.d/certbot-renew
    log "Removed certbot renewal cron job"
fi

# Remove Wazuh repository (optional)
log "Checking for Wazuh repository..."
if [ -f "/etc/apt/sources.list.d/wazuh.list" ]; then
    read -p "Remove Wazuh APT repository? (y/N): " remove_repo
    if [[ $remove_repo =~ ^[Yy]$ ]]; then
        sudo rm -f /etc/apt/sources.list.d/wazuh.list
        sudo apt-get update
        log "Removed Wazuh repository"
    fi
fi

# Clean up any remaining Wazuh processes
log "Checking for remaining Wazuh processes..."
if pgrep -f "wazuh\|ossec" > /dev/null; then
    warn "Found running Wazuh processes, attempting to kill..."
    sudo pkill -f "wazuh\|ossec" || warn "Some processes may still be running"
fi

# Final cleanup
log "Performing final cleanup..."
sudo updatedb 2>/dev/null || warn "Could not update locate database"

# Display cleanup summary
log "Wazuh cleanup completed successfully!"
echo
echo "============================================="
echo "           CLEANUP SUMMARY"
echo "============================================="
echo "✅ Wazuh services stopped and disabled"
echo "✅ Wazuh packages removed"
echo "✅ Configuration directories cleaned"
echo "✅ User accounts removed"
echo "✅ Authelia 2FA removed (if was configured)"
echo "✅ Nginx configuration cleaned"
echo "✅ Systemd services removed"
echo "✅ Certificate hooks removed"
echo ""
echo "Preserved:"
echo "🔒 SSL certificates (/etc/letsencrypt/)"
echo "🔒 Docker installation"
echo "🔒 Nginx service (running)"
echo "🔒 System packages (curl, certbot, etc.)"
echo ""
echo "============================================="
echo "Next Steps:"
echo "1. Your system is now clean of Wazuh components"
echo "2. You can run the installation script again"
echo "3. SSL certificates are preserved for reuse"
echo "============================================="

log "Cleanup completed successfully!"