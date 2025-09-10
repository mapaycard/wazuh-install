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
echo "  ✗ Nginx configuration for Wazuh"
echo "  ✗ Wazuh systemd services"
echo "  ✗ Wazuh installation files"
echo
echo -e "${RED}WARNING: This action cannot be undone!${NC}"
echo -e "${YELLOW}SSL certificates will be preserved.${NC}"
echo
read -p "Are you sure you want to continue? (y/N): " confirm

if [[ ! $confirm =~ ^[Yy]$ ]]; then
    log "Cleanup cancelled by user."
    exit 0
fi

log "Starting Wazuh cleanup process..."

# Stop all Wazuh services
log "Stopping Wazuh services..."
sudo systemctl stop wazuh-indexer 2>/dev/null || warn "wazuh-indexer service not running"
sudo systemctl stop wazuh-manager 2>/dev/null || warn "wazuh-manager service not running"
sudo systemctl stop wazuh-dashboard 2>/dev/null || warn "wazuh-dashboard service not running"
sudo systemctl stop nginx 2>/dev/null || warn "nginx service not running"

# Disable services
log "Disabling Wazuh services..."
sudo systemctl disable wazuh-indexer 2>/dev/null || warn "wazuh-indexer service not installed"
sudo systemctl disable wazuh-manager 2>/dev/null || warn "wazuh-manager service not installed"
sudo systemctl disable wazuh-dashboard 2>/dev/null || warn "wazuh-dashboard service not installed"

# Remove Wazuh packages
log "Removing Wazuh packages..."
packages_to_remove=(
    "wazuh-indexer"
    "wazuh-manager" 
    "wazuh-dashboard"
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
    "/var/ossec"
    "/var/lib/wazuh-indexer"
    "/var/log/wazuh-indexer"
    "/var/log/wazuh-dashboard"
    "/usr/share/wazuh-indexer"
    "/usr/share/wazuh-dashboard"
    "/tmp/wazuh-install-files"
    "/tmp/wazuh-install"
)

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

# Remove Nginx Wazuh configuration
log "Removing Nginx Wazuh configuration..."
if [ -f "/etc/nginx/sites-available/wazuh" ]; then
    sudo rm -f /etc/nginx/sites-available/wazuh
    log "Removed Nginx Wazuh site configuration"
fi

if [ -L "/etc/nginx/sites-enabled/wazuh" ]; then
    sudo rm -f /etc/nginx/sites-enabled/wazuh
    log "Removed Nginx Wazuh site symlink"
fi

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

# Remove systemd service files
log "Removing Wazuh systemd service files..."
service_files=(
    "/usr/lib/systemd/system/wazuh-indexer.service"
    "/usr/lib/systemd/system/wazuh-manager.service"
    "/usr/lib/systemd/system/wazuh-dashboard.service"
    "/etc/systemd/system/wazuh.service"
)

for service_file in "${service_files[@]}"; do
    if [ -f "$service_file" ]; then
        log "Removing service file: $service_file"
        sudo rm -f "$service_file"
    fi
done

# Reload systemd daemon
sudo systemctl daemon-reload

# Remove certificate renewal hooks for Wazuh
log "Removing Wazuh certificate renewal hooks..."
if [ -f "/etc/letsencrypt/renewal-hooks/post/wazuh-restart.sh" ]; then
    sudo rm -f /etc/letsencrypt/renewal-hooks/post/wazuh-restart.sh
    log "Removed Wazuh certificate renewal hook"
fi

# Remove cron jobs
log "Removing Wazuh cron jobs..."
if [ -f "/etc/cron.d/certbot-renew" ]; then
    # Check if it's Wazuh-specific and remove only if needed
    if grep -q "wazuh" /etc/cron.d/certbot-renew 2>/dev/null; then
        sudo rm -f /etc/cron.d/certbot-renew
        log "Removed Wazuh-specific certbot cron job"
    fi
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
echo "✅ Nginx configuration cleaned"
echo "✅ Systemd services removed"
echo "✅ Certificate hooks removed"
echo ""
echo "Preserved:"
echo "🔒 SSL certificates (/etc/letsencrypt/)"
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