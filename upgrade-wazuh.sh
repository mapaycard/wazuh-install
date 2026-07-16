#!/bin/bash

# Wazuh Upgrade Script
# Upgrades an all-in-one Wazuh installation (indexer, manager, dashboard) to the
# latest 4.x version available in the official Wazuh apt repository.
# Following official documentation: https://documentation.wazuh.com/current/upgrade-guide/upgrading-central-components.html
#
# Prerequisites: Wazuh installed via install-wazuh.sh (all-in-one deployment)
# IMPORTANT: Take a VM snapshot before running this script. Wazuh downgrades are NOT supported.

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

# Cleanup on failure: re-disable the Wazuh repo so a broken run doesn't leave
# the system exposed to accidental upgrades via routine apt upgrade
cleanup_on_error() {
    warn "An error occurred during the upgrade."
    if [ -f /etc/apt/sources.list.d/wazuh.list ]; then
        sudo sed -i 's/^deb/#deb/' /etc/apt/sources.list.d/wazuh.list 2>/dev/null || true
    fi
    warn "The Wazuh apt repository has been disabled again."
    # Best-effort: bring back services the script may have stopped, so a failed
    # run doesn't leave the stack more broken than the failure itself
    sudo systemctl start wazuh-indexer filebeat wazuh-dashboard 2>/dev/null || true
    warn "The system may be in a partially upgraded state. Check service status with:"
    warn "  systemctl status wazuh-indexer wazuh-manager wazuh-dashboard filebeat"
    error "Upgrade failed. If services are broken, restore your VM snapshot."
}
trap cleanup_on_error ERR

# Check if running on Debian/Ubuntu
if ! command -v apt-get &> /dev/null; then
    error "This script is designed for Debian/Ubuntu systems only."
fi

# Optional parameter: pin a specific target version (e.g. 4.14.6)
TARGET_VERSION="${1:-}"

# ============================================
# Step 1: Pre-flight Checks
# ============================================
log "Step 1: Running pre-flight checks..."

for pkg in wazuh-indexer wazuh-manager wazuh-dashboard filebeat; do
    if ! dpkg -s "$pkg" &> /dev/null; then
        error "Package $pkg is not installed. This script only supports all-in-one deployments created by install-wazuh.sh."
    fi
done

CURRENT_VERSION=$(dpkg-query -W -f='${Version}' wazuh-manager | cut -d'-' -f1)
log "Current Wazuh version: $CURRENT_VERSION"

for service in wazuh-indexer wazuh-manager wazuh-dashboard filebeat; do
    if ! sudo systemctl is-active --quiet "$service"; then
        error "Service $service is not running. Fix it before upgrading (systemctl status $service)."
    fi
done
log "All Wazuh services are running"

# Require at least 5 GB free disk space for packages and reindexing headroom
FREE_KB=$(df --output=avail / | tail -1 | tr -d ' ')
if [ "$FREE_KB" -lt 5242880 ]; then
    error "Less than 5 GB free disk space on /. Free up space before upgrading."
fi

# ============================================
# Step 2: Enable Wazuh Repository
# ============================================
log "Step 2: Enabling Wazuh apt repository..."

if [ -f /etc/apt/sources.list.d/wazuh.list ]; then
    # install-wazuh.sh / the official installer comments the repo out after install
    sudo sed -i 's/^#deb/deb/' /etc/apt/sources.list.d/wazuh.list
else
    info "Wazuh repository not found, adding it..."
    # Verify the downloaded key against the published Wazuh signing key fingerprint
    # before trusting it, so a compromised download cannot taint the apt trust chain
    WAZUH_GPG_FINGERPRINT="0DCFCA5547B19D2A6099506096B3EE5F29111145"
    KEY_FILE=$(mktemp)
    curl -fsS https://packages.wazuh.com/key/GPG-KEY-WAZUH -o "$KEY_FILE"
    ACTUAL_FPR=$(gpg --show-keys --with-colons "$KEY_FILE" 2>/dev/null | awk -F: '/^fpr:/ {print $10; exit}')
    if [ "$ACTUAL_FPR" != "$WAZUH_GPG_FINGERPRINT" ]; then
        rm -f "$KEY_FILE"
        error "Wazuh GPG key fingerprint mismatch (got: ${ACTUAL_FPR:-none}, expected: $WAZUH_GPG_FINGERPRINT). Possible tampering - aborting."
    fi
    sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import "$KEY_FILE"
    rm -f "$KEY_FILE"
    sudo chmod 644 /usr/share/keyrings/wazuh.gpg
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list > /dev/null
fi

sudo apt-get update -qq

# Determine target version from the repo if not pinned
if [ -z "$TARGET_VERSION" ]; then
    TARGET_VERSION=$(apt-cache policy wazuh-manager | awk '/Candidate:/ {print $2}' | cut -d'-' -f1)
fi

if [ -z "$TARGET_VERSION" ] || [ "$TARGET_VERSION" = "(none)" ]; then
    error "Could not determine target version from the Wazuh repository."
fi

if [ "$TARGET_VERSION" = "$CURRENT_VERSION" ]; then
    sudo sed -i 's/^deb/#deb/' /etc/apt/sources.list.d/wazuh.list
    log "Already on the latest version ($CURRENT_VERSION). Nothing to do."
    trap - ERR
    exit 0
fi

# Refuse downgrades explicitly (Wazuh does not support them)
if [ "$(printf '%s\n%s\n' "$CURRENT_VERSION" "$TARGET_VERSION" | sort -V | head -1)" != "$CURRENT_VERSION" ]; then
    sudo sed -i 's/^deb/#deb/' /etc/apt/sources.list.d/wazuh.list
    error "Target version $TARGET_VERSION is older than the installed version $CURRENT_VERSION. Wazuh downgrades are not supported - restore a snapshot instead."
fi

# Resolve the full apt version string (e.g. 4.14.6-1) for pinned installs
APT_VERSION=$(apt-cache madison wazuh-manager | awk -v v="$TARGET_VERSION" '$3 ~ "^"v"-" {print $3; exit}')
if [ -z "$APT_VERSION" ]; then
    error "Version $TARGET_VERSION not found in the Wazuh repository. Available versions: $(apt-cache madison wazuh-manager | awk '{print $3}' | tr '\n' ' ')"
fi

log "Upgrade plan: $CURRENT_VERSION -> $TARGET_VERSION"
echo ""
warn "Wazuh downgrades are NOT supported. Make sure you have a VM snapshot before continuing."
warn "The dashboard will be unavailable for a few minutes. Agents will buffer events (no data loss)."
echo ""
read -p "Continue with the upgrade? (yes/no): " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
    sudo sed -i 's/^deb/#deb/' /etc/apt/sources.list.d/wazuh.list
    log "Upgrade cancelled. Repository disabled again."
    trap - ERR
    exit 0
fi

indexer_api() {
    # indexer_api <METHOD> <PATH> [JSON_BODY]
    # Credentials are passed via a curl config file on a file descriptor (process
    # substitution) instead of argv, so the password never shows up in `ps` output.
    # --fail makes HTTP errors (401, 5xx) return a non-zero exit code so callers
    # can actually detect failures.
    local method="$1" path="$2" body="${3:-}"
    if [ -n "$body" ]; then
        curl -skf --config <(printf 'user = "admin:%s"\n' "$INDEXER_PASS") -X "$method" "https://localhost:9200$path" -H 'Content-Type: application/json' -d "$body"
    else
        curl -skf --config <(printf 'user = "admin:%s"\n' "$INDEXER_PASS") -X "$method" "https://localhost:9200$path"
    fi
}

# Optional indexer admin credentials for cluster preparation steps.
# On a single-node deployment these steps are recommended but not strictly required.
# Validated immediately - before any services are stopped - so a typo is caught
# while the system is still untouched.
echo ""
info "The indexer admin password is used to prepare the cluster (disable shard allocation, flush)."
info "It is in the wazuh-passwords.txt file from the original installation. Leave empty to skip."
while true; do
    read -s -p "Indexer admin password (or press Enter to skip): " INDEXER_PASS
    echo ""
    if [ -z "$INDEXER_PASS" ]; then
        break
    fi
    if indexer_api GET "/_cluster/health" > /dev/null 2>&1; then
        log "Indexer credentials verified"
        break
    fi
    warn "Could not authenticate against the indexer with that password. Try again or press Enter to skip."
done

# ============================================
# Step 3: Backup Configuration Files
# ============================================
log "Step 3: Backing up configuration files..."

BACKUP_DIR="/root/wazuh-upgrade-backup-$(date +%Y%m%d-%H%M%S)"
sudo mkdir -p "$BACKUP_DIR"
sudo cp /var/ossec/etc/ossec.conf "$BACKUP_DIR/" 2>/dev/null || true
sudo cp /etc/wazuh-dashboard/opensearch_dashboards.yml "$BACKUP_DIR/" 2>/dev/null || true
sudo cp /etc/wazuh-indexer/opensearch.yml "$BACKUP_DIR/" 2>/dev/null || true
sudo cp /etc/wazuh-indexer/jvm.options "$BACKUP_DIR/" 2>/dev/null || true
sudo cp /etc/filebeat/filebeat.yml "$BACKUP_DIR/" 2>/dev/null || true
sudo cp -r /usr/share/wazuh-dashboard/data/wazuh/config "$BACKUP_DIR/wazuh-dashboard-app-config" 2>/dev/null || true
log "Configuration backed up to $BACKUP_DIR"

# ============================================
# Step 4: Prepare and Upgrade the Indexer
# ============================================
log "Step 4: Upgrading Wazuh indexer..."

if [ -n "$INDEXER_PASS" ]; then
    info "Disabling shard replica allocation and flushing indices..."
    indexer_api PUT "/_cluster/settings" '{"persistent":{"cluster.routing.allocation.enable":"primaries"}}' > /dev/null || warn "Could not disable shard allocation (continuing)"
    indexer_api POST "/_flush" > /dev/null || warn "Flush request failed (continuing)"
else
    warn "Skipping cluster preparation (no indexer password provided)"
fi

info "Stopping filebeat and dashboard during indexer upgrade..."
sudo systemctl stop filebeat wazuh-dashboard

# --force-confdef/--force-confold: keep locally modified config files without prompting.
# This preserves the SSL and Authelia customizations made by the other scripts.
APT_OPTS=(-y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold")

sudo DEBIAN_FRONTEND=noninteractive apt-get install "${APT_OPTS[@]}" "wazuh-indexer=$APT_VERSION"
sudo systemctl daemon-reload
sudo systemctl restart wazuh-indexer

info "Waiting for the indexer to come back up..."
for i in {1..60}; do
    HTTP_CODE=$(curl -sk -o /dev/null -w '%{http_code}' https://localhost:9200 || true)
    # 200 (authenticated) or 401 (up, credentials required) both mean the indexer is serving
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "401" ]; then
        log "Indexer is up"
        break
    fi
    sleep 5
    if [ $i -eq 60 ]; then
        error "Indexer did not come back up after 5 minutes. Check: journalctl -u wazuh-indexer"
    fi
done

if [ -n "$INDEXER_PASS" ]; then
    info "Re-enabling shard allocation..."
    indexer_api PUT "/_cluster/settings" '{"persistent":{"cluster.routing.allocation.enable":"all"}}' > /dev/null || warn "Could not re-enable shard allocation - run manually: PUT /_cluster/settings {\"persistent\":{\"cluster.routing.allocation.enable\":\"all\"}}"
    info "Cluster health: $(indexer_api GET "/_cluster/health" | grep -o '"status":"[a-z]*"' || echo 'unknown')"
fi

# ============================================
# Step 5: Upgrade the Manager
# ============================================
log "Step 5: Upgrading Wazuh manager..."

sudo DEBIAN_FRONTEND=noninteractive apt-get install "${APT_OPTS[@]}" "wazuh-manager=$APT_VERSION"

if ! sudo systemctl is-active --quiet wazuh-manager; then
    sudo systemctl restart wazuh-manager
fi
log "Manager upgraded: $(sudo /var/ossec/bin/wazuh-control info | grep WAZUH_VERSION)"

# ============================================
# Step 6: Update Filebeat Module and Template
# ============================================
log "Step 6: Updating Filebeat Wazuh module and index template..."

# Download to a temp file with -f (fail on HTTP errors) instead of piping straight
# into tar, so an error page or truncated download is never extracted into the module
# directory. Note: Wazuh publishes no checksum/signature for this artifact; TLS to
# packages.wazuh.com is the same trust anchor used for the apt repository definition.
FILEBEAT_MODULE=$(mktemp)
curl -fsSL -o "$FILEBEAT_MODULE" https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.4.tar.gz || { rm -f "$FILEBEAT_MODULE"; error "Failed to download the Filebeat Wazuh module."; }
sudo tar -xzf "$FILEBEAT_MODULE" -C /usr/share/filebeat/module
rm -f "$FILEBEAT_MODULE"

# Fetch the version-matched index template into a temp file first for the same reason:
# a failed download must not clobber the existing working template
TEMPLATE_FILE=$(mktemp)
curl -fsS -o "$TEMPLATE_FILE" "https://raw.githubusercontent.com/wazuh/wazuh/v$TARGET_VERSION/extensions/elasticsearch/7.x/wazuh-template.json" || { rm -f "$TEMPLATE_FILE"; error "Failed to download the Wazuh index template for v$TARGET_VERSION."; }
sudo cp "$TEMPLATE_FILE" /etc/filebeat/wazuh-template.json
rm -f "$TEMPLATE_FILE"
sudo chmod go+r /etc/filebeat/wazuh-template.json

sudo systemctl start filebeat

if sudo filebeat test output | grep -q "talk to server... OK"; then
    log "Filebeat is connected to the indexer"
else
    warn "Filebeat output test did not report OK. Check: filebeat test output"
fi

# ============================================
# Step 7: Upgrade the Dashboard
# ============================================
log "Step 7: Upgrading Wazuh dashboard..."

sudo DEBIAN_FRONTEND=noninteractive apt-get install "${APT_OPTS[@]}" "wazuh-dashboard=$APT_VERSION"
sudo systemctl restart wazuh-dashboard

info "Waiting for the dashboard to come back up..."
for i in {1..60}; do
    HTTP_CODE=$(curl -sk -o /dev/null -w '%{http_code}' https://localhost:5601/status || true)
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "401" ]; then
        log "Dashboard is up"
        break
    fi
    sleep 5
    if [ $i -eq 60 ]; then
        error "Dashboard did not come back up after 5 minutes. Check: journalctl -u wazuh-dashboard"
    fi
done

# ============================================
# Step 8: Disable Wazuh Repository
# ============================================
log "Step 8: Disabling Wazuh apt repository (prevents accidental upgrades)..."
sudo sed -i 's/^deb/#deb/' /etc/apt/sources.list.d/wazuh.list

# ============================================
# Step 9: Final Verification
# ============================================
log "Step 9: Verifying the upgrade..."

FAILED=0
for service in wazuh-indexer wazuh-manager wazuh-dashboard filebeat; do
    if sudo systemctl is-active --quiet "$service"; then
        log "$service is running"
    else
        warn "$service is NOT running - check: journalctl -u $service"
        FAILED=1
    fi
done

NEW_VERSION=$(dpkg-query -W -f='${Version}' wazuh-manager | cut -d'-' -f1)

# Disable the trap since we reached the end
trap - ERR

echo ""
log "=============================================="
log "Wazuh upgrade completed: $CURRENT_VERSION -> $NEW_VERSION"
log "=============================================="
echo ""
info "Installed package versions:"
dpkg -l | grep -E 'wazuh|filebeat' | awk '{print "  " $2 " " $3}'
echo ""
info "Configuration backups: $BACKUP_DIR"
info "Next steps:"
info "  1. Log into the dashboard and verify the version in the About page"
info "  2. Check that all agents reconnected (Agents management)"
info "  3. Upgrade agents from the dashboard (agents must not be newer than the manager)"

if [ $FAILED -eq 1 ]; then
    warn "One or more services are not running. Investigate before considering the upgrade complete."
    exit 1
fi
