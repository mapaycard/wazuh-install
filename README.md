# Wazuh Installation Scripts

This repository contains automated installation scripts for deploying Wazuh on Debian-based VMs. The installation is split into two modular scripts for better flexibility and troubleshooting. Works on any cloud provider including Hetzner, DigitalOcean, GCP, AWS, Azure, and more.

## Overview

This repository provides two scripts for a complete Wazuh deployment:

### 1. `install-wazuh.sh` - Base Installation
- Native package installation using official Wazuh installation assistant
- All core Wazuh components (indexer, manager, dashboard)
- Basic firewall configuration
- HTTPS access on port 443
- Ready for immediate use

### 2. `configure-ssl.sh` - SSL Configuration
- SSL/TLS encryption using Let's Encrypt certificates
- HTTP to HTTPS redirect configuration
- Automatic certificate renewal with webroot method
- Production-ready HTTPS setup
- Direct dashboard access on port 443

## Prerequisites

### For Base Installation:
- Debian/Ubuntu-based VM (any cloud provider: Hetzner, DigitalOcean, AWS, GCP, Azure, etc.)
- Non-root user with sudo privileges
- Internet connectivity
- Ports 443, 1514, 1515, and 55000 accessible

### Additional for SSL Configuration:
- Domain name pointing to your VM's external IP
- Ports 80 and 443 accessible from the internet
- Valid email address for Let's Encrypt registration

## Server Requirements

**Minimum for up to 20 agents:**
- **CPU:** 4 vCPUs
- **RAM:** 16 GB
- **Disk:** 160 GB+ SSD storage
- **Network:** 100 Mbps+ bandwidth

**Tested platforms:** Hetzner Cloud, DigitalOcean, AWS EC2, GCP, Azure

## Quick Start

### Option A: Basic Installation (HTTP)
```bash
# 1. Download and run base installation
./install-wazuh.sh

# 2. Access Wazuh via HTTPS
# https://your-server-ip
```

### Option B: Full Installation with SSL (HTTPS)
```bash
# 1. Install Wazuh base
./install-wazuh.sh

# 2. Configure SSL (requires domain name)
./configure-ssl.sh wazuh.yourdomain.com admin@yourdomain.com

# 3. Access Wazuh via HTTPS
# https://wazuh.yourdomain.com
```

## Usage

### 1. Base Wazuh Installation
```bash
# No parameters required
./install-wazuh.sh
```

**What it does:**
- Installs all Wazuh components
- Configures basic firewall rules
- Provides HTTPS access on port 443
- Ready for immediate use

### 2. SSL Configuration (Optional)
```bash
# Requires domain and email
./configure-ssl.sh <DOMAIN_NAME> <EMAIL>
```

**Parameters:**
- **DOMAIN_NAME** - Fully qualified domain name (e.g., wazuh.yourdomain.com)
- **EMAIL** - Email address for Let's Encrypt certificate registration

**What it does:**
- Generates Let's Encrypt SSL certificates
- Configures Wazuh dashboard for HTTPS with custom domain
- Sets up HTTP to HTTPS redirect
- Enables automatic certificate renewal with webroot method

### Error Handling
```bash
# SSL script will show usage if parameters missing
./configure-ssl.sh

# Output:
ERROR: Usage: ./configure-ssl.sh <DOMAIN_NAME> <EMAIL>
Example: ./configure-ssl.sh wazuh.yourdomain.com admin@yourdomain.com
```

## What Gets Installed

### Core Components (install-wazuh.sh)
- **Wazuh Manager**: Security data processing and alert generation
- **Wazuh Indexer**: Data storage and search (OpenSearch-based)
- **Wazuh Dashboard**: Web interface for security monitoring
- **Native packages** - Uses official Wazuh installation assistant
- **Systemd services** - Standard Linux service management
- **UFW firewall** - Basic port configuration

### SSL Components (configure-ssl.sh)
- **Let's Encrypt certificates** - Free SSL/TLS certificates
- **HTTP to HTTPS redirect** - Nginx-based automatic redirection
- **Certbot** - Automatic certificate management with webroot
- **Domain-specific SSL** - Custom domain SSL configuration
- **Auto-renewal** - Zero-downtime certificate renewal

### Security Features
- Secure password generation (base installation)
- Let's Encrypt SSL certificates with automatic renewal (SSL script)
- TLS 1.2/1.3 encryption (SSL script)
- UFW firewall configuration
- Security headers and hardening (SSL script)

## Access Information

### After Base Installation
| Service | URL | Credentials |
|---------|-----|-------------|
| Dashboard | `https://server-ip` | admin / *generated-password* |
| API | `https://server-ip:55000` | wazuh-wui / *generated-password* |

### After SSL Configuration
| Service | URL | Credentials |
|---------|-----|-------------|
| Dashboard | `https://your-domain` | admin / *generated-password* |
| API | `https://your-domain:55000` | wazuh-wui / *generated-password* |

**🔐 SECURE PASSWORDS**: The installation assistant generates unique, secure passwords automatically!
- Passwords are saved to `/tmp/wazuh-install-files/wazuh-passwords.txt`
- **⚠️ IMPORTANT**: Save this file immediately - passwords cannot be recovered if lost

## Port Configuration

The installation configures the following ports:

| Port | Protocol | Service | Description |
|------|----------|---------|-------------|
| 80 | TCP | HTTP | Redirects to HTTPS |
| 443 | TCP | HTTPS | Wazuh Dashboard (secure) |
| 1514 | UDP | Wazuh | Agent data communication |
| 1515 | TCP | Wazuh | Agent enrollment |
| 55000 | TCP | API | Wazuh REST API |

## Post-Installation Steps

### 1. Save Generated Passwords (After Base Installation)
```bash
# Copy the password file to a secure location
sudo cp /tmp/wazuh-install-files/wazuh-passwords.txt ~/wazuh-passwords-backup.txt
sudo chmod 600 ~/wazuh-passwords-backup.txt

# View current passwords
cat /tmp/wazuh-install-files/wazuh-passwords.txt
```

### 1a. Configure SSL (Optional)
```bash
# If you want HTTPS access, run the SSL configuration
./configure-ssl.sh wazuh.yourdomain.com admin@yourdomain.com
```

### 2. Configure Agents
Use the following information to register agents:
- **Server Address**: Your domain or IP
- **Registration Port**: 1515
- **Communication Port**: 1514

### 3. Verify Installation

#### Base Installation Verification
```bash
# Check all Wazuh services
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer  
sudo systemctl status wazuh-dashboard

# Test HTTP dashboard access
curl -s http://localhost:5601
```

#### SSL Installation Verification (if configured)
```bash
# Check Nginx status
sudo systemctl status nginx

# Check SSL certificate
sudo certbot certificates

# Test HTTPS dashboard access
curl -k https://your-domain/app/wazuh
```

## Management Commands

### Service Management
```bash
# Individual service management
sudo systemctl start|stop|restart wazuh-manager
sudo systemctl start|stop|restart wazuh-indexer
sudo systemctl start|stop|restart wazuh-dashboard
sudo systemctl start|stop|restart nginx

# Check service status
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard

# Enable/disable auto-start
sudo systemctl enable wazuh-manager
sudo systemctl disable wazuh-manager
```

### View Service Logs
```bash
# View logs for specific services
sudo journalctl -u wazuh-manager -f
sudo journalctl -u wazuh-indexer -f
sudo journalctl -u wazuh-dashboard -f

# View Wazuh logs directly
sudo tail -f /var/ossec/logs/ossec.log
sudo tail -f /var/log/wazuh-indexer/wazuh-cluster.log
```

### SSL Certificate Management
```bash
# Check certificate status
sudo certbot certificates

# Manual renewal (automatic renewal is configured)
sudo certbot renew

# Test renewal process
sudo certbot renew --dry-run
```

## Directory Structure

```
/var/ossec/                     # Wazuh Manager installation
├── bin/                        # Wazuh binaries
├── etc/                        # Configuration files
├── logs/                       # Wazuh Manager logs
└── queue/                      # Agent communication queues

/etc/wazuh-indexer/             # Indexer configuration
├── opensearch.yml              # Main indexer config
└── certs/                      # SSL certificates

/etc/wazuh-dashboard/           # Dashboard configuration
├── opensearch_dashboards.yml   # Main dashboard config
└── certs/                      # SSL certificates

/var/lib/wazuh-indexer/         # Indexer data storage
└── nodes/                      # Index data and logs

/tmp/wazuh-install-files/       # Installation files (temporary)
└── wazuh-passwords.txt         # Generated passwords
```

## Troubleshooting

### Common Issues

#### Services Won't Start
```bash
# Check individual service status
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-manager  
sudo systemctl status wazuh-dashboard

# View service logs
sudo journalctl -u wazuh-indexer -n 50
sudo journalctl -u wazuh-manager -n 50
sudo journalctl -u wazuh-dashboard -n 50

# Restart services in correct order
sudo systemctl restart wazuh-indexer
sleep 10
sudo systemctl restart wazuh-manager
sleep 10
sudo systemctl restart wazuh-dashboard
```

#### SSL Certificate Issues
```bash
# Check certificate validity
openssl x509 -in /etc/letsencrypt/live/your-domain/cert.pem -text -noout

# Manual certificate renewal
sudo certbot certonly --standalone -d your-domain.com
```

#### Dashboard Not Accessible
```bash
# Check Nginx configuration
sudo nginx -t

# Check Nginx logs
sudo tail -f /var/log/nginx/error.log

# Restart Nginx
sudo systemctl restart nginx
```

#### Firewall Issues
```bash
# Check UFW status
sudo ufw status

# Allow specific ports
sudo ufw allow 443/tcp
```

### Log Locations
- **Nginx logs**: `/var/log/nginx/access.log`, `/var/log/nginx/error.log`
- **Wazuh Manager logs**: `/var/ossec/logs/ossec.log`
- **Wazuh Indexer logs**: `/var/log/wazuh-indexer/wazuh-cluster.log`
- **Wazuh Dashboard logs**: `/var/log/wazuh-dashboard/wazuh-dashboard.log`
- **System logs**: `journalctl -u wazuh-manager|wazuh-indexer|wazuh-dashboard`

## Security Considerations

### Immediate Actions Required
1. **Save generated passwords** from `/tmp/wazuh-install-files/wazuh-passwords.txt`
2. **Configure proper user management** in Wazuh Dashboard
3. **Review and adjust firewall rules** based on your needs
4. **Set up proper backup procedures**
5. **Test SSL certificate auto-renewal**

### Additional Security Measures
- Enable two-factor authentication
- Configure custom API credentials
- Set up log monitoring and alerting
- Regular security updates
- Network segmentation

## Backup and Recovery

### Important Files to Backup
- `/var/ossec/` - Wazuh Manager configuration and data
- `/etc/wazuh-indexer/` - Indexer configuration
- `/etc/wazuh-dashboard/` - Dashboard configuration  
- `/var/lib/wazuh-indexer/` - Indexer data (large, consider selective backup)
- `/etc/letsencrypt/` - SSL certificates
- `/etc/nginx/sites-available/wazuh` - Nginx configuration
- `/tmp/wazuh-install-files/wazuh-passwords.txt` - Generated passwords

### Backup Command Example
```bash
# Create backup directory
mkdir -p ~/wazuh-backup/$(date +%Y%m%d)

# Backup Wazuh configurations
sudo tar -czf ~/wazuh-backup/$(date +%Y%m%d)/wazuh-manager.tar.gz /var/ossec/etc/
sudo tar -czf ~/wazuh-backup/$(date +%Y%m%d)/wazuh-indexer-config.tar.gz /etc/wazuh-indexer/
sudo tar -czf ~/wazuh-backup/$(date +%Y%m%d)/wazuh-dashboard-config.tar.gz /etc/wazuh-dashboard/

# Backup SSL certificates
sudo tar -czf ~/wazuh-backup/$(date +%Y%m%d)/ssl-certs.tar.gz /etc/letsencrypt/

# Backup passwords
sudo cp /tmp/wazuh-install-files/wazuh-passwords.txt ~/wazuh-backup/$(date +%Y%m%d)/
```

## Monitoring and Maintenance

### Regular Maintenance Tasks
- Monitor disk usage (`/var/lib/wazuh-indexer/` grows over time)
- Check log rotation settings
- Verify SSL certificate renewal
- Update Wazuh packages periodically (`apt update && apt upgrade`)
- Review security alerts and rules
- Clean up old indices to save disk space

### Health Checks
```bash
# Check dashboard health
curl -k https://your-domain/app/wazuh

# Check API health (use actual password from wazuh-passwords.txt)
curl -k -u wazuh-wui:YOUR_GENERATED_PASSWORD https://your-domain:55000/

# Check indexer health
curl -k https://localhost:9200/_cluster/health

# Check all services status
sudo systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard nginx
```

## Cleanup and Reinstallation

If you need to completely remove Wazuh and start fresh, use the cleanup script:

### Complete Cleanup
```bash
# Run the cleanup script to remove all Wazuh components
./cleanup-wazuh.sh
```

### What the cleanup script removes:
- ✅ All Wazuh services (indexer, manager, dashboard)
- ✅ All Wazuh packages and dependencies
- ✅ All configuration files and data
- ✅ Wazuh system users and groups
- ✅ Nginx Wazuh configuration (if SSL was configured)
- ✅ Systemd service files
- ✅ Certificate renewal hooks (if SSL was configured)

### What is preserved:
- 🔒 SSL certificates (/etc/letsencrypt/)
- 🔒 Nginx service (continues running)
- 🔒 System packages (curl, certbot, etc.)

### After cleanup:
```bash
# Run the base installation script
./install-wazuh.sh

# Then optionally configure SSL
./configure-ssl.sh siem.yourdomain.com admin@yourdomain.com
```

The cleanup script includes confirmation prompts and detailed logging for safety.

## Platform Compatibility

This script has been tested and works on:

| Platform | VM Type | Status | Notes |
|----------|---------|--------|-------|
| **Hetzner Cloud** | CPX31 (4vCPU/16GB) | ✅ Tested | Excellent performance with NVMe |
| **GCP** | e2-standard-4 | ✅ Tested | Good performance and reliability |
| **DigitalOcean** | 4vCPU/16GB Droplet | ✅ Compatible | Standard droplet works well |
| **AWS EC2** | t3.xlarge | ✅ Compatible | Similar specs recommended |
| **Azure** | Standard_D4s_v3 | ✅ Compatible | 4vCPU/16GB configuration |

## Support and Documentation

- [Wazuh Official Documentation](https://documentation.wazuh.com/)
- [Wazuh Community Forum](https://wazuh.com/community/)
- [Wazuh Installation Guide](https://documentation.wazuh.com/current/installation-guide/)

## License

This installation script is provided under the MIT License. Wazuh itself is licensed under the GNU General Public License version 2.

## Script Structure

```
wazuh/
├── install-wazuh.sh      # Base Wazuh installation (HTTP)
├── configure-ssl.sh      # SSL configuration (HTTPS)
├── cleanup-wazuh.sh      # Complete removal script
└── README.md            # This documentation
```

## Contributing

Contributions to improve these installation scripts are welcome. Please ensure:
- Test changes on a fresh VM
- Test both base installation and SSL configuration
- Update documentation accordingly
- Follow security best practices
- Include proper error handling
- Test on multiple cloud platforms if possible

---

**Note**: These scripts were all vibe coded using AI and are designed for production use but should be reviewed and tested in your specific environment before deployment.