# Wazuh GCP Installation Script

This repository contains an automated installation script for deploying Wazuh on a Debian-based VM in Google Cloud Platform (GCP) with full SSL/HTTPS configuration.

## Overview

The `install-wazuh-gcp.sh` script provides a complete, production-ready Wazuh installation with:
- SSL/TLS encryption using Let's Encrypt certificates
- Nginx reverse proxy for secure HTTPS access
- Docker-based deployment for easy management
- Automatic certificate renewal
- Firewall configuration
- System service integration

## Prerequisites

- Debian/Ubuntu-based VM on GCP
- Non-root user with sudo privileges
- Internet connectivity
- Domain name pointing to your VM's external IP (recommended)
- Ports 80, 443, 1514, 1515, and 55000 accessible

## Quick Start

1. Clone or download this repository to your GCP VM
2. Make the script executable:
   ```bash
   chmod +x install-wazuh-gcp.sh
   ```
3. Run the installation:
   ```bash
   ./install-wazuh-gcp.sh [domain] [email]
   ```

## Usage

### Basic Installation
Uses the VM's external IP address:
```bash
./install-wazuh-gcp.sh
```

### Custom Domain Installation
```bash
./install-wazuh-gcp.sh wazuh.yourdomain.com admin@yourdomain.com
```

## What Gets Installed

### Core Components
- **Wazuh Manager**: Security data processing and alert generation
- **Wazuh Indexer**: Data storage and search (OpenSearch-based)
- **Wazuh Dashboard**: Web interface for security monitoring
- **Docker & Docker Compose**: Container orchestration
- **Nginx**: Reverse proxy for HTTPS termination
- **Certbot**: SSL certificate management

### Security Features
- Let's Encrypt SSL certificates with automatic renewal
- TLS 1.2/1.3 encryption
- UFW firewall configuration
- Secure default configurations

## Access Information

After installation, you can access Wazuh at:

| Service | URL | Default Credentials |
|---------|-----|-------------------|
| Dashboard | `https://your-domain` | admin / SecretPassword |
| API | `https://your-domain:55000` | wazuh-wui / MyS3cr37P450r.*- |

**⚠️ SECURITY WARNING**: Change default passwords immediately after first login!

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

### 1. Change Default Passwords
```bash
# Access the dashboard and change admin password
# API passwords can be changed in the configuration files
```

### 2. Configure Agents
Use the following information to register agents:
- **Server Address**: Your domain or IP
- **Registration Port**: 1515
- **Communication Port**: 1514

### 3. Verify Installation
```bash
# Check Wazuh services
docker compose ps

# Check Nginx status
sudo systemctl status nginx

# Check SSL certificate
sudo certbot certificates
```

## Management Commands

### Service Management
```bash
# Start Wazuh services
sudo systemctl start wazuh

# Stop Wazuh services
sudo systemctl stop wazuh

# Restart services
sudo systemctl restart wazuh

# Check status
sudo systemctl status wazuh
```

### Manual Docker Commands
```bash
cd /opt/wazuh

# Start services
docker compose up -d

# Stop services
docker compose down

# View logs
docker compose logs -f

# Restart specific service
docker compose restart wazuh.dashboard
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
/opt/wazuh/
├── docker-compose.yml          # Main compose file
├── docker-compose.override.yml # SSL configuration overrides
├── single-node/
│   └── config/
│       ├── wazuh_indexer_ssl_certs/
│       └── wazuh_dashboard_ssl_certs/
└── wazuh-docker/               # Additional configuration files
```

## Troubleshooting

### Common Issues

#### Services Won't Start
```bash
# Check Docker status
sudo systemctl status docker

# Check logs
docker compose logs

# Restart Docker daemon
sudo systemctl restart docker
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
- **Nginx logs**: `/var/log/nginx/`
- **Docker logs**: `docker compose logs`
- **System logs**: `journalctl -u wazuh`
- **Installation log**: `/var/log/wazuh-install.log`

## Security Considerations

### Immediate Actions Required
1. **Change default passwords** for all services
2. **Configure proper user management** in Wazuh
3. **Review and adjust firewall rules** based on your needs
4. **Set up proper backup procedures**

### Additional Security Measures
- Enable two-factor authentication
- Configure custom API credentials
- Set up log monitoring and alerting
- Regular security updates
- Network segmentation

## Backup and Recovery

### Important Files to Backup
- `/opt/wazuh/` - Wazuh configuration and data
- `/etc/letsencrypt/` - SSL certificates
- `/etc/nginx/sites-available/wazuh` - Nginx configuration

### Backup Command Example
```bash
# Create backup directory
mkdir -p ~/wazuh-backup/$(date +%Y%m%d)

# Backup Wazuh data
sudo tar -czf ~/wazuh-backup/$(date +%Y%m%d)/wazuh-config.tar.gz /opt/wazuh/

# Backup SSL certificates
sudo tar -czf ~/wazuh-backup/$(date +%Y%m%d)/ssl-certs.tar.gz /etc/letsencrypt/
```

## Monitoring and Maintenance

### Regular Maintenance Tasks
- Monitor disk usage (Wazuh data grows over time)
- Check log rotation settings
- Verify SSL certificate renewal
- Update Docker images periodically
- Review security alerts and rules

### Health Checks
```bash
# Check service health
curl -k https://your-domain/app/wazuh

# Check API health
curl -k -u wazuh-wui:MyS3cr37P450r.*- https://your-domain:55000/
```

## Support and Documentation

- [Wazuh Official Documentation](https://documentation.wazuh.com/)
- [Wazuh Community Forum](https://wazuh.com/community/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)

## License

This installation script is provided under the MIT License. Wazuh itself is licensed under the GNU General Public License version 2.

## Contributing

Contributions to improve this installation script are welcome. Please ensure:
- Test changes on a fresh VM
- Update documentation accordingly
- Follow security best practices
- Include proper error handling

---

**Note**: This script is designed for production use but should be reviewed and tested in your specific environment before deployment.