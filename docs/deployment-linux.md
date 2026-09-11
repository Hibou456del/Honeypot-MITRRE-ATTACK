# Linux Deployment Guide

This guide covers deploying the Dynamic Honeypot Platform on Linux with integration to an existing Cowrie installation.

## Prerequisites

### System Requirements

- **Linux distribution**: Ubuntu 20.04+ / Debian 11+ / RHEL 8+
- **RAM**: 4GB minimum, 8GB recommended
- **Disk**: 20GB minimum
- **Network**: Isolated laboratory network with MikroTik firewall
- **Existing Cowrie installation** (see Cowrie Integration section)

### Required Software

- **Python 3.9+**
- **Docker & Docker Compose**
- **Git**
- **PostgreSQL** (optional, can use Docker)
- **Cowrie** (already installed)

## Installation Steps

### 1. System Preparation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y python3 python3-pip python3-venv git docker.io docker-compose

# Add user to docker group
sudo usermod -aG docker $USER

# Reboot or log out/in for group changes to take effect
```

### 2. Clone Repository

```bash
# Clone repository
git clone <repository-url>
cd dynamic-honeypot

# Create production environment file
cp .env.example .env
```

### 3. Configure Environment

Edit `.env` for production:

```bash
nano .env
```

**Production settings:**
```
ENVIRONMENT=production
PLATFORM=linux
DB_PASSWORD=<strong_password>
DJANGO_SECRET_KEY=<strong_random_key>
DJANGO_DEBUG=False
COWRIE_LOG_PATH=/var/log/cowrie
COWRIE_INTEGRATION_MODE=host
```

### 4. Install Python Dependencies

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 5. Configure for Existing Cowrie

### Step 1: Inspect Existing Cowrie Installation

```bash
# Find Cowrie installation
sudo find / -name "cowrie" -type d 2>/dev/null

# Check Cowrie version
cd /opt/cowrie  # or wherever Cowrie is installed
cat cowrie.cfg | grep version

# Check log location
cat cowrie.cfg | grep log_path

# Check running status
sudo systemctl status cowrie
# or
ps aux | grep cowrie
```

### Step 2: Identify Cowrie Configuration

```bash
# Check Cowrie configuration file
cat /opt/cowrie/etc/cowrie.cfg

# Note important paths:
# - log_path: Where logs are written
# - output: Where output files are stored
# - listen ports: SSH/Telnet ports
```

### Step 3: Backup Existing Configuration

```bash
# Create backup directory
sudo mkdir -p /opt/cowrie_backup

# Backup configuration
sudo cp -r /opt/cowrie/etc /opt/cowrie_backup/

# Backup logs
sudo cp -r /var/log/cowrie /opt/cowrie_backup/ 2>/dev/null

# Backup output
sudo cp -r /opt/cowrie/var/lib/cowrie /opt/cowrie_backup/ 2>/dev/null
```

### Step 4: Update Project Configuration

Edit `config/settings.yaml`:

```yaml
environment: production
platform: linux

cowrie:
  enabled: true
  integration_mode: host
  log_path: /var/log/cowrie  # Adjust to your Cowrie log path
  log_format: json
```

Edit `config/cowrie_config.yaml`:

```yaml
cowrie:
  integration_mode: host
  host_paths:
    install_dir: /opt/cowrie  # Adjust to your installation
    config_dir: /opt/cowrie/etc
    log_dir: /var/log/cowrie  # Adjust to your log path
    share_dir: /opt/cowrie/share/cowrie
    output_dir: /opt/cowrie/var/lib/cowrie
```

### Step 5: Set Permissions

```bash
# Create log directory for parser
sudo mkdir -p /var/log/honeypot
sudo chown $USER:$USER /var/log/honeypot

# Create data directories
mkdir -p data/events/{raw,normalized,exported}
mkdir -p data/generated_decoys

# Set permissions for Cowrie log access
# Option 1: Add user to cowrie group
sudo usermod -aG cowrie $USER

# Option 2: Set group permissions on log directory
sudo chmod 750 /var/log/cowrie
sudo chgrp cowrie /var/log/cowrie
```

### 6. Start Services

#### Using Docker Compose (Recommended)

```bash
# Start production services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f
```

#### Using Systemd Services

Create systemd service files:

```bash
# Dashboard service
sudo nano /etc/systemd/system/honeypot-dashboard.service
```

Content:
```ini
[Unit]
Description=Dynamic Honeypot Dashboard
After=network.target postgresql.service

[Service]
Type=simple
User=honeypot
WorkingDirectory=/opt/dynamic-honeypot
Environment="PATH=/opt/dynamic-honeypot/venv/bin"
ExecStart=/opt/dynamic-honeypot/venv/bin/python dashboard/app_flask.py
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
# Collector service
sudo nano /etc/systemd/system/honeypot-collector.service
```

Content:
```ini
[Unit]
Description=Dynamic Honeypot Log Collector
After=network.target

[Service]
Type=simple
User=honeypot
WorkingDirectory=/opt/dynamic-honeypot
Environment="PATH=/opt/dynamic-honeypot/venv/bin"
ExecStart=/opt/dynamic-honeypot/venv/bin/python collectors/log_collector.py
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start services
sudo systemctl enable honeypot-dashboard
sudo systemctl enable honeypot-collector
sudo systemctl start honeypot-dashboard
sudo systemctl start honeypot-collector
```

### 7. Configure Network (MikroTik)

See `mikrotik-configuration.md` for detailed MikroTik setup.

Basic requirements:
- Honeypot in isolated VLAN/DMZ
- Restricted outbound access
- Firewall rules to control traffic
- Logging of network events

## Verification

### Test Cowrie Integration

```bash
# Test Cowrie parser
python -c "
from collectors.parse_cowrie import CowrieParser
parser = CowrieParser('/var/log/cowrie/cowrie.json')
events = parser.parse_file()
print(f'Parsed {len(events)} events')
print(f'Statistics: {parser.get_statistics()}')
"
```

### Test Complete Pipeline

```bash
# Run test scenario
python tests/test_scenarios/scenario_ssh_connection.py
```

### Test Dashboard Access

```bash
# Check if dashboard is running
curl http://localhost:8000/api/statistics

# Or access in browser
# http://<honeypot-ip>:8000
```

## Maintenance

### Log Rotation

Configure logrotate for Cowrie logs:

```bash
sudo nano /etc/logrotate.d/cowrie
```

Content:
```
/var/log/cowrie/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 cowrie cowrie
}
```

### Database Maintenance

```bash
# Backup PostgreSQL database
docker exec honeypot-postgres pg_dump -U honeypot_user honeypot_db > backup.sql

# Restore PostgreSQL database
docker exec -i honeypot-postgres psql -U honeypot_user honeypot_db < backup.sql
```

### Service Monitoring

```bash
# Check service status
sudo systemctl status honeypot-dashboard
sudo systemctl status honeypot-collector

# View logs
sudo journalctl -u honeypot-dashboard -f
sudo journalctl -u honeypot-collector -f
```

### Updates

```bash
# Update code
git pull origin main

# Update dependencies
source venv/bin/activate
pip install -r requirements.txt

# Restart services
sudo systemctl restart honeypot-dashboard
sudo systemctl restart honeypot-collector
```

## Troubleshooting

### Cowrie Integration Issues

**Problem**: Permission denied reading Cowrie logs
- **Solution**: Check user permissions on log directory
- **Solution**: Add user to cowrie group
- **Solution**: Adjust log directory permissions

**Problem**: Cowrie logs not in expected format
- **Solution**: Check Cowrie configuration for output format
- **Solution**: Ensure JSON output is enabled in Cowrie
- **Solution**: Update parser to match actual log format

**Problem**: Cowrie service conflicts
- **Solution**: Ensure Cowrie continues running normally
- **Solution**: Parser should only read logs, not interfere with Cowrie

### Docker Issues

**Problem**: Docker containers can't start
- **Solution**: Check Docker service status
- **Solution**: Verify Docker daemon is running
- **Solution**: Check container logs: `docker-compose logs`

**Problem**: Network connectivity issues
- **Solution**: Check Docker network configuration
- **Solution**: Verify firewall rules
- **Solution**: Check MikroTik configuration

### Performance Issues

**Problem**: High CPU usage
- **Solution**: Check Docker resource limits
- **Solution**: Optimize detection rules
- **Solution**: Adjust correlation window

**Problem**: High memory usage
- **Solution**: Limit event history size
- **Solution**: Adjust Docker memory limits
- **Solution**: Implement log rotation

## Security Hardening

### Firewall Configuration

```bash
# Allow only necessary ports
sudo ufw allow 22/tcp    # SSH (management)
sudo ufw allow 8000/tcp  # Dashboard
sudo ufw allow 2222/tcp # Cowrie SSH
sudo ufw enable
```

### User Security

```bash
# Create dedicated honeypot user
sudo useradd -r -s /bin/false honeypot

# Set file permissions
sudo chown -R honeypot:honeypot /opt/dynamic-honeypot
sudo chmod 750 /opt/dynamic-honeypot
```

### Service Security

```bash
# Run services as non-root user
# Configure in systemd service files

# Restrict network access
# Configure in MikroTik firewall
```

## Monitoring

### System Monitoring

```bash
# CPU and memory usage
htop

# Disk usage
df -h

# Network connections
netstat -tulpn
```

### Application Monitoring

```bash
# Check application logs
tail -f /var/log/honeypot/*.log

# Check Docker logs
docker-compose logs -f

# Check database connections
docker exec honeypot-postgres psql -U honeypot_user -d honeypot_db -c "SELECT count(*) FROM pg_stat_activity;"
```

## Backup Strategy

### Automated Backup Script

```bash
#!/bin/bash
# backup.sh

BACKUP_DIR="/opt/backups/honeypot"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p $BACKUP_DIR

# Backup database
docker exec honeypot-postgres pg_dump -U honeypot_user honeypot_db > $BACKUP_DIR/db_$DATE.sql

# Backup configuration
tar -czf $BACKUP_DIR/config_$DATE.tar.gz config/

# Backup generated data
tar -czf $BACKUP_DIR/data_$DATE.tar.gz data/

# Keep last 7 days
find $BACKUP_DIR -name "*.sql" -mtime +7 -delete
find $BACKUP_DIR -name "*.tar.gz" -mtime +7 -delete
```

Add to crontab:
```bash
# Daily backup at 2 AM
0 2 * * * /opt/dynamic-honeypot/backup.sh
```

## Integration Testing

### Test Complete Pipeline

```bash
# 1. Generate test traffic to Cowrie
ssh -p 2222 testuser@localhost

# 2. Wait for log collection
sleep 30

# 3. Check normalized events
ls -la data/events/normalized/

# 4. Check dashboard
curl http://localhost:8000/api/statistics

# 5. Check alerts
curl http://localhost:8000/api/alerts
```

## Upgrade Path

### From Development to Production

1. **Backup development data**
2. **Copy repository to production server**
3. **Update configuration files**
4. **Install production dependencies**
5. **Configure Cowrie integration**
6. **Start services**
7. **Verify functionality**
8. **Configure monitoring**

## Additional Resources

- [Cowrie Documentation](https://cowrie.readthedocs.io/)
- [Docker Documentation](https://docs.docker.com/)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [MikroTik Documentation](https://wiki.mikrotik.com/wiki/Main_Page)