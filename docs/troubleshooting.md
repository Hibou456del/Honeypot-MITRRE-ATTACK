# Troubleshooting Guide

## Overview

This guide provides solutions to common issues encountered when deploying and operating the Dynamic Honeypot Platform.

## Installation Issues

### Python Environment Issues

#### Problem: Module not found errors
```
ModuleNotFoundError: No module named 'yaml'
```

**Solutions:**
```bash
# Ensure virtual environment is activated
source venv/bin/activate  # Linux/Mac
.\venv\Scripts\activate  # Windows

# Reinstall dependencies
pip install -r requirements.txt

# Check Python path
which python
python --version
```

#### Problem: Permission denied installing packages
```
PermissionError: [Errno 13] Permission denied
```

**Solutions:**
```bash
# Use user directory
pip install --user -r requirements.txt

# Or use virtual environment
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Docker Issues

#### Problem: Docker daemon not running
```
Cannot connect to the Docker daemon
```

**Solutions:**
```bash
# Start Docker Desktop (Windows/Mac)
# Or start Docker service (Linux)
sudo systemctl start docker
sudo systemctl enable docker

# Check Docker status
docker info
```

#### Problem: Container network issues
```
ERROR: could not connect to database
```

**Solutions:**
```bash
# Check Docker network
docker network ls
docker network inspect honeypot-network

# Restart containers
docker-compose down
docker-compose up -d

# Check container logs
docker-compose logs postgres
```

## Configuration Issues

### Environment Variables

#### Problem: Missing environment variables
```
KeyError: 'DB_PASSWORD'
```

**Solutions:**
```bash
# Copy example .env file
cp .env.example .env

# Edit .env file
nano .env

# Ensure .env is in correct location
ls -la .env

# Restart services
docker-compose restart
```

#### Problem: Configuration file not found
```
FileNotFoundError: config/settings.yaml
```

**Solutions:**
```bash
# Check configuration directory
ls -la config/

# Check current working directory
pwd

# Set correct path in code or move to project root
cd /path/to/dynamic-honeypot
```

### Cowrie Integration

#### Problem: Cannot read Cowrie logs
```
PermissionError: [Errno 13] Permission denied: '/var/log/cowrie/cowrie.json'
```

**Solutions:**
```bash
# Check log permissions
ls -la /var/log/cowrie/

# Add user to cowrie group
sudo usermod -aG cowrie $USER

# Or adjust permissions
sudo chmod 750 /var/log/cowrie
sudo chgrp cowrie /var/log/cowrie

# Test access
cat /var/log/cowrie/cowrie.json
```

#### Problem: Cowrie logs not in expected format
```
JSONDecodeError: Expecting value: line 1 column 1 (char 0)
```

**Solutions:**
```bash
# Check actual log format
head -5 /var/log/cowrie/cowrie.json

# Check if JSON logging is enabled
grep -A 5 "output_json" /opt/cowrie/etc/cowrie.cfg

# If not JSON, enable JSON logging in Cowrie config
# Or modify parser to match actual format
```

## Runtime Issues

### Parser Issues

#### Problem: Parser returns zero events
```
Parsed 0 events from log file
```

**Solutions:**
```bash
# Check if log file exists and has content
ls -la collectors/sample_logs/cowrie_sample.log
wc -l collectors/sample_logs/cowrie_sample.log

# Check log file format
head -3 collectors/sample_logs/cowrie_sample.log

# Test parser manually
python -c "
from collectors.parse_cowrie import CowrieParser
parser = CowrieParser('collectors/sample_logs/cowrie_sample.log')
events = parser.parse_file()
print(f'Events: {len(events)}')
print(f'Stats: {parser.get_statistics()}')
"
```

#### Problem: Parser crashes on malformed data
```
AttributeError: 'NoneType' object has no attribute 'get'
```

**Solutions:**
```bash
# Check for corrupted log files
python -c "
import json
with open('collectors/sample_logs/cowrie_sample.log') as f:
    for i, line in enumerate(f):
        try:
            json.loads(line)
        except:
            print(f'Error on line {i}')
"

# Clean corrupted lines
# Or add error handling in parser
```

### Database Issues

#### Problem: Database connection failed
```
psycopg2.OperationalError: could not connect to server
```

**Solutions:**
```bash
# Check if PostgreSQL is running
docker-compose ps postgres

# Check database logs
docker-compose logs postgres

# Verify database credentials
# Check .env file

# Test connection manually
docker exec -it honeypot-postgres psql -U honeypot_user -d honeypot_db -c "SELECT 1;"
```

#### Problem: Database schema errors
```
django.db.utils.OperationalError: no such table: events_event
```

**Solutions:**
```bash
# Run migrations
python manage.py migrate

# Or for Django
docker-compose exec dashboard python manage.py migrate

# Create tables manually if needed
```

### Detection Engine Issues

#### Problem: No alerts generated
```
Generated 0 alerts from 10 events
```

**Solutions:**
```bash
# Check if rules are enabled
python -c "
from detection.rules import RuleEngine
engine = RuleEngine()
print(f'Enabled rules: {len(engine.get_enabled_rules())}')
print(f'Total rules: {len(engine.get_all_rules())}')
"

# Check detection rules configuration
cat config/detection_rules.yaml

# Test with known malicious events
python -c "
from detection.detection_engine import DetectionEngine
engine = DetectionEngine()
events = [{
    'timestamp': '2026-09-08T10:20:00Z',
    'event_type': 'login_failed',
    'source_ip': '192.168.1.100'
}]
alerts = engine.analyze_events(events)
print(f'Alerts: {len(alerts)}')
"
```

#### Problem: High false positive rate
```
Too many alerts for benign activity
```

**Solutions:**
```bash
# Adjust detection thresholds
# Edit config/detection_rules.yaml

# Increase confidence thresholds
# Add more specific patterns

# Review detection rules
python -c "
from detection.rules import RuleEngine
engine = RuleEngine()
for rule in engine.get_all_rules():
    print(f'{rule.name}: {rule.severity}')
"
```

### Dashboard Issues

#### Problem: Dashboard won't start
```
Address already in use
```

**Solutions:**
```bash
# Check if port is in use
netstat -tulpn | grep 8000

# Kill process using port
kill -9 <PID>

# Or use different port
python dashboard/app_flask.py --port 8001
```

#### Problem: Dashboard shows no data
```
No events displayed in dashboard
```

**Solutions:**
```bash
# Check if collector is running
ps aux | grep log_collector

# Check if events are being generated
ls -la data/events/normalized/

# Check API endpoints
curl http://localhost:8000/api/statistics
curl http://localhost:8000/api/events

# Check database connection
docker-compose exec dashboard python manage.py dbshell
```

## Performance Issues

### Memory Issues

#### Problem: High memory usage
```
MemoryError: Unable to allocate memory
```

**Solutions:**
```bash
# Check memory usage
htop
docker stats

# Limit event history size
# Edit config/settings.yaml
detection:
  max_events_per_session: 500  # Reduce from 1000

# Restart services
docker-compose restart

# Add memory limits to Docker
# Edit docker-compose.yml
services:
  dashboard:
    mem_limit: 512m
```

#### Problem: Memory leak over time
```
Memory usage increases continuously
```

**Solutions:**
```bash
# Monitor memory usage
watch -n 5 'docker stats --no-stream'

# Restart services periodically
# Add to cron
0 3 * * * docker-compose restart

# Check for memory leaks
python -m memory_profiler collectors/log_collector.py
```

### CPU Issues

#### Problem: High CPU usage
```
CPU usage near 100%
```

**Solutions:**
```bash
# Check CPU usage
top
docker stats

# Identify CPU-intensive process
ps aux --sort=-%cpu | head

# Reduce processing frequency
# Edit collection interval

# Add CPU limits to Docker
services:
  detection:
    cpus: '0.5'
```

## Network Issues

### Connectivity Issues

#### Problem: Cannot connect to honeypot
```
Connection refused
```

**Solutions:**
```bash
# Check if honeypot service is running
docker-compose ps

# Check firewall rules
sudo ufw status
iptables -L

# Check MikroTik configuration
# See mikrotik-configuration.md

# Test connectivity
telnet <honeypot-ip> 2222
curl http://<honeypot-ip>:8080
```

#### Problem: Network isolation not working
```
Honeypot can access external network
```

**Solutions:**
```bash
# Check outbound blocking
# From honeypot container
docker exec -it honeypot-container ping google.com

# Check firewall rules
sudo iptables -L FORWARD

# Check MikroTik rules
# See mikrotik-configuration.md

# Verify honeypot network configuration
ip addr show
```

## File System Issues

### Permission Issues

#### Problem: Cannot write to data directories
```
PermissionError: [Errno 13] Permission denied: 'data/events/'
```

**Solutions:**
```bash
# Check directory permissions
ls -la data/

# Fix permissions
chmod 755 data/
chmod 755 data/events/
chown $USER:$USER data/

# Or run as correct user
# Don't run as root
```

#### Problem: Disk space full
```
No space left on device
```

**Solutions:**
```bash
# Check disk usage
df -h
du -sh data/

# Clean old logs
find data/events/raw/ -name "*.log" -mtime +7 -delete

# Clean old normalized events
find data/events/normalized/ -name "*.json" -mtime +30 -delete

# Setup log rotation
# See deployment-linux.md
```

## Integration Issues

### Cowrie Integration

#### Problem: Cowrie service conflicts
```
Cowrie stops after platform starts
```

**Solutions:**
```bash
# Check Cowrie service status
sudo systemctl status cowrie

# Check if platform is interfering
# Platform should only read logs, not modify Cowrie

# Verify read-only access
# See cowrie-integration.md

# Restart Cowrie if needed
sudo systemctl restart cowrie
```

#### Problem: Cowrie logs not being processed
```
No new events in dashboard
```

**Solutions:**
```bash
# Check if collector is running
ps aux | grep log_collector

# Check log file permissions
ls -la /var/log/cowrie/

# Test parser
python -c "
from collectors.parse_cowrie import CowrieParser
parser = CowrieParser('/var/log/cowrie/cowrie.json')
events = parser.parse_file()
print(f'Events: {len(events)}')
"

# Check collector logs
tail -f /var/log/honeypot/honeypot.log
```

### MITRE Mapping Issues

#### Problem: No MITRE techniques mapped
```
Mapped 0 events to MITRE techniques
```

**Solutions:**
```bash
# Check mapping configuration
cat config/mitre_attack_mapping.json

# Test mapper
python -c "
from mitre.mitre_mapper import MiteMapper
mapper = MiteMapper()
event = {
    'timestamp': '2026-09-08T10:15:30Z',
    'event_type': 'command_execution',
    'command': 'whoami'
}
result = mapper.map_event(event)
print(f'Techniques: {len(result.techniques)}')
"

# Check if events are being normalized correctly
# See normalization issues section
```

## Debugging Tools

### Python Debugging

#### Using pdb
```bash
# Run with debugger
python -m pdb collectors/log_collector.py

# Set breakpoints in code
import pdb; pdb.set_trace()
```

#### Using VS Code Debugger
1. Set breakpoints in code
2. Press F5 to start debugging
3. Use debug controls to step through code

### Logging

#### Enable debug logging
```python
# In code
import logging
logging.basicConfig(level=logging.DEBUG)

# Or in config
# Edit config/settings.yaml
logging:
  level: DEBUG
```

#### View logs
```bash
# Application logs
tail -f logs/honeypot.log

# Docker logs
docker-compose logs -f

# System logs
journalctl -u honeypot-dashboard -f
```

### Health Checks

#### Service health
```bash
# Check all services
docker-compose ps

# Check specific service
docker-compose exec dashboard python -c "print('OK')"

# Database health
docker-compose exec postgres pg_isready
```

#### API health
```bash
# Check API endpoints
curl http://localhost:8000/api/statistics
curl http://localhost:8000/api/events
curl http://localhost:8000/api/alerts
```

## Getting Help

### Documentation
- Check relevant documentation in `docs/` directory
- Review error messages carefully
- Check GitHub issues for similar problems

### Community Resources
- GitHub Issues: Report bugs and ask questions
- Documentation: Check for updated guides
- Forums: Community support channels

### Support Process
1. **Identify Issue**: Clearly define the problem
2. **Gather Information**: Collect logs, error messages, configuration
3. **Search Documentation**: Check existing documentation
4. **Create Issue**: File detailed bug report if needed
5. **Provide Details**: Include environment, configuration, steps to reproduce

## Common Error Messages

### Import Errors
```
ImportError: No module named 'yaml'
```
**Solution**: Install dependencies with `pip install -r requirements.txt`

### Connection Errors
```
ConnectionRefusedError: [Errno 111] Connection refused
```
**Solution**: Check if service is running and firewall rules

### Permission Errors
```
PermissionError: [Errno 13] Permission denied
```
**Solution**: Check file permissions and user access

### Configuration Errors
```
KeyError: 'missing_key'
```
**Solution**: Check configuration files and environment variables

### Database Errors
```
psycopg2.OperationalError: FATAL: database does not exist
```
**Solution**: Create database or check connection settings

## Prevention

### Regular Maintenance
- **Daily**: Monitor logs and errors
- **Weekly**: Check disk space and performance
- **Monthly**: Review security updates
- **Quarterly**: Full system review

### Backup and Recovery
- **Regular Backups**: Automated database and config backups
- **Test Restores**: Verify backup integrity
- **Documentation**: Keep backup procedures updated

### Monitoring
- **Health Checks**: Regular service health checks
- **Performance Monitoring**: Track system performance
- **Security Monitoring**: Monitor for security events
- **Alerting**: Set up appropriate alerts