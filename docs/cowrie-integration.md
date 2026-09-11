# Cowrie Integration Guide

This guide details how to integrate the Dynamic Honeypot Platform with an existing Cowrie installation on Linux.

## Overview

The platform is designed to work with existing Cowrie installations without requiring reinstallation or reconfiguration. The integration is read-only and non-intrusive.

## Prerequisites

- Existing Cowrie installation
- Cowrie version 1.5.0+ (for JSON log support)
- Read access to Cowrie log files
- Python 3.9+ on the same system

## Integration Approach

### Non-Intrusive Integration

The platform uses a **read-only** approach:
- **No modification** to Cowrie configuration
- **No restart** of Cowrie service
- **No interference** with Cowrie operation
- **Log files are read** using standard file access

### Architecture

```
┌─────────────────┐
│   Cowrie        │
│   (Running)     │
└────────┬────────┘
         │
         │ Writes logs
         ↓
┌─────────────────┐
│  Log Files      │
│  (/var/log/...) │
└────────┬────────┘
         │
         │ Read by parser
         ↓
┌─────────────────┐
│  Cowrie Parser  │
│  (This platform)│
└─────────────────┘
```

## Step-by-Step Integration

### Step 1: Inventory Existing Cowrie Installation

```bash
# Find Cowrie installation
sudo find / -name "cowrie.cfg" 2>/dev/null

# Check Cowrie version
cd /opt/cowrie  # Adjust to your installation
python3 --version
./bin/cowrie --version

# Check running process
ps aux | grep cowrie

# Check service status
sudo systemctl status cowrie
```

### Step 2: Identify Cowrie Configuration

```bash
# View main configuration
cat /opt/cowrie/etc/cowrie.cfg

# Key settings to note:
# - log_path: Where log files are written
# - output: Where output files are stored
# - listen ports: SSH/Telnet ports
# - auth_class: Authentication backend
```

### Step 3: Verify Log Format

```bash
# Check if JSON logging is enabled
grep -A 5 "output_json" /opt/cowrie/etc/cowrie.cfg

# Check log location
grep -A 5 "log_path" /opt/cowrie/etc/cowrie.cfg

# View sample log file
tail -20 /var/log/cowrie/cowrie.json  # Adjust path as needed
```

**Expected JSON format:**
```json
{
  "eventid": "cowrie.session.connect",
  "timestamp": "2026-09-08T10:15:23Z",
  "src_ip": "192.168.1.100",
  "src_port": 54321,
  "dst_ip": "192.168.1.50",
  "dst_port": 2222,
  "session": "abc123",
  "protocol": "ssh"
}
```

### Step 4: Enable JSON Logging (if not enabled)

If Cowrie is not configured for JSON output:

```bash
# Backup original configuration
sudo cp /opt/cowrie/etc/cowrie.cfg /opt/cowrie/etc/cowrie.cfg.backup

# Edit configuration
sudo nano /opt/cowrie/etc/cowrie.cfg
```

Add or modify:
```ini
[output_json]
log_path = /var/log/cowrie/cowrie.json
```

**⚠️ IMPORTANT**: After modifying configuration, restart Cowrie:
```bash
sudo systemctl restart cowrie
```

### Step 5: Set File Permissions

```bash
# Check current permissions
ls -la /var/log/cowrie/

# Add honeypot user to cowrie group (if exists)
sudo usermod -aG cowrie $USER

# OR set group permissions
sudo chmod 750 /var/log/cowrie
sudo chgrp cowrie /var/log/cowrie

# Verify access
ls -la /var/log/cowrie/cowrie.json
```

### Step 6: Configure Platform

Edit `config/settings.yaml`:

```yaml
cowrie:
  enabled: true
  integration_mode: host
  log_path: /var/log/cowrie  # Adjust to your path
  log_format: json
  session_timeout: 1800
```

Edit `config/cowrie_config.yaml`:

```yaml
cowrie:
  integration_mode: host
  host_paths:
    install_dir: /opt/cowrie        # Adjust
    config_dir: /opt/cowrie/etc     # Adjust
    log_dir: /var/log/cowrie        # Adjust
    share_dir: /opt/cowrie/share/cowrie
    output_dir: /opt/cowrie/var/lib/cowrie
```

### Step 7: Test Parser

```bash
# Test Cowrie parser
python3 -c "
from collectors.parse_cowrie import CowrieParser
parser = CowrieParser('/var/log/cowrie/cowrie.json')
events = parser.parse_file()
print(f'Parsed {len(events)} events')
print(f'Statistics: {parser.get_statistics()}')
"
```

### Step 8: Test Complete Pipeline

```bash
# Run test scenario
python3 tests/test_scenarios/scenario_ssh_connection.py
```

## Advanced Configuration

### Multiple Cowrie Instances

If running multiple Cowrie instances:

```yaml
cowrie:
  enabled: true
  integration_mode: host
  log_paths:
    - /var/log/cowrie/instance1/cowrie.json
    - /var/log/cowrie/instance2/cowrie.json
```

### Custom Log Formats

If using custom log format, modify `parse_cowrie.py`:

```python
def _parse_event_data(self, data: Dict[str, Any]) -> Optional[CowrieEvent]:
    # Add custom parsing logic here
    pass
```

### Real-time Log Monitoring

For real-time log processing:

```python
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class LogHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path.endswith('cowrie.json'):
            # Trigger log processing
            process_new_logs()

observer = Observer()
observer.schedule(LogHandler(), '/var/log/cowrie')
observer.start()
```

## Troubleshooting

### Permission Denied

**Problem**: Permission denied reading Cowrie logs
```bash
# Check permissions
ls -la /var/log/cowrie/

# Solution 1: Add user to cowrie group
sudo usermod -aG cowrie $USER

# Solution 2: Adjust directory permissions
sudo chmod 750 /var/log/cowrie
sudo chgrp cowrie /var/log/cowrie
```

### Log Format Issues

**Problem**: Parser cannot read log format
```bash
# Check actual log format
head -5 /var/log/cowrie/cowrie.json

# Solution: Enable JSON logging in Cowrie
# Solution: Modify parser to match actual format
```

### Cowrie Service Conflicts

**Problem**: Platform interferes with Cowrie operation
- **Solution**: Ensure platform only reads logs
- **Solution**: Do not modify Cowrie configuration after initial setup
- **Solution**: Monitor Cowrie service status

### Performance Impact

**Problem**: Parsing slows down Cowrie
- **Solution**: Use separate log file for platform
- **Solution**: Implement log rotation
- **Solution**: Batch processing instead of real-time

## Validation

### Integration Validation Checklist

- [ ] Cowrie installation identified
- [ ] Cowrie version confirmed (1.5.0+)
- [ ] Log location identified
- [ ] Log format verified (JSON)
- [ ] File permissions configured
- [ ] Platform configuration updated
- [ ] Parser tested successfully
- [ ] Complete pipeline tested
- [ ] No interference with Cowrie operation
- [ ] Monitoring configured

### Test Scenarios

1. **Basic Parsing Test**
   ```bash
   python3 -c "from collectors.parse_cowrie import CowrieParser; parser = CowrieParser('/var/log/cowrie/cowrie.json'); print(len(parser.parse_file()))"
   ```

2. **Integration Test**
   ```bash
   python3 tests/test_scenarios/scenario_ssh_connection.py
   ```

3. **Real-time Test**
   ```bash
   # Generate test traffic
   ssh -p 2222 test@localhost
   
   # Check if events are processed
   ls -la data/events/normalized/
   ```

## Maintenance

### Log Rotation

Configure logrotate for Cowrie logs:

```bash
sudo nano /etc/logrotate.d/cowrie
```

```
/var/log/cowrie/*.json {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 cowrie cowrie
    sharedscripts
    postrotate
        systemctl reload cowrie >/dev/null 2>&1 || true
    endscript
}
```

### Monitoring Integration Health

```bash
# Check if parser is running
ps aux | grep log_collector

# Check if logs are being processed
tail -f /var/log/honeypot/honeypot.log

# Check event count
ls -la data/events/normalized/
```

### Updates and Upgrades

When updating Cowrie:

1. **Backup current configuration**
2. **Test new Cowrie version in isolation**
3. **Verify log format compatibility**
4. **Update parser if needed**
5. **Test integration**
6. **Deploy to production**

## Cowrie-Specific Considerations

### Session Management

The platform tracks Cowrie sessions using session IDs from logs. Ensure:
- Session IDs are consistent across log entries
- Session timeout is configured appropriately
- Session cleanup doesn't interfere with tracking

### Output Files

Cowrie may generate output files (downloaded files, etc.). Configure:
- Output file location in `config/cowrie_config.yaml`
- Processing of output files if needed
- Cleanup of old output files

### Authentication Events

The platform parses authentication events from Cowrie logs. Ensure:
- Failed login attempts are logged
- Successful logins are logged
- Authentication method is recorded

## Performance Optimization

### Batch Processing

Instead of real-time processing, use batch processing:

```python
# Process logs every 5 minutes
import schedule
import time

def process_logs():
    parser = CowrieParser('/var/log/cowrie/cowrie.json')
    events = parser.parse_file()
    # Process events...

schedule.every(5).minutes.do(process_logs)

while True:
    schedule.run_pending()
    time.sleep(60)
```

### Log File Splitting

Split large log files for better performance:

```bash
# Split by size
split -b 100M /var/log/cowrie/cowrie.json cowrie_split_

# Process each file
for file in cowrie_split_*; do
    python3 -c "from collectors.parse_cowrie import CowrieParser; parser = CowrieParser('$file'); parser.parse_file()"
done
```

## Security Considerations

### Log File Security

- Ensure log files have appropriate permissions
- Regularly rotate and archive logs
- Monitor for unauthorized log access
- Encrypt sensitive log data if needed

### Cowrie Security

- Maintain Cowrie security updates
- Monitor Cowrie for vulnerabilities
- Keep Cowrie isolated from production systems
- Regularly review Cowrie configuration

## Additional Resources

- [Cowrie Documentation](https://cowrie.readthedocs.io/)
- [Cowrie GitHub Repository](https://github.com/cowrie/cowrie)
- [Cowrie Configuration Guide](https://cowrie.readthedocs.io/en/latest/quickstart.html)