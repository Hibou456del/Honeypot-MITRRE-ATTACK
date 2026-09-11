# MikroTik Configuration Guide

This guide covers configuring a MikroTik router for network segmentation and security for the Dynamic Honeypot Platform.

## Network Architecture

### Target Topology

```
┌─────────────────────────────────────────────────────────────┐
│                     Internet / Lab Network                   │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       │ eth1 (WAN)
┌──────────────────────▼──────────────────────────────────────┐
│                   MikroTik Router                            │
│  - RouterOS v6.48+                                           │
│  - Firewall / NAT                                             │
│  - VLAN Management                                            │
└────────┬─────────────────────────────┬──────────────────────┘
         │ eth2                       │ eth3
         │                            │
┌────────▼──────────┐        ┌────────▼──────────┐
│  Production       │        │  Honeypot         │
│  Network         │        │  DMZ / VLAN      │
│  (Safe)          │        │  (Isolated)      │
└───────────────────┘        └─────────┬────────┘
                                       │
                    ┌──────────────────┼──────────────────┐
                    │                  │                  │
            ┌───────▼──────┐  ┌───────▼──────┐  ┌───────▼──────┐
            │   Cowrie     │  │  HTTP        │  │  Management  │
            │   (2222)     │  │  Honeypot    │  │  (8000)      │
            └──────────────┘  │  (8080)      │  └──────────────┘
                               └──────────────┘
```

## MikroTik Configuration

### Basic Network Setup

#### 1. Interface Configuration

```mikrotik
# Enable interfaces
/interface enable eth1
/interface enable eth2
/interface enable eth3

# Configure WAN interface (eth1)
/ip address add address=192.168.1.1/24 interface=eth1

# Configure production network (eth2)
/ip address add address=192.168.10.1/24 interface=eth2

# Configure honeypot DMZ (eth3)
/ip address add address=192.168.50.1/24 interface=eth3
```

#### 2. VLAN Configuration (Optional)

```mikrotik
# Create VLAN for honeypot DMZ
/interface vlan add name=honeypot-vlan vlan-id=50 interface=eth3

# Assign IP to VLAN
/ip address add address=192.168.50.1/24 interface=honeypot-vlan
```

#### 3. DHCP Configuration

```mikrotik
# DHCP pool for honeypot DMZ
/ip pool add name=honeypot-pool ranges=192.168.50.100-192.168.50.200

# DHCP network
/ip dhcp-server network add address=192.168.50.0/24 gateway=192.168.50.1 dns-server=8.8.8.8

# DHCP server
/ip dhcp-server add name=honeypot-dhcp interface=honeypot-vlan address-pool=honeypot-pool disabled=no
```

### Firewall Configuration

#### 1. Basic Firewall Rules

```mikrotik
# Reset firewall
/ip firewall filter
# (Careful: this removes existing rules)

# Default deny policy
/ip firewall filter add chain=input action=drop comment="Default deny input"
/ip firewall filter add chain=forward action=drop comment="Default deny forward"
/ip firewall filter add chain=output action=accept comment="Accept output"

# Allow established connections
/ip firewall filter add chain=input connection-state=established action=accept
/ip firewall filter add chain=forward connection-state=established action=accept

# Allow related connections
/ip firewall filter add chain=input connection-state=related action=accept
/ip firewall filter add chain=forward connection-state=related action=accept
```

#### 2. Honeypot DMZ Rules

```mikrotik
# Allow SSH to Cowrie (port 2222)
/ip firewall filter add chain=forward dst-port=2222 protocol=tcp action=accept in-interface=eth1 out-interface=eth3 comment="Allow Cowrie SSH"

# Allow HTTP to honeypot (port 8080)
/ip firewall filter add chain=forward dst-port=8080 protocol=tcp action=accept in-interface=eth1 out-interface=eth3 comment="Allow HTTP Honeypot"

# Allow dashboard access (port 8000) from management network only
/ip firewall filter add chain=forward dst-port=8000 protocol=tcp src-address=192.168.10.0/24 action=accept in-interface=eth2 out-interface=eth3 comment="Allow Dashboard from Production"

# Block all other inbound to honeypot DMZ
/ip firewall filter add chain=forward in-interface=eth1 out-interface=eth3 action=drop comment="Block other inbound to DMZ"
```

#### 3. Outbound Restrictions

```mikrotik
# Block all outbound from honeypot DMZ
/ip firewall filter add chain=forward in-interface=eth3 out-interface=eth1 action=drop comment="Block outbound from DMZ"

# Allow DNS from honeypot (optional, for name resolution)
/ip firewall filter add chain=forward dst-port=53 protocol=udp in-interface=eth3 out-interface=eth1 action=accept comment="Allow DNS from DMZ"

# Allow specific outbound for testing (remove in production)
/ip firewall filter add chain=forward dst-address=192.168.1.0/24 in-interface=eth3 out-interface=eth1 action=accept comment="Allow local network access for testing"
```

#### 4. Rate Limiting

```mikrotik
# Rate limit connections to honeypot
/ip firewall filter add chain=forward in-interface=eth1 connection-limit=100,32 action=jump jump-target=honeypot-limit comment="Rate limit honeypot connections"

/ip firewall filter add chain=honeypot-limit action=add-src-to-address-list address-list=honeypot-blocked address-list-timeout=1d comment="Add to blocked list"

/ip firewall filter add chain=honeypot-limit src-address-list=honeypot-blocked action=drop comment="Drop blocked IPs"
```

### NAT Configuration

```mikrotik
# NAT for honeypot DMZ (if needed for outbound)
/ip firewall nat add chain=srcnat out-interface=eth1 src-address=192.168.50.0/24 action=masquerade comment="NAT for honeypot DMZ"

# Port forwarding to honeypot services
/ip firewall nat add chain=dstnat dst-port=2222 protocol=tcp in-interface=eth1 action=dst-nat to-addresses=192.168.50.100 to-ports=2222 comment="Forward Cowrie SSH"

/ip firewall nat add chain=dstnat dst-port=8080 protocol=tcp in-interface=eth1 action=dst-nat to-addresses=192.168.50.100 to-ports=8080 comment="Forward HTTP Honeypot"
```

### Logging Configuration

```mikrotik
# Enable firewall logging
/ip firewall filter add chain=forward action=log log-prefix="FW: " comment="Log forwarded packets"

# Configure logging
/system logging set 0 topics=firewall action=memory
/system logging add topics=firewall action=remote remote=192.168.10.10:514

# Log honeypot connections
/ip firewall filter add chain=forward dst-port=2222 protocol=tcp action=log log-prefix="COWRIE: " comment="Log Cowrie connections"
/ip firewall filter add chain=forward dst-port=8080 protocol=tcp action=log log-prefix="HTTPHP: " comment="Log HTTP Honeypot connections"
```

## Security Hardening

### 1. Management Access

```mikrotik
# Restrict management access
/ip firewall filter add chain=input dst-port=22 protocol=tcp src-address=192.168.10.0/24 action=accept comment="Allow SSH from production"
/ip firewall filter add chain=input dst-port=22 protocol=tcp action=drop comment="Block SSH from elsewhere"

# Winbox/HTTP access (restrict similarly)
/ip firewall filter add chain=input dst-port=8291 protocol=tcp src-address=192.168.10.0/24 action=accept comment="Allow Winbox from production"
/ip firewall filter add chain=input dst-port=80 protocol=tcp src-address=192.168.10.0/24 action=accept comment="Allow HTTP from production"
```

### 2. Monitoring and Alerting

```mikrotik
# Set up email alerts for blocked IPs
/tool e-mail set server=smtp.example.com from=mikrotik@example.com

# Script to check for blocked IPs
/system script add name="check-blocked" source={
  :local blocked [ip firewall address-list find list=honeypot-blocked]
  :if ([:len $blocked] > 0) do={
    /tool e-mail send to="admin@example.com" subject="Honeypot Blocked IPs" body="Blocked IPs: $blocked"
  }
}

# Schedule script check
/system scheduler add name="check-blocked-schedule" interval=1h on-event=check-blocked
```

### 3. Bandwidth Limiting

```mikrotik
# Limit bandwidth to honeypot
/queue simple add name=honeypot-limit target=192.168.50.0/24 max-limit=10M/10M comment="Limit honeypot bandwidth"
```

## Monitoring and Maintenance

### 1. Traffic Monitoring

```mikrotik
# Monitor traffic to honeypot
/tool torch interface=eth3

# Check connection table
/ip firewall connection print where dst-address=192.168.50.0/24

# Monitor firewall hits
/ip firewall filter print stats
```

### 2. Log Analysis

```mikrotik
# View firewall logs
/log print where topics~"firewall"

# Export logs
/log export file-name=firewall-logs
```

### 3. Regular Maintenance

```mikrotik
# Clear old address list entries
/ip firewall address-list remove [find where list=honeypot-blocked and creation-time < ([:tme] - 7d)]

# Backup configuration
/export file-name=mikrotik-backup
```

## Validation

### Test Connectivity

```bash
# Test Cowrie from external network
ssh -p 2222 test@<public-ip>

# Test HTTP honeypot
curl http://<public-ip>:8080

# Test dashboard from production network
curl http://192.168.50.100:8000
```

### Test Firewall Rules

```mikrotik
# Test packet flow
/tool ping 192.168.50.100 src-address=192.168.1.100

# Check NAT rules
/ip firewall nat print
```

### Test Rate Limiting

```bash
# Generate high connection rate
for i in {1..200}; do ssh -p 2222 test@<honeypot-ip>; done

# Check if IP gets blocked
# Check MikroTik address list
```

## Troubleshooting

### Common Issues

**Problem**: Honeypot not accessible from external network
- **Solution**: Check NAT rules
- **Solution**: Verify firewall forward rules
- **Solution**: Check interface status

**Problem**: Outbound connections from honeypot not blocked
- **Solution**: Verify outbound blocking rules
- **Solution**: Check rule order (specific before general)
- **Solution**: Test with specific IP addresses

**Problem**: Rate limiting not working
- **Solution**: Check connection-limit syntax
- **Solution**: Verify address-list creation
- **Solution**: Monitor firewall statistics

## Security Best Practices

1. **Regular Updates**: Keep RouterOS updated
2. **Strong Passwords**: Use complex passwords for management
3. **Management Access**: Restrict to specific networks
4. **Logging**: Enable comprehensive logging
5. **Monitoring**: Regular traffic and connection monitoring
6. **Backups**: Regular configuration backups
7. **Testing**: Test rules in non-production environment first

## Advanced Configuration

### GeoIP Blocking

```mikrotik
# Requires GeoIP database
/ip firewall filter add chain=forward src-address-list=malicious_countries action=drop comment="Block malicious countries"
```

### DDoS Protection

```mikrotik
# Enable SYN flood protection
/ip settings set syn-flood-limit=200

# Add SYN flood detection
/ip firewall filter add chain=forward protocol=tcp connection-limit=100,32 action=add-src-to-address-list address-list=syn-flood
```

### Advanced Logging

```mikrotik
# Send logs to external syslog server
/system logging add action=remote remote=192.168.10.10:514 target=remote
/system logging add topics=firewall action=remote
```

## Additional Resources

- [MikroTik Documentation](https://wiki.mikrotik.com/wiki/Main_Page)
- [RouterOS Firewall Guide](https://wiki.mikrotik.com/wiki/Manual:IP/Firewall)
- [MikroTik Forums](https://forum.mikrotik.com/)