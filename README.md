# Dynamic Honeypot Platform with MITRE ATT&CK Mapping

A sophisticated cybersecurity research platform for proactive threat detection using dynamic honeypots and MITRE ATT&CK framework integration.

## Project Overview

This platform is designed for academic memory research and laboratory environments to:
- Deploy and manage dynamic honeypot services
- Collect and normalize security events
- Map attacker behaviors to MITRE ATT&CK techniques
- Adapt deception surfaces based on observed activities
- Provide comprehensive dashboards for threat analysis

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Network Layer                             │
│                   (MikroTik Firewall)                        │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│                  Honeypot Services                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                  │
│  │ Cowrie   │  │ HTTP     │  │ FTP/Other │                  │
│  │ SSH/Telnet│ │ Honeypot │  │ Services  │                  │
│  └─────┬────┘  └─────┬────┘  └─────┬────┘                  │
└────────┼────────────┼────────────┼──────────────────────────┘
         │            │            │
         └────────────┼────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                  Event Pipeline                              │
│  Collector → Parser → Normalizer → Analyzer → Mapper         │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                  Analysis Layer                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Detection    │  │ MITRE Mapping│  │ Deception   │      │
│  │ Engine       │  │ Engine       │  │ Orchestrator │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                  Presentation Layer                          │
│              Dashboard & Alerting                            │
└──────────────────────────────────────────────────────────────┘
```

## Key Features

### 1. Multi-Service Honeypots
- **Cowrie**: SSH/Telnet honeypot for credential attacks
- **HTTP Honeypot**: Web-based attack observation
- **Extensible Architecture**: Add FTP, API, and custom services

### 2. Dynamic Deception
- **Profile-Based**: Multiple deception profiles (LOW, RECON, CREDENTIAL, WEB, HIGH_INTERACTION)
- **Adaptive**: Automatically adjusts based on attacker behavior
- **Safe**: All decoys are fictional - no real credentials or data

### 3. MITRE ATT&CK Integration
- **Technique Mapping**: Maps events to ATT&CK techniques with confidence scores
- **Tactic Classification**: Groups techniques by tactics
- **Traceable**: Maintains justification and evidence for each mapping

### 4. Detection Engine
- **Rule-Based**: Configurable detection rules
- **Correlation**: Multi-event pattern detection
- **Alerting**: Severity-based alert generation

### 5. Comprehensive Dashboard
- **Real-time Monitoring**: Live event feeds
- **MITRE Visualization**: Tactic and technique views
- **Session Analysis**: Detailed session reconstruction
- **Deception Management**: Profile and decoy tracking

## Quick Start

### Prerequisites
- Docker and Docker Compose
- Python 3.9+
- Git

### Development Setup (Windows)

1. **Clone the repository**
```bash
git clone <repository-url>
cd dynamic-honeypot
```

2. **Create environment file**
```bash
cp .env.example .env
# Edit .env with your settings
```

3. **Start development environment**
```bash
docker-compose -f docker-compose.dev.yml up -d
```

4. **Access dashboard**
```
http://localhost:8000
```

### Production Deployment (Linux)

Detailed Linux deployment instructions are provided in `docs/deployment-linux.md`.

## Project Structure

```
dynamic-honeypot/
├── config/                 # Configuration files
├── honeypot/              # Deception components
├── collectors/            # Log collection and parsing
├── detection/             # Detection engine
├── mitre/                 # MITRE ATT&CK integration
├── dashboard/             # Web dashboard
├── database/              # Database setup
├── tests/                 # Test suite
├── data/                  # Runtime data
├── scripts/               # Utility scripts
├── docs/                  # Documentation
└── utils/                 # Shared utilities
```

## Security Considerations

⚠️ **Important Security Notes:**

- This platform is designed for isolated laboratory environments
- Never deploy in production networks without proper isolation
- All credentials and data in honeypots are fictional
- Network segmentation via MikroTik is required
- No real sensitive data should ever be placed in decoys
- Outbound connections from honeypot should be restricted

## Documentation

- [Architecture Documentation](docs/architecture.md)
- [Windows Deployment Guide](docs/deployment-windows.md)
- [Linux Deployment Guide](docs/deployment-linux.md)
- [Cowrie Integration](docs/cowrie-integration.md)
- [MikroTik Configuration](docs/mikrotik-configuration.md)
- [MITRE Methodology](docs/mitre-methodology.md)
- [Test Plan](docs/test-plan.md)

## Testing

Run the test suite:
```bash
pytest tests/
```

Run specific test scenarios:
```bash
pytest tests/test_scenarios/scenario_ssh_connection.py
```

## Contributing

This is an academic research project. Contributions should focus on:
- Improving detection accuracy
- Expanding MITRE ATT&CK coverage
- Enhancing deception capabilities
- Adding new honeypot services

## License

[License to be determined]

## Acknowledgments

- Cowrie SSH/Telnet Honeypot
- MITRE ATT&CK Framework
- Django Web Framework
- Docker and Docker Compose

## Disclaimer

This platform is for educational and research purposes only. The authors are not responsible for misuse of this software. Always ensure proper authorization before deploying honeypots in any environment.