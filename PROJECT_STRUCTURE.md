# Dynamic Honeypot Platform - File Structure

## Root Directory Structure

```
dynamic-honeypot/
├── docker-compose.yml              # Main Docker orchestration
├── docker-compose.dev.yml          # Development mode (Windows)
├── docker-compose.prod.yml        # Production mode (Linux)
├── .env.example                   # Environment variables template
├── .gitignore                     # Git ignore rules
├── README.md                      # Project overview
├── requirements.txt               # Python dependencies
├── requirements-dev.txt           # Development dependencies
├── LICENSE                        # License file
│
├── config/                        # Configuration files
│   ├── settings.yaml              # Main settings (paths, modes)
│   ├── honeypot_profiles.yaml     # Decoy profile definitions
│   ├── mitre_attack_mapping.json  # MITRE ATT&CK mapping rules
│   ├── detection_rules.yaml       # Detection engine rules
│   └── cowrie_config.yaml         # Cowrie integration settings
│
├── honeypot/                      # Core honeypot components
│   ├── __init__.py
│   ├── create_dynamic_files.py    # Decoy file generator
│   ├── update_honeypot.py         # Dynamic orchestrator
│   ├── profiles/                  # Decoy profile definitions
│   │   ├── __init__.py
│   │   ├── base.py                # Base profile class
│   │   ├── low.py                 # PROFILE_LOW
│   │   ├── recon.py               # PROFILE_RECON
│   │   ├── credential.py          # PROFILE_CREDENTIAL
│   │   ├── web.py                 # PROFILE_WEB
│   │   └── high_interaction.py    # PROFILE_HIGH_INTERACTION
│   └── decoy_templates/           # Template files for decoys
│       ├── fake_config.php
│       ├── fake_database.sql
│       ├── fake_env_file
│       └── fake_nginx.conf
│
├── collectors/                    # Log collection and parsing
│   ├── __init__.py
│   ├── log_collector.py          # Main log collection orchestrator
│   ├── parse_cowrie.py           # Cowrie log parser
│   ├── parse_http.py             # HTTP honeypot parser
│   ├── normalize_events.py       # Event normalization to JSON/CSV
│   ├── export_events.py          # Export to various formats
│   └── sample_logs/              # Sample logs for testing
│       ├── cowrie_sample.log
│       └── http_sample.log
│
├── detection/                     # Detection engine
│   ├── __init__.py
│   ├── detection_engine.py       # Main detection logic
│   ├── rules.py                  # Detection rules definitions
│   ├── alerts.py                 # Alert generation and management
│   └── correlation.py            # Event correlation logic
│
├── mitre/                         # MITRE ATT&CK integration
│   ├── __init__.py
│   ├── mitre_mapper.py           # Main mapping engine
│   ├── mapping_loader.py         # Load and validate mappings
│   ├── techniques.py             # Technique definitions
│   └── confidence_calculator.py  # Confidence scoring
│
├── dashboard/                     # Web dashboard
│   ├── __init__.py
│   ├── app.py                    # Main application (Django/FastAPI)
│   ├── models.py                 # Database models
│   ├── views.py                  # API endpoints
│   ├── serializers.py            # Data serializers
│   ├── templates/                # HTML templates
│   │   ├── base.html
│   │   ├── dashboard.html
│   │   ├── events.html
│   │   ├── sessions.html
│   │   ├── mitre.html
│   │   └── decoys.html
│   ├── static/                   # CSS, JS, images
│   │   ├── css/
│   │   ├── js/
│   │   └── img/
│   └── urls.py                   # URL routing
│
├── database/                      # Database setup
│   ├── __init__.py
│   ├── migrations/               # Database migrations
│   ├── seed_data.py              # Initial data seeding
│   └── backup/                   # Database backups
│
├── tests/                         # Test suite
│   ├── __init__.py
│   ├── test_parsers.py           # Parser tests
│   ├── test_normalization.py     # Normalization tests
│   ├── test_mapping.py           # MITRE mapping tests
│   ├── test_detection.py         # Detection engine tests
│   ├── test_deception.py         # Decoy generation tests
│   ├── test_orchestrator.py      # Orchestrator tests
│   ├── test_dashboard.py         # Dashboard tests
│   └── test_scenarios/           # Laboratory test scenarios
│       ├── scenario_ssh_connection.py
│       ├── scenario_commands.py
│       ├── scenario_file_interaction.py
│       ├── scenario_event_sequence.py
│       └── scenario_adaptation.py
│
├── data/                          # Runtime data
│   ├── sample_logs/              # Additional sample logs
│   ├── generated_decoys/         # Generated decoy files
│   ├── fake_users.json           # Generated fake users
│   ├── fake_credentials.json     # Generated fake credentials
│   ├── fake_documents/           # Generated fake documents
│   └── events/                   # Collected events
│       ├── raw/
│       ├── normalized/
│       └── exported/
│
├── scripts/                       # Utility scripts
│   ├── setup_dev_environment.py  # Development setup
│   ├── setup_linux_environment.py # Linux deployment setup
│   ├── backup_configuration.py   # Config backup
│   ├── validate_installation.py  # Installation validation
│   └── migrate_cowrie.py         # Cowrie migration helper
│
├── docs/                          # Documentation
│   ├── architecture.md            # System architecture
│   ├── api_documentation.md      # API documentation
│   ├── deployment-windows.md     # Windows deployment guide
│   ├── deployment-linux.md       # Linux deployment guide
│   ├── cowrie-integration.md     # Cowrie integration guide
│   ├── mikrotik-configuration.md  # MikroTik setup guide
│   ├── test-plan.md              # Testing methodology
│   ├── mitre-methodology.md      # MITRE mapping methodology
│   ├── security-considerations.md # Security guidelines
│   └── troubleshooting.md        # Common issues and solutions
│
└── utils/                         # Shared utilities
    ├── __init__.py
    ├── logger.py                 # Logging configuration
    ├── file_utils.py             # File operations
    ├── network_utils.py          # Network utilities
    ├── config_loader.py          # Configuration loading
    ├── date_utils.py             # Date/time utilities
    └── validation.py             # Input validation
```

## Key Design Principles

### 1. Module Interface Contracts

**Event Pipeline Flow:**
```
Raw Log → Parser → Normalized Event → Analyzer → MITRE Mapper → Detection Engine → Alert
```

**Standard Event Format:**
```json
{
  "timestamp": "2026-01-01T12:00:00Z",
  "source_ip": "X.X.X.X",
  "service": "ssh|http|ftp",
  "event_type": "command_execution|file_download|connection",
  "session_id": "SESSION_ID",
  "username": "fake_user",
  "command": "observed_command",
  "source": "cowrie|http_honeypot",
  "raw_event": "original_log_line"
}
```

### 2. Configuration Architecture

- **settings.yaml**: Environment-specific paths, modes, and global settings
- **honeypot_profiles.yaml**: Decoy profile definitions and transition rules
- **mitre_attack_mapping.json**: MITRE ATT&CK technique mappings with confidence
- **detection_rules.yaml**: Detection rule definitions and thresholds
- **cowrie_config.yaml**: Cowrie integration settings (paths, formats)

### 3. Windows/Linux Compatibility

**Path Handling:**
- Use `pathlib.Path` for cross-platform path operations
- Define path templates in configuration
- Abstract OS-specific operations in utils

**Docker Strategy:**
- Development mode: Full stack on Windows Docker Desktop
- Production mode: Cowrie on host, other services in containers
- Volume mounting for log access
- Network isolation via Docker networks

### 4. Security Isolation

**Network Isolation:**
- Docker network segmentation
- MikroTik firewall rules
- Restricted outbound connections

**Data Isolation:**
- No real credentials in any config
- All decoys generated as fictional data
- Sensitive paths in .gitignore
- Environment variables for secrets

**Process Isolation:**
- Containerized services
- Limited filesystem permissions
- Resource limits in Docker

### 5. Testing Strategy

**Unit Tests:**
- Parser logic with sample logs
- Normalization accuracy
- MITRE mapping correctness
- Detection rule evaluation

**Integration Tests:**
- End-to-end event pipeline
- Dashboard data flow
- Database operations

**Scenario Tests:**
- SSH connection scenario
- Command execution scenario
- File interaction scenario
- Event sequence scenario
- Adaptation trigger scenario

## Implementation Phases

### Phase 1: Foundation (Current)
- File structure creation
- Configuration templates
- Base utilities
- Docker setup

### Phase 2: Collection Pipeline
- Log collectors
- Parsers (Cowrie, HTTP)
- Normalization
- Export functionality

### Phase 3: Analysis Layer
- MITRE mapping engine
- Detection engine
- Alert generation

### Phase 4: Deception Layer
- Decoy generator
- Orchestrator
- Profile management

### Phase 5: Visualization
- Dashboard backend
- Frontend templates
- API endpoints

### Phase 6: Testing & Documentation
- Test suite
- Deployment guides
- Integration procedures

## Dependencies to Identify

**Python Core:**
- asyncio for async operations
- json/yaml for configuration
- pathlib for cross-platform paths
- logging for structured logging
- datetime for timestamps

**Data Processing:**
- pandas for data analysis
- csv/json for data export
- re for pattern matching

**Web Framework:**
- Django or FastAPI (to be decided based on complexity)
- Django REST Framework if Django chosen

**Database:**
- PostgreSQL adapter (psycopg2)
- SQLAlchemy for ORM (if not using Django ORM)

**MITRE ATT&CK:**
- MITRE ATT&CK Python library (mitreattack-python)
- Or custom parsing of STIX data

**Testing:**
- pytest for testing
- pytest-cov for coverage
- pytest-asyncio for async tests

**Docker:**
- docker-compose for orchestration
- Official Python image
- Official PostgreSQL image

## Next Steps

1. Create base directory structure
2. Initialize Git repository
3. Create configuration templates
4. Set up Docker Compose files
5. Implement base utilities
6. Create first parser (Cowrie) with sample data
