# System Architecture

## Overview

The Dynamic Honeypot Platform is a comprehensive cybersecurity research system designed for proactive threat detection using dynamic honeypots and MITRE ATT&CK framework integration.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Network Layer                            │
│                   (MikroTik Firewall)                        │
│  - Network Segmentation                                    │
│  - Traffic Filtering                                        │
│  - Access Control                                          │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│                  Honeypot Services Layer                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Cowrie     │  │ HTTP Honeypot│  │ Future: FTP  │      │
│  │   SSH/Telnet │  │   Port 8080  │  │   Services    │      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘      │
└─────────┼────────────────┼─────────────────┼────────────────┘
          │                │                 │
          └────────────────┼─────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                  Event Collection Layer                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Log Collector│  │  Cowrie      │  │  HTTP        │      │
│  │  Orchestrator │  │  Parser      │  │  Parser      │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                  Event Normalization Layer                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Normalizer   │  │  JSON Export │  │  CSV Export  │      │
│  │  Standardized│  │  Database    │  │  Files       │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                  Analysis Layer                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ MITRE Mapper │  │ Detection    │  │ Correlation  │      │
│  │  ATT&CK     │  │  Engine      │  │  Engine      │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                  Deception Layer                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Decoy        │  │ Orchestrator │  │ Profile      │      │
│  │  Generator  │  │  Dynamic     │  │  Manager     │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                  Presentation Layer                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Dashboard    │  │ Alerting     │  │ Reporting    │      │
│  │  Web UI     │  │  System      │  │  System      │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. Honeypot Services

#### Cowrie (SSH/Telnet)
- **Purpose**: SSH and Telnet honeypot
- **Integration**: Read-only log parsing
- **Output**: JSON format logs
- **Key Features**: 
  - Credential attack capture
  - Command execution logging
  - File download tracking

#### HTTP Honeypot
- **Purpose**: Web-based attack observation
- **Implementation**: Custom Flask/FastAPI service
- **Key Features**:
  - SQL injection detection
  - Vulnerability scanning detection
  - Admin panel access tracking

### 2. Event Collection

#### Log Collector
- **Purpose**: Orchestrate log collection from multiple sources
- **Key Functions**:
  - Scheduled log collection
  - Multi-source aggregation
  - Error handling and retry logic

#### Parsers
- **Cowrie Parser**: JSON log parsing with event type classification
- **HTTP Parser**: Web request parsing with attack pattern detection
- **Extensibility**: Plugin architecture for additional parsers

### 3. Event Normalization

#### Normalizer
- **Purpose**: Convert diverse event formats to standard structure
- **Standard Format**:
  ```json
  {
    "timestamp": "ISO 8601",
    "source_ip": "string",
    "service": "ssh|http|ftp",
    "event_type": "string",
    "session_id": "string",
    "raw_event": "original_data"
  }
  ```

#### Export System
- **JSON Export**: Structured data with metadata
- **CSV Export**: Flattened tabular data
- **Database Export**: PostgreSQL storage

### 4. Analysis Layer

#### MITRE ATT&CK Mapper
- **Purpose**: Map events to MITRE techniques
- **Key Features**:
  - Confidence scoring
  - Tactic classification
  - Technique candidate ranking
  - Traceable justification

#### Detection Engine
- **Purpose**: Apply detection rules to events
- **Key Features**:
  - Rule-based detection
  - Pattern matching
  - Sequence detection
  - Alert generation

#### Correlation Engine
- **Purpose**: Identify related events
- **Correlation Types**:
  - Source IP correlation
  - Session correlation
  - Attack sequence correlation
  - Time-based correlation

### 5. Deception Layer

#### Decoy Generator
- **Purpose**: Create fake files and credentials
- **Generation Types**:
  - Fake users and passwords
  - Configuration files
  - Database files
  - Web files
  - Directory structures

#### Orchestrator
- **Purpose**: Adapt deception based on attacker behavior
- **Adaptation Triggers**:
  - Repeated failed authentication
  - Reconnaissance commands
  - File downloads
  - Privilege escalation attempts

#### Profile Manager
- **Purpose**: Manage deception profiles
- **Profiles**:
  - PROFILE_LOW: Minimal deception
  - PROFILE_RECON: Enhanced for reconnaissance
  - PROFILE_CREDENTIAL: Credential-focused
  - PROFILE_WEB: Web/API focused
  - PROFILE_HIGH_INTERACTION: Rich interaction

### 6. Presentation Layer

#### Dashboard
- **Technology**: Flask web application
- **Key Features**:
  - Real-time event monitoring
  - MITRE ATT&CK visualization
  - Alert management
  - Session analysis
  - Deception management

#### Alerting System
- **Alert Levels**: Critical, High, Medium, Low, Info
- **Delivery Methods**: Dashboard, email (future), syslog (future)
- **Alert Content**: Event details, confidence, recommended actions

## Data Flow

### Event Processing Pipeline

```
Raw Log → Parser → Normalizer → Analyzer → Mapper → Detector → Alerter
   ↓         ↓          ↓          ↓         ↓         ↓         ↓
 JSON   Standard    JSON/CSV   MITRE    Rules    Alert    Dashboard
Format   Event      Export    Map     Apply   Generate Display
```

### Dynamic Adaptation Flow

```
Attacker Activity → Event Collection → Analysis → 
Trigger Detection → Profile Selection → Decoy Generation → 
Deployment → New Observation
```

## Technology Stack

### Core Technologies
- **Language**: Python 3.9+
- **Web Framework**: Flask
- **Database**: PostgreSQL
- **Containerization**: Docker/Docker Compose
- **Task Scheduling**: Python schedule library

### Key Libraries
- **Data Processing**: pandas, jsonschema
- **Configuration**: pyyaml, python-dotenv
- **MITRE ATT&CK**: mitreattack-python
- **Logging**: structlog
- **Date/Time**: python-dateutil, pytz

### Deployment
- **Development**: Windows + Docker Desktop
- **Production**: Linux + Systemd/Docker
- **Network**: MikroTik firewall

## Security Architecture

### Network Isolation
- **DMZ/VLAN**: Separate honeypot network
- **Firewall Rules**: Restricted inbound/outbound
- **Traffic Monitoring**: Network-level logging

### Data Protection
- **No Real Credentials**: All decoys are fictional
- **Environment Variables**: Secrets in .env files
- **Access Control**: File permissions and user groups
- **Audit Logging**: All actions logged

### Process Isolation
- **Containerization**: Docker containers for services
- **Least Privilege**: Non-root user execution
- **Resource Limits**: CPU/memory constraints

## Scalability Considerations

### Horizontal Scaling
- **Multiple Honeypots**: Add more honeypot instances
- **Distributed Collection**: Multiple collectors
- **Load Balancing**: Distribute dashboard requests

### Vertical Scaling
- **Resource Allocation**: Increase CPU/memory
- **Database Optimization**: Indexing, partitioning
- **Caching**: Redis for frequently accessed data

### Performance Optimization
- **Batch Processing**: Process events in batches
- **Async Operations**: Asynchronous I/O where possible
- **Log Rotation**: Prevent disk space issues

## Monitoring and Observability

### Application Monitoring
- **Health Checks**: Service health endpoints
- **Performance Metrics**: Response times, throughput
- **Error Tracking**: Exception logging and alerting

### System Monitoring
- **Resource Usage**: CPU, memory, disk, network
- **Service Status**: Process monitoring
- **Log Aggregation**: Centralized log collection

### Business Metrics
- **Detection Rate**: Alert effectiveness
- **False Positive Rate**: Alert accuracy
- **MITRE Coverage**: Technique mapping coverage

## Extension Points

### Adding New Honeypot Services
1. Create parser in `collectors/`
2. Add to log collector
3. Create sample logs
4. Add tests
5. Update configuration

### Adding New Detection Rules
1. Edit `config/detection_rules.yaml`
2. Test with sample events
3. Add tests
4. Deploy and monitor

### Adding New MITRE Mappings
1. Edit `config/mitre_attack_mapping.json`
2. Test with sample events
3. Validate confidence scoring
4. Update documentation

### Adding New Deception Profiles
1. Edit `config/honeypot_profiles.yaml`
2. Add profile configuration
3. Implement profile logic
4. Test adaptation triggers

## Integration Points

### External Systems
- **SIEM**: Syslog integration (future)
- **SOAR**: API integration (future)
- **Threat Intelligence**: Integration with threat feeds (future)
- **CMDB**: Asset management integration (future)

### APIs
- **REST API**: Dashboard data access
- **Webhooks**: Alert notifications (future)
- **GraphQL**: Complex queries (future)

## Failure Modes and Recovery

### Component Failures
- **Parser Failure**: Skip event, log error, continue
- **Database Failure**: Queue events, retry connection
- **Network Failure**: Buffer events, retry later
- **Service Failure**: Automatic restart via systemd

### Data Recovery
- **Database Backups**: Regular automated backups
- **Log Backups**: Log rotation and archiving
- **Configuration Backups**: Version control
- **Disaster Recovery**: Restore from backups

## Compliance and Governance

### Data Retention
- **Event Logs**: Configurable retention period
- **Alerts**: Longer retention for analysis
- **Decoys**: Regenerated on profile change

### Audit Trail
- **All Actions**: Logged with timestamps
- **Configuration Changes**: Tracked and versioned
- **Access Logs**: User activity tracking

### Privacy Considerations
- **No Personal Data**: All data is fictional
- **IP Address Handling**: Consider privacy implications
- **Data Minimization**: Store only necessary data