# Windows Deployment Guide

This guide covers setting up and running the Dynamic Honeypot Platform on Windows for development purposes.

## Prerequisites

### Required Software

- **Windows 10/11** with Administrator privileges
- **Python 3.9+** - Download from [python.org](https://www.python.org/downloads/)
- **Git** - Download from [git-scm.com](https://git-scm.com/download/win)
- **Docker Desktop** - Download from [docker.com](https://www.docker.com/products/docker-desktop)
- **VS Code** (recommended) - Download from [code.visualstudio.com](https://code.visualstudio.com/)

### Optional Software

- **PostgreSQL** (if not using Docker)
- **Redis** (if not using Docker)

## Installation Steps

### 1. Clone the Repository

```powershell
git clone <repository-url>
cd dynamic-honeypot
```

### 2. Install Python Dependencies

```powershell
# Create virtual environment
python -m venv venv

# Activate virtual environment
.\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### 3. Configure Environment Variables

```powershell
# Copy example environment file
copy .env.example .env

# Edit .env with your settings
notepad .env
```

**Required settings in `.env`:**
```
DB_PASSWORD=your_secure_password
DJANGO_SECRET_KEY=your_secret_key_here
```

### 4. Start Docker Services

```powershell
# Start development environment
docker-compose -f docker-compose.dev.yml up -d

# Check service status
docker-compose -f docker-compose.dev.yml ps
```

### 5. Initialize Database

```powershell
# Run Django migrations (if using Django)
python manage.py migrate

# Create superuser (optional)
python manage.py createsuperuser
```

## Development Workflow

### Running Components Individually

#### Log Collector

```powershell
python collectors/log_collector.py
```

#### Detection Engine

```powershell
python detection/detection_engine.py
```

#### MITRE Mapper

```powershell
python mitre/mitre_mapper.py
```

#### Dashboard (Flask)

```powershell
python dashboard/app_flask.py
```

Access dashboard at: `http://localhost:8000`

### Running Complete Stack

```powershell
# Start all services
docker-compose -f docker-compose.dev.yml up

# Start in background
docker-compose -f docker-compose.dev.yml up -d

# View logs
docker-compose -f docker-compose.dev.yml logs -f
```

## Testing

### Run Unit Tests

```powershell
# Activate virtual environment
.\venv\Scripts\activate

# Run all tests
pytest tests/

# Run specific test file
pytest tests/test_parsers.py

# Run with coverage
pytest tests/ --cov=. --cov-report=html
```

### Run Test Scenarios

```powershell
# Scenario 1: SSH Connection
python tests/test_scenarios/scenario_ssh_connection.py

# Scenario 2: Command Execution
python tests/test_scenarios/scenario_commands.py

# Scenario 3: File Interaction
python tests/test_scenarios/scenario_file_interaction.py

# Scenario 4: Event Sequence
python tests/test_scenarios/scenario_event_sequence.py

# Scenario 5: Adaptation
python tests/test_scenarios/scenario_adaptation.py
```

## Configuration

### File Locations

- **Configuration**: `config/`
- **Sample Logs**: `collectors/sample_logs/`
- **Generated Decoys**: `data/generated_decoys/`
- **Event Data**: `data/events/`
- **Database**: `data/honeypot.db` (SQLite)

### Key Configuration Files

- `config/settings.yaml` - Main settings
- `config/honeypot_profiles.yaml` - Deception profiles
- `config/mitre_attack_mapping.json` - MITRE mappings
- `config/detection_rules.yaml` - Detection rules

### Windows-Specific Settings

In `config/settings.yaml`, ensure:
```yaml
environment: development
platform: windows
```

## Troubleshooting

### Docker Issues

**Problem**: Docker Desktop won't start
- **Solution**: Ensure WSL 2 is installed and enabled
- **Solution**: Check Docker Desktop system requirements

**Problem**: Containers can't access host files
- **Solution**: Check Docker Desktop file sharing settings
- **Solution**: Ensure project directory is in shared location

### Python Issues

**Problem**: Module not found errors
- **Solution**: Ensure virtual environment is activated
- **Solution**: Run `pip install -r requirements.txt` again

**Problem**: Permission errors
- **Solution**: Run PowerShell as Administrator
- **Solution**: Check file permissions on project directory

### Database Issues

**Problem**: Database connection errors
- **Solution**: Ensure PostgreSQL container is running
- **Solution**: Check database credentials in `.env`

### Path Issues

**Problem**: File path errors on Windows
- **Solution**: Use forward slashes in configuration files
- **Solution**: Use raw strings for Windows paths in Python

## Development Tips

### VS Code Setup

1. Install Python extension
2. Install Docker extension
3. Set Python interpreter to project virtual environment
4. Configure workspace settings

### Code Formatting

```powershell
# Format code with Black
black .

# Sort imports with isort
isort .

# Lint with flake8
flake8 .
```

### Debugging

```powershell
# Run with Python debugger
python -m pdb collectors/log_collector.py

# Use VS Code debugger
# Set breakpoints in VS Code and press F5
```

## Performance Considerations

### Docker Resource Limits

Docker Desktop on Windows may have resource limits. Adjust in Docker Desktop settings:
- Increase memory allocation (recommended: 4GB+)
- Increase CPU allocation (recommended: 2+ cores)

### File System Performance

Windows file system performance with Docker can be slower. Consider:
- Using WSL 2 backend
- Placing project in WSL file system
- Minimizing file watch operations

## Security Considerations for Development

### Local Development Security

- **Never commit** `.env` file or real credentials
- **Use strong passwords** in development environment
- **Keep Docker updated** to latest version
- **Firewall** - Docker may modify Windows Firewall rules

### Data Isolation

- Development data is in `data/` directory
- Regularly clean up old logs and events
- Database can be reset by deleting `data/honeypot.db`

## Common Development Tasks

### Adding New Parsers

1. Create parser in `collectors/`
2. Add to `log_collector.py`
3. Create sample logs in `collectors/sample_logs/`
4. Add tests in `tests/test_parsers.py`

### Adding New Detection Rules

1. Edit `config/detection_rules.yaml`
2. Test with sample events
3. Add tests in `tests/test_detection.py`

### Adding MITRE Mappings

1. Edit `config/mitre_attack_mapping.json`
2. Test with sample events
3. Add tests in `tests/test_mapping.py`

### Adding Dashboard Pages

1. Create template in `dashboard/templates/`
2. Add route in `dashboard/app_flask.py`
3. Test in browser

## Backup and Restore

### Backup Development Data

```powershell
# Backup database
copy data\honeypot.db data\honeypot.db.backup

# Backup configuration
copy config\ config_backup\ /E
```

### Restore Development Data

```powershell
# Restore database
copy data\honeypot.db.backup data\honeypot.db

# Restore configuration
copy config_backup\ config\ /E
```

## Next Steps

After completing Windows development setup:

1. Test all components individually
2. Run test scenarios to verify functionality
3. Review generated data in `data/` directory
4. Prepare for Linux deployment (see `deployment-linux.md`)

## Additional Resources

- [Docker Desktop Documentation](https://docs.docker.com/desktop/)
- [Python on Windows Documentation](https://docs.python.org/3/using/windows.html)
- [Git for Windows Guide](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git)
- [VS Code Python Documentation](https://code.visualstudio.com/docs/python/python-tutorial)