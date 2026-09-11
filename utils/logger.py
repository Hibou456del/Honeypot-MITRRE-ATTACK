"""
Logging configuration for the Dynamic Honeypot Platform.
Provides structured logging with JSON format support.
"""

import logging
import logging.config
import sys
from pathlib import Path
from typing import Optional
import json
from datetime import datetime


class HoneypotLogger:
    """Centralized logger for honeypot components."""
    
    def __init__(self, name: str, config: Optional[dict] = None):
        """
        Initialize logger with optional configuration.
        
        Args:
            name: Logger name (usually module name)
            config: Optional logging configuration dictionary
        """
        self.logger = logging.getLogger(name)
        self._setup_logger(config)
    
    def _setup_logger(self, config: Optional[dict] = None):
        """Setup logger with console and file handlers."""
        if config:
            logging.config.dictConfig(config)
        else:
            # Default configuration
            self.logger.setLevel(logging.INFO)
            
            # Console handler
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(logging.INFO)
            
            # File handler
            log_dir = Path("logs")
            log_dir.mkdir(exist_ok=True)
            file_handler = logging.FileHandler(
                log_dir / "honeypot.log",
                encoding='utf-8'
            )
            file_handler.setLevel(logging.DEBUG)
            
            # Formatter
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            console_handler.setFormatter(formatter)
            file_handler.setFormatter(formatter)
            
            self.logger.addHandler(console_handler)
            self.logger.addHandler(file_handler)
    
    def info(self, message: str, **kwargs):
        """Log info message with optional structured data."""
        if kwargs:
            self.logger.info(f"{message} - {json.dumps(kwargs)}")
        else:
            self.logger.info(message)
    
    def debug(self, message: str, **kwargs):
        """Log debug message with optional structured data."""
        if kwargs:
            self.logger.debug(f"{message} - {json.dumps(kwargs)}")
        else:
            self.logger.debug(message)
    
    def warning(self, message: str, **kwargs):
        """Log warning message with optional structured data."""
        if kwargs:
            self.logger.warning(f"{message} - {json.dumps(kwargs)}")
        else:
            self.logger.warning(message)
    
    def error(self, message: str, **kwargs):
        """Log error message with optional structured data."""
        if kwargs:
            self.logger.error(f"{message} - {json.dumps(kwargs)}")
        else:
            self.logger.error(message)
    
    def critical(self, message: str, **kwargs):
        """Log critical message with optional structured data."""
        if kwargs:
            self.logger.critical(f"{message} - {json.dumps(kwargs)}")
        else:
            self.logger.critical(message)


def get_logger(name: str, config: Optional[dict] = None) -> HoneypotLogger:
    """
    Get or create a logger instance.
    
    Args:
        name: Logger name
        config: Optional logging configuration
        
    Returns:
        HoneypotLogger instance
    """
    return HoneypotLogger(name, config)


class StructuredLogger:
    """Logger for structured JSON output."""
    
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        
        # Console handler with JSON formatter
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
        self.logger.addHandler(handler)
    
    def log(self, level: str, message: str, **kwargs):
        """Log structured message."""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": level,
            "logger": self.logger.name,
            "message": message,
            **kwargs
        }
        self.logger.info(json.dumps(log_entry))


class JsonFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""
    
    def format(self, record):
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage()
        }
        
        # Add extra fields if present
        if hasattr(record, 'extra_fields'):
            log_entry.update(record.extra_fields)
        
        return json.dumps(log_entry)