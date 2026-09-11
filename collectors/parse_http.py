"""
HTTP honeypot log parser for the Dynamic Honeypot Platform.
Parses HTTP honeypot logs and converts them to standardized event format.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from utils.logger import get_logger


@dataclass
class HTTPEvent:
    """Standardized HTTP event structure."""
    timestamp: str
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    method: str
    path: str
    status_code: int
    user_agent: str
    event_type: str
    post_data: Optional[Dict[str, Any]] = None
    headers: Optional[Dict[str, str]] = None
    raw_event: Optional[str] = None
    additional_data: Optional[Dict[str, Any]] = None


class HTTPParser:
    """Parser for HTTP honeypot logs."""
    
    def __init__(self, log_path: str):
        """
        Initialize HTTP parser.
        
        Args:
            log_path: Path to HTTP log file
        """
        self.log_path = Path(log_path)
        self.logger = get_logger("HTTPParser")
        self.event_count = 0
        self.error_count = 0
    
    def parse_file(self) -> List[HTTPEvent]:
        """
        Parse entire HTTP log file.
        
        Returns:
            List of HTTPEvent objects
        """
        events = []
        
        if not self.log_path.exists():
            self.logger.error(f"Log file not found: {self.log_path}")
            return events
        
        try:
            with open(self.log_path, 'r', encoding='utf-8') as f:
                for line in f:
                    event = self.parse_line(line.strip())
                    if event:
                        events.append(event)
                        self.event_count += 1
                    else:
                        self.error_count += 1
            
            self.logger.info(
                f"Parsed {self.event_count} events from {self.log_path}",
                errors=self.error_count
            )
            
        except Exception as e:
            self.logger.error(f"Error parsing file: {e}")
        
        return events
    
    def parse_line(self, line: str) -> Optional[HTTPEvent]:
        """
        Parse a single log line.
        
        Args:
            line: Single log line (JSON format)
            
        Returns:
            HTTPEvent object or None if parsing fails
        """
        if not line:
            return None
        
        try:
            data = json.loads(line)
            return self._parse_event_data(data)
        except json.JSONDecodeError as e:
            self.logger.debug(f"JSON decode error: {e}")
            return None
        except Exception as e:
            self.logger.debug(f"Parse error: {e}")
            return None
    
    def _parse_event_data(self, data: Dict[str, Any]) -> Optional[HTTPEvent]:
        """
        Parse HTTP event data dictionary.
        
        Args:
            data: Event data dictionary
            
        Returns:
            HTTPEvent object
        """
        # Extract common fields
        timestamp = data.get('timestamp', '')
        source_ip = data.get('source_ip', '')
        source_port = data.get('source_port', 0)
        destination_ip = data.get('destination_ip', '')
        destination_port = data.get('destination_port', 0)
        method = data.get('method', 'GET')
        path = data.get('path', '/')
        status_code = data.get('status', 200)
        user_agent = data.get('user_agent', '')
        
        # Determine event type based on path and method
        event_type = self._determine_event_type(method, path, status_code)
        
        return HTTPEvent(
            timestamp=timestamp,
            source_ip=source_ip,
            source_port=source_port,
            destination_ip=destination_ip,
            destination_port=destination_port,
            method=method,
            path=path,
            status_code=status_code,
            user_agent=user_agent,
            event_type=event_type,
            post_data=data.get('post_data'),
            headers=data.get('headers'),
            raw_event=json.dumps(data),
            additional_data=data
        )
    
    def _determine_event_type(self, method: str, path: str, status_code: int) -> str:
        """
        Determine event type based on request characteristics.
        
        Args:
            method: HTTP method
            path: Request path
            status_code: HTTP status code
            
        Returns:
            Event type string
        """
        # Check for SQL injection patterns
        sql_injection_patterns = [
            r"' OR '1'='1",
            r"UNION SELECT",
            r"DROP TABLE",
            r"1=1",
            r"sleep\(",
            r"benchmark\("
        ]
        
        for pattern in sql_injection_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                return 'sql_injection_attempt'
        
        # Check for admin panel access
        if 'admin' in path.lower() or 'login' in path.lower():
            return 'admin_panel_access'
        
        # Check for sensitive file access
        sensitive_files = ['.env', 'config.php', 'database.yml', 'password', 'secret']
        for sensitive_file in sensitive_files:
            if sensitive_file in path.lower():
                return 'sensitive_file_access'
        
        # Check for vulnerability scanning
        scan_patterns = ['wp-content', 'phpmyadmin', 'admin', 'login', 'test']
        scan_count = sum(1 for pattern in scan_patterns if pattern in path.lower())
        if scan_count >= 2:
            return 'vulnerability_scan'
        
        # Check for web shell upload attempts
        if method == 'POST' and any(ext in path for ext in ['.php', '.jsp', '.asp']):
            return 'web_shell_upload'
        
        # Default classification
        if method == 'GET':
            return 'http_get'
        elif method == 'POST':
            return 'http_post'
        else:
            return f'http_{method.lower()}'
    
    def get_statistics(self) -> Dict[str, int]:
        """
        Get parsing statistics.
        
        Returns:
            Dictionary with statistics
        """
        return {
            'total_events': self.event_count,
            'error_count': self.error_count,
            'success_rate': (
                (self.event_count / (self.event_count + self.error_count) * 100)
                if (self.event_count + self.error_count) > 0 else 0
            )
        }
    
    def get_events_by_type(self, events: List[HTTPEvent]) -> Dict[str, int]:
        """
        Count events by type.
        
        Args:
            events: List of HTTPEvent objects
            
        Returns:
            Dictionary with event type counts
        """
        type_counts = {}
        for event in events:
            event_type = event.event_type
            type_counts[event_type] = type_counts.get(event_type, 0) + 1
        return type_counts
    
    def get_events_by_ip(self, events: List[HTTPEvent]) -> Dict[str, int]:
        """
        Count events by source IP.
        
        Args:
            events: List of HTTPEvent objects
            
        Returns:
            Dictionary with IP event counts
        """
        ip_counts = {}
        for event in events:
            ip = event.source_ip
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
        return ip_counts
    
    def detect_sql_injection(self, events: List[HTTPEvent]) -> List[HTTPEvent]:
        """
        Filter events that match SQL injection patterns.
        
        Args:
            events: List of HTTPEvent objects
            
        Returns:
            List of events with SQL injection patterns
        """
        return [event for event in events if event.event_type == 'sql_injection_attempt']
    
    def detect_admin_access(self, events: List[HTTPEvent]) -> List[HTTPEvent]:
        """
        Filter events that access admin panels.
        
        Args:
            events: List of HTTPEvent objects
            
        Returns:
            List of admin panel access events
        """
        return [event for event in events if event.event_type == 'admin_panel_access']


def parse_http_log(log_path: str) -> List[HTTPEvent]:
    """
    Convenience function to parse HTTP log file.
    
    Args:
        log_path: Path to HTTP log file
        
    Returns:
        List of HTTPEvent objects
    """
    parser = HTTPParser(log_path)
    return parser.parse_file()


def event_to_dict(event: HTTPEvent) -> Dict[str, Any]:
    """
    Convert HTTPEvent to dictionary.
    
    Args:
        event: HTTPEvent object
        
    Returns:
        Dictionary representation
    """
    return asdict(event)