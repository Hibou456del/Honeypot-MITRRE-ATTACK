"""
Cowrie log parser for the Dynamic Honeypot Platform.
Parses Cowrie JSON logs and converts them to standardized event format.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass, asdict
from utils.logger import get_logger
from utils.date_utils import DateUtils


@dataclass
class CowrieEvent:
    """Standardized Cowrie event structure."""
    timestamp: str
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    session_id: str
    event_type: str
    username: Optional[str] = None
    command: Optional[str] = None
    protocol: str = "ssh"
    raw_event: Optional[str] = None
    additional_data: Optional[Dict[str, Any]] = None


class CowrieParser:
    """Parser for Cowrie honeypot logs."""
    
    def __init__(self, log_path: str):
        """
        Initialize Cowrie parser.
        
        Args:
            log_path: Path to Cowrie log file
        """
        self.log_path = Path(log_path)
        self.logger = get_logger("CowrieParser")
        self.event_count = 0
        self.error_count = 0
    
    def parse_file(self) -> List[CowrieEvent]:
        """
        Parse entire Cowrie log file.
        
        Returns:
            List of CowrieEvent objects
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
    
    def parse_line(self, line: str) -> Optional[CowrieEvent]:
        """
        Parse a single log line.
        
        Args:
            line: Single log line (JSON format)
            
        Returns:
            CowrieEvent object or None if parsing fails
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
    
    def _parse_event_data(self, data: Dict[str, Any]) -> Optional[CowrieEvent]:
        """
        Parse Cowrie event data dictionary.
        
        Args:
            data: Event data dictionary
            
        Returns:
            CowrieEvent object
        """
        eventid = data.get('eventid', '')
        
        # Extract common fields
        timestamp = data.get('timestamp', '')
        source_ip = data.get('src_ip', '')
        source_port = data.get('src_port', 0)
        destination_ip = data.get('dst_ip', '')
        destination_port = data.get('dst_port', 0)
        session_id = data.get('session', '')
        protocol = data.get('protocol', 'ssh')
        
        # Parse event based on event type
        if eventid == 'cowrie.session.connect':
            return self._parse_connect_event(
                data, timestamp, source_ip, source_port,
                destination_ip, destination_port, session_id, protocol
            )
        elif eventid == 'cowrie.login.success':
            return self._parse_login_success(
                data, timestamp, source_ip, source_port,
                destination_ip, destination_port, session_id, protocol
            )
        elif eventid == 'cowrie.login.failed':
            return self._parse_login_failed(
                data, timestamp, source_ip, source_port,
                destination_ip, destination_port, session_id, protocol
            )
        elif eventid == 'cowrie.command.input':
            return self._parse_command_input(
                data, timestamp, source_ip, source_port,
                destination_ip, destination_port, session_id, protocol
            )
        elif eventid == 'cowrie.session.closed':
            return self._parse_session_closed(
                data, timestamp, source_ip, source_port,
                destination_ip, destination_port, session_id, protocol
            )
        else:
            # Generic event parsing
            return self._parse_generic_event(
                data, timestamp, source_ip, source_port,
                destination_ip, destination_port, session_id, protocol, eventid
            )
    
    def _parse_connect_event(
        self, data: Dict[str, Any], timestamp: str, source_ip: str,
        source_port: int, destination_ip: str, destination_port: int,
        session_id: str, protocol: str
    ) -> CowrieEvent:
        """Parse session connect event."""
        return CowrieEvent(
            timestamp=timestamp,
            source_ip=source_ip,
            source_port=source_port,
            destination_ip=destination_ip,
            destination_port=destination_port,
            session_id=session_id,
            event_type='session_connect',
            protocol=protocol,
            raw_event=json.dumps(data),
            additional_data={
                'protocol': protocol,
                'version': data.get('version', '')
            }
        )
    
    def _parse_login_success(
        self, data: Dict[str, Any], timestamp: str, source_ip: str,
        source_port: int, destination_ip: str, destination_port: int,
        session_id: str, protocol: str
    ) -> CowrieEvent:
        """Parse successful login event."""
        return CowrieEvent(
            timestamp=timestamp,
            source_ip=source_ip,
            source_port=source_port,
            destination_ip=destination_ip,
            destination_port=destination_port,
            session_id=session_id,
            event_type='login_success',
            username=data.get('username', ''),
            protocol=protocol,
            raw_event=json.dumps(data),
            additional_data={
                'method': data.get('method', ''),
                'username': data.get('username', '')
            }
        )
    
    def _parse_login_failed(
        self, data: Dict[str, Any], timestamp: str, source_ip: str,
        source_port: int, destination_ip: str, destination_port: int,
        session_id: str, protocol: str
    ) -> CowrieEvent:
        """Parse failed login event."""
        return CowrieEvent(
            timestamp=timestamp,
            source_ip=source_ip,
            source_port=source_port,
            destination_ip=destination_ip,
            destination_port=destination_port,
            session_id=session_id,
            event_type='login_failed',
            username=data.get('username', ''),
            protocol=protocol,
            raw_event=json.dumps(data),
            additional_data={
                'username': data.get('username', ''),
                'password': data.get('password', ''),
                'error': data.get('error', '')
            }
        )
    
    def _parse_command_input(
        self, data: Dict[str, Any], timestamp: str, source_ip: str,
        source_port: int, destination_ip: str, destination_port: int,
        session_id: str, protocol: str
    ) -> CowrieEvent:
        """Parse command input event."""
        command = data.get('input', '')
        
        return CowrieEvent(
            timestamp=timestamp,
            source_ip=source_ip,
            source_port=source_port,
            destination_ip=destination_ip,
            destination_port=destination_port,
            session_id=session_id,
            event_type='command_execution',
            username=data.get('username', ''),
            command=command,
            protocol=protocol,
            raw_event=json.dumps(data),
            additional_data={
                'command': command,
                'username': data.get('username', '')
            }
        )
    
    def _parse_session_closed(
        self, data: Dict[str, Any], timestamp: str, source_ip: str,
        source_port: int, destination_ip: str, destination_port: int,
        session_id: str, protocol: str
    ) -> CowrieEvent:
        """Parse session closed event."""
        return CowrieEvent(
            timestamp=timestamp,
            source_ip=source_ip,
            source_port=source_port,
            destination_ip=destination_ip,
            destination_port=destination_port,
            session_id=session_id,
            event_type='session_closed',
            protocol=protocol,
            raw_event=json.dumps(data),
            additional_data={}
        )
    
    def _parse_generic_event(
        self, data: Dict[str, Any], timestamp: str, source_ip: str,
        source_port: int, destination_ip: str, destination_port: int,
        session_id: str, protocol: str, eventid: str
    ) -> CowrieEvent:
        """Parse generic/unknown event type."""
        return CowrieEvent(
            timestamp=timestamp,
            source_ip=source_ip,
            source_port=source_port,
            destination_ip=destination_ip,
            destination_port=destination_port,
            session_id=session_id,
            event_type=eventid,
            protocol=protocol,
            raw_event=json.dumps(data),
            additional_data=data
        )
    
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
    
    def get_events_by_type(self, events: List[CowrieEvent]) -> Dict[str, int]:
        """
        Count events by type.
        
        Args:
            events: List of CowrieEvent objects
            
        Returns:
            Dictionary with event type counts
        """
        type_counts = {}
        for event in events:
            event_type = event.event_type
            type_counts[event_type] = type_counts.get(event_type, 0) + 1
        return type_counts
    
    def get_events_by_ip(self, events: List[CowrieEvent]) -> Dict[str, int]:
        """
        Count events by source IP.
        
        Args:
            events: List of CowrieEvent objects
            
        Returns:
            Dictionary with IP event counts
        """
        ip_counts = {}
        for event in events:
            ip = event.source_ip
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
        return ip_counts


def parse_cowrie_log(log_path: str) -> List[CowrieEvent]:
    """
    Convenience function to parse Cowrie log file.
    
    Args:
        log_path: Path to Cowrie log file
        
    Returns:
        List of CowrieEvent objects
    """
    parser = CowrieParser(log_path)
    return parser.parse_file()


def event_to_dict(event: CowrieEvent) -> Dict[str, Any]:
    """
    Convert CowrieEvent to dictionary.
    
    Args:
        event: CowrieEvent object
        
    Returns:
        Dictionary representation
    """
    return asdict(event)