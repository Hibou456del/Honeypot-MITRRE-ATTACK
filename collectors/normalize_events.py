"""
Event normalization module for the Dynamic Honeypot Platform.
Normalizes parsed events from different sources into a consistent format.
"""

import json
import csv
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import dataclass, asdict
from utils.logger import get_logger
from utils.date_utils import DateUtils
from utils.file_utils import FileUtils


@dataclass
class NormalizedEvent:
    """Standardized event format for all honeypot sources."""
    timestamp: str
    source_ip: str
    service: str
    event_type: str
    session_id: str
    raw_event: str
    
    # Optional fields
    username: Optional[str] = None
    command: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    status_code: Optional[int] = None
    user_agent: Optional[str] = None
    
    # Metadata
    source: str = "unknown"
    severity: str = "info"
    confidence: float = 0.0
    tags: Optional[List[str]] = None
    additional_data: Optional[Dict[str, Any]] = None


class EventNormalizer:
    """Normalizes events from different honeypot sources."""
    
    def __init__(self, output_dir: str = "data/events/normalized"):
        """
        Initialize event normalizer.
        
        Args:
            output_dir: Directory for normalized events
        """
        self.output_dir = Path(output_dir)
        self.logger = get_logger("EventNormalizer")
        FileUtils.ensure_dir(self.output_dir)
        self.normalized_count = 0
    
    def normalize_cowrie_event(self, cowrie_event: Any) -> NormalizedEvent:
        """
        Normalize Cowrie event to standard format.
        
        Args:
            cowrie_event: CowrieEvent object
            
        Returns:
            NormalizedEvent object
        """
        # Convert to dict if it's a dataclass
        if hasattr(cowrie_event, '__dict__'):
            event_dict = asdict(cowrie_event)
        else:
            event_dict = cowrie_event
        
        return NormalizedEvent(
            timestamp=event_dict.get('timestamp', ''),
            source_ip=event_dict.get('source_ip', ''),
            service=event_dict.get('protocol', 'ssh'),
            event_type=event_dict.get('event_type', ''),
            session_id=event_dict.get('session_id', ''),
            raw_event=event_dict.get('raw_event', json.dumps(event_dict)),
            username=event_dict.get('username'),
            command=event_dict.get('command'),
            source='cowrie',
            severity=self._determine_severity(event_dict.get('event_type', '')),
            additional_data=event_dict.get('additional_data', {})
        )
    
    def normalize_http_event(self, http_event: Any) -> NormalizedEvent:
        """
        Normalize HTTP event to standard format.
        
        Args:
            http_event: HTTPEvent object
            
        Returns:
            NormalizedEvent object
        """
        # Convert to dict if it's a dataclass
        if hasattr(http_event, '__dict__'):
            event_dict = asdict(http_event)
        else:
            event_dict = http_event
        
        return NormalizedEvent(
            timestamp=event_dict.get('timestamp', ''),
            source_ip=event_dict.get('source_ip', ''),
            service='http',
            event_type=event_dict.get('event_type', ''),
            session_id=f"http_{event_dict.get('source_ip', '')}_{event_dict.get('timestamp', '')}",
            raw_event=event_dict.get('raw_event', json.dumps(event_dict)),
            method=event_dict.get('method'),
            path=event_dict.get('path'),
            status_code=event_dict.get('status_code'),
            user_agent=event_dict.get('user_agent'),
            source='http_honeypot',
            severity=self._determine_severity(event_dict.get('event_type', '')),
            additional_data=event_dict.get('additional_data', {})
        )
    
    def _determine_severity(self, event_type: str) -> str:
        """
        Determine severity level based on event type.
        
        Args:
            event_type: Event type string
            
        Returns:
            Severity level (critical, high, medium, low, info)
        """
        critical_events = ['sql_injection_attempt', 'privilege_escalation', 'web_shell_upload']
        high_events = ['login_failed', 'sensitive_file_access', 'file_download']
        medium_events = ['command_execution', 'admin_panel_access', 'vulnerability_scan']
        low_events = ['session_connect', 'http_get', 'http_post']
        
        if event_type in critical_events:
            return 'critical'
        elif event_type in high_events:
            return 'high'
        elif event_type in medium_events:
            return 'medium'
        elif event_type in low_events:
            return 'low'
        else:
            return 'info'
    
    def normalize_batch(self, events: List[Any], source_type: str) -> List[NormalizedEvent]:
        """
        Normalize a batch of events.
        
        Args:
            events: List of event objects
            source_type: Type of source ('cowrie' or 'http')
            
        Returns:
            List of NormalizedEvent objects
        """
        normalized_events = []
        
        for event in events:
            try:
                if source_type == 'cowrie':
                    normalized = self.normalize_cowrie_event(event)
                elif source_type == 'http':
                    normalized = self.normalize_http_event(event)
                else:
                    self.logger.warning(f"Unknown source type: {source_type}")
                    continue
                
                normalized_events.append(normalized)
                self.normalized_count += 1
                
            except Exception as e:
                self.logger.error(f"Error normalizing event: {e}")
        
        self.logger.info(f"Normalized {self.normalized_count} events from {source_type}")
        return normalized_events
    
    def save_to_json(self, events: List[NormalizedEvent], filename: str) -> bool:
        """
        Save normalized events to JSON file.
        
        Args:
            events: List of NormalizedEvent objects
            filename: Output filename
            
        Returns:
            True if successful
        """
        try:
            output_path = self.output_dir / filename
            
            # Convert events to dictionaries
            events_data = [asdict(event) for event in events]
            
            # Add metadata
            output_data = {
                'metadata': {
                    'generated_at': DateUtils.to_iso_string(DateUtils.now()),
                    'total_events': len(events),
                    'format_version': '1.0'
                },
                'events': events_data
            }
            
            FileUtils.save_json(output_path, output_data)
            self.logger.info(f"Saved {len(events)} events to {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving to JSON: {e}")
            return False
    
    def save_to_csv(self, events: List[NormalizedEvent], filename: str) -> bool:
        """
        Save normalized events to CSV file.
        
        Args:
            events: List of NormalizedEvent objects
            filename: Output filename
            
        Returns:
            True if successful
        """
        try:
            output_path = self.output_dir / filename
            
            if not events:
                self.logger.warning("No events to save to CSV")
                return False
            
            # Convert events to dictionaries
            events_data = [asdict(event) for event in events]
            
            # Flatten nested dictionaries for CSV
            flattened_events = []
            for event_dict in events_data:
                flattened = self._flatten_dict(event_dict)
                flattened_events.append(flattened)
            
            # Write CSV
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                if flattened_events:
                    fieldnames = set()
                    for event in flattened_events:
                        fieldnames.update(event.keys())
                    
                    writer = csv.DictWriter(f, fieldnames=sorted(fieldnames))
                    writer.writeheader()
                    writer.writerows(flattened_events)
            
            self.logger.info(f"Saved {len(events)} events to {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving to CSV: {e}")
            return False
    
    def _flatten_dict(self, d: Dict[str, Any], parent_key: str = '', sep: str = '_') -> Dict[str, Any]:
        """
        Flatten nested dictionary.
        
        Args:
            d: Dictionary to flatten
            parent_key: Parent key for nested values
            sep: Separator for nested keys
            
        Returns:
            Flattened dictionary
        """
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                # Convert lists to strings
                items.append((new_key, json.dumps(v)))
            else:
                items.append((new_key, v))
        return dict(items)
    
    def get_statistics(self) -> Dict[str, int]:
        """
        Get normalization statistics.
        
        Returns:
            Dictionary with statistics
        """
        return {
            'total_normalized': self.normalized_count
        }


def normalize_cowrie_events(cowrie_events: List[Any]) -> List[NormalizedEvent]:
    """
    Convenience function to normalize Cowrie events.
    
    Args:
        cowrie_events: List of CowrieEvent objects
        
    Returns:
        List of NormalizedEvent objects
    """
    normalizer = EventNormalizer()
    return normalizer.normalize_batch(cowrie_events, 'cowrie')


def normalize_http_events(http_events: List[Any]) -> List[NormalizedEvent]:
    """
    Convenience function to normalize HTTP events.
    
    Args:
        http_events: List of HTTPEvent objects
        
    Returns:
        List of NormalizedEvent objects
    """
    normalizer = EventNormalizer()
    return normalizer.normalize_batch(http_events, 'http')