"""
Event export module for the Dynamic Honeypot Platform.
Exports normalized events to various formats and databases.
"""

import json
import csv
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
from utils.logger import get_logger
from utils.date_utils import DateUtils
from utils.file_utils import FileUtils


class EventExporter:
    """Exports normalized events to various formats."""
    
    def __init__(self, output_dir: str = "data/events/exported"):
        """
        Initialize event exporter.
        
        Args:
            output_dir: Directory for exported events
        """
        self.output_dir = Path(output_dir)
        self.logger = get_logger("EventExporter")
        FileUtils.ensure_dir(self.output_dir)
        self.export_count = 0
    
    def export_to_json(
        self,
        events: List[Dict[str, Any]],
        filename: str,
        include_metadata: bool = True
    ) -> bool:
        """
        Export events to JSON file.
        
        Args:
            events: List of event dictionaries
            filename: Output filename
            include_metadata: Whether to include metadata
            
        Returns:
            True if successful
        """
        try:
            output_path = self.output_dir / filename
            
            if include_metadata:
                output_data = {
                    'metadata': {
                        'exported_at': DateUtils.to_iso_string(DateUtils.now()),
                        'total_events': len(events),
                        'format_version': '1.0',
                        'export_type': 'full_export'
                    },
                    'events': events
                }
            else:
                output_data = events
            
            FileUtils.save_json(output_path, output_data)
            self.export_count += len(events)
            self.logger.info(f"Exported {len(events)} events to JSON: {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting to JSON: {e}")
            return False
    
    def export_to_csv(
        self,
        events: List[Dict[str, Any]],
        filename: str,
        flatten: bool = True
    ) -> bool:
        """
        Export events to CSV file.
        
        Args:
            events: List of event dictionaries
            filename: Output filename
            flatten: Whether to flatten nested dictionaries
            
        Returns:
            True if successful
        """
        try:
            output_path = self.output_dir / filename
            
            if not events:
                self.logger.warning("No events to export to CSV")
                return False
            
            # Flatten events if requested
            if flatten:
                events_to_export = [self._flatten_dict(event) for event in events]
            else:
                events_to_export = events
            
            # Determine fieldnames
            fieldnames = set()
            for event in events_to_export:
                fieldnames.update(event.keys())
            
            # Write CSV
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=sorted(fieldnames))
                writer.writeheader()
                writer.writerows(events_to_export)
            
            self.export_count += len(events)
            self.logger.info(f"Exported {len(events)} events to CSV: {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting to CSV: {e}")
            return False
    
    def export_by_service(
        self,
        events: List[Dict[str, Any]],
        base_filename: str,
        format: str = 'json'
    ) -> Dict[str, bool]:
        """
        Export events grouped by service.
        
        Args:
            events: List of event dictionaries
            base_filename: Base filename for exports
            format: Export format ('json' or 'csv')
            
        Returns:
            Dictionary with service names and export status
        """
        # Group events by service
        events_by_service = {}
        for event in events:
            service = event.get('service', 'unknown')
            if service not in events_by_service:
                events_by_service[service] = []
            events_by_service[service].append(event)
        
        # Export each service group
        results = {}
        for service, service_events in events_by_service.items():
            filename = f"{base_filename}_{service}.{format}"
            
            if format == 'json':
                success = self.export_to_json(service_events, filename)
            elif format == 'csv':
                success = self.export_to_csv(service_events, filename)
            else:
                self.logger.error(f"Unsupported format: {format}")
                success = False
            
            results[service] = success
        
        return results
    
    def export_by_date(
        self,
        events: List[Dict[str, Any]],
        base_filename: str,
        format: str = 'json'
    ) -> Dict[str, bool]:
        """
        Export events grouped by date.
        
        Args:
            events: List of event dictionaries
            base_filename: Base filename for exports
            format: Export format ('json' or 'csv')
            
        Returns:
            Dictionary with dates and export status
        """
        # Group events by date
        events_by_date = {}
        for event in events:
            timestamp = event.get('timestamp', '')
            if timestamp:
                # Extract date from timestamp
                try:
                    dt = DateUtils.from_iso_string(timestamp)
                    date_str = dt.strftime('%Y-%m-%d')
                except:
                    date_str = 'unknown'
            else:
                date_str = 'unknown'
            
            if date_str not in events_by_date:
                events_by_date[date_str] = []
            events_by_date[date_str].append(event)
        
        # Export each date group
        results = {}
        for date, date_events in events_by_date.items():
            filename = f"{base_filename}_{date}.{format}"
            
            if format == 'json':
                success = self.export_to_json(date_events, filename)
            elif format == 'csv':
                success = self.export_to_csv(date_events, filename)
            else:
                self.logger.error(f"Unsupported format: {format}")
                success = False
            
            results[date] = success
        
        return results
    
    def export_summary(
        self,
        events: List[Dict[str, Any]],
        filename: str = "events_summary.json"
    ) -> bool:
        """
        Export summary statistics of events.
        
        Args:
            events: List of event dictionaries
            filename: Output filename
            
        Returns:
            True if successful
        """
        try:
            summary = self._generate_summary(events)
            output_path = self.output_dir / filename
            
            FileUtils.save_json(output_path, summary)
            self.logger.info(f"Exported summary to {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting summary: {e}")
            return False
    
    def _generate_summary(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate summary statistics from events.
        
        Args:
            events: List of event dictionaries
            
        Returns:
            Summary dictionary
        """
        summary = {
            'total_events': len(events),
            'generated_at': DateUtils.to_iso_string(DateUtils.now()),
            'by_service': {},
            'by_event_type': {},
            'by_severity': {},
            'by_source_ip': {},
            'time_range': {}
        }
        
        if not events:
            return summary
        
        # Count by service
        for event in events:
            service = event.get('service', 'unknown')
            summary['by_service'][service] = summary['by_service'].get(service, 0) + 1
        
        # Count by event type
        for event in events:
            event_type = event.get('event_type', 'unknown')
            summary['by_event_type'][event_type] = summary['by_event_type'].get(event_type, 0) + 1
        
        # Count by severity
        for event in events:
            severity = event.get('severity', 'info')
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
        
        # Count by source IP
        for event in events:
            source_ip = event.get('source_ip', 'unknown')
            summary['by_source_ip'][source_ip] = summary['by_source_ip'].get(source_ip, 0) + 1
        
        # Time range
        timestamps = [event.get('timestamp') for event in events if event.get('timestamp')]
        if timestamps:
            try:
                timestamps_sorted = sorted([DateUtils.from_iso_string(ts) for ts in timestamps if DateUtils.from_iso_string(ts)])
                if timestamps_sorted:
                    summary['time_range']['earliest'] = DateUtils.to_iso_string(timestamps_sorted[0])
                    summary['time_range']['latest'] = DateUtils.to_iso_string(timestamps_sorted[-1])
            except Exception as e:
                self.logger.debug(f"Error calculating time range: {e}")
        
        return summary
    
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
        Get export statistics.
        
        Returns:
            Dictionary with statistics
        """
        return {
            'total_exported': self.export_count
        }


def export_events_to_json(events: List[Dict[str, Any]], filename: str) -> bool:
    """
    Convenience function to export events to JSON.
    
    Args:
        events: List of event dictionaries
        filename: Output filename
        
    Returns:
        True if successful
    """
    exporter = EventExporter()
    return exporter.export_to_json(events, filename)


def export_events_to_csv(events: List[Dict[str, Any]], filename: str) -> bool:
    """
    Convenience function to export events to CSV.
    
    Args:
        events: List of event dictionaries
        filename: Output filename
        
    Returns:
        True if successful
    """
    exporter = EventExporter()
    return exporter.export_to_csv(events, filename)