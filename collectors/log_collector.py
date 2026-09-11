"""
Log collector orchestrator for the Dynamic Honeypot Platform.
Coordinates log collection, parsing, normalization, and export.
"""

import time
import schedule
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
from utils.logger import get_logger
from utils.config_loader import load_settings
from utils.file_utils import FileUtils
from parse_cowrie import CowrieParser, parse_cowrie_log
from parse_http import HTTPParser, parse_http_log
from normalize_events import EventNormalizer, NormalizedEvent
from export_events import EventExporter


class LogCollector:
    """Main log collection orchestrator."""
    
    def __init__(self, config_path: str = "config/settings.yaml"):
        """
        Initialize log collector.
        
        Args:
            config_path: Path to configuration file
        """
        self.logger = get_logger("LogCollector")
        self.settings = load_settings(config_path)
        self.normalizer = EventNormalizer()
        self.exporter = EventExporter()
        
        # Initialize parsers
        self.cowrie_parser: Optional[CowrieParser] = None
        self.http_parser: Optional[HTTPParser] = None
        
        # Statistics
        self.stats = {
            'cowrie_events': 0,
            'http_events': 0,
            'normalized_events': 0,
            'exported_events': 0,
            'last_collection': None
        }
    
    def initialize_parsers(self):
        """Initialize parsers based on configuration."""
        # Cowrie parser
        if self.settings.cowrie.get('enabled', False):
            cowrie_log_path = self._get_cowrie_log_path()
            if cowrie_log_path and Path(cowrie_log_path).exists():
                self.cowrie_parser = CowrieParser(cowrie_log_path)
                self.logger.info(f"Cowrie parser initialized: {cowrie_log_path}")
            else:
                self.logger.warning(f"Cowrie log path not found: {cowrie_log_path}")
        
        # HTTP parser
        if self.settings.http_honeypot.get('enabled', False):
            http_log_path = self.settings.http_honeypot.get('log_path', './data/events/raw/http.log')
            if Path(http_log_path).exists():
                self.http_parser = HTTPParser(http_log_path)
                self.logger.info(f"HTTP parser initialized: {http_log_path}")
            else:
                self.logger.warning(f"HTTP log path not found: {http_log_path}")
    
    def _get_cowrie_log_path(self) -> Optional[str]:
        """Get Cowrie log path based on environment."""
        if self.settings.environment == 'development':
            return self.settings.cowrie.get('dev_log_path')
        else:
            return self.settings.cowrie.get('log_path')
    
    def collect_cowrie_logs(self) -> List:
        """
        Collect and parse Cowrie logs.
        
        Returns:
            List of parsed Cowrie events
        """
        if not self.cowrie_parser:
            self.logger.warning("Cowrie parser not initialized")
            return []
        
        try:
            events = self.cowrie_parser.parse_file()
            self.stats['cowrie_events'] += len(events)
            self.logger.info(f"Collected {len(events)} Cowrie events")
            return events
        except Exception as e:
            self.logger.error(f"Error collecting Cowrie logs: {e}")
            return []
    
    def collect_http_logs(self) -> List:
        """
        Collect and parse HTTP logs.
        
        Returns:
            List of parsed HTTP events
        """
        if not self.http_parser:
            self.logger.warning("HTTP parser not initialized")
            return []
        
        try:
            events = self.http_parser.parse_file()
            self.stats['http_events'] += len(events)
            self.logger.info(f"Collected {len(events)} HTTP events")
            return events
        except Exception as e:
            self.logger.error(f"Error collecting HTTP logs: {e}")
            return []
    
    def normalize_events(self, cowrie_events: List, http_events: List) -> List[NormalizedEvent]:
        """
        Normalize all collected events.
        
        Args:
            cowrie_events: List of Cowrie events
            http_events: List of HTTP events
            
        Returns:
            List of normalized events
        """
        all_normalized = []
        
        # Normalize Cowrie events
        if cowrie_events:
            normalized_cowrie = self.normalizer.normalize_batch(cowrie_events, 'cowrie')
            all_normalized.extend(normalized_cowrie)
        
        # Normalize HTTP events
        if http_events:
            normalized_http = self.normalizer.normalize_batch(http_events, 'http')
            all_normalized.extend(normalized_http)
        
        self.stats['normalized_events'] += len(all_normalized)
        self.logger.info(f"Normalized {len(all_normalized)} events")
        
        return all_normalized
    
    def export_events(self, normalized_events: List[NormalizedEvent]) -> bool:
        """
        Export normalized events.
        
        Args:
            normalized_events: List of normalized events
            
        Returns:
            True if successful
        """
        if not normalized_events:
            self.logger.warning("No events to export")
            return False
        
        try:
            # Convert to dictionaries
            events_dicts = [event.__dict__ for event in normalized_events]
            
            # Generate filename with timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            
            # Export to JSON
            json_success = self.exporter.export_to_json(
                events_dicts,
                f"events_{timestamp}.json"
            )
            
            # Export to CSV
            csv_success = self.exporter.export_to_csv(
                events_dicts,
                f"events_{timestamp}.csv"
            )
            
            # Export summary
            self.exporter.export_summary(events_dicts, f"summary_{timestamp}.json")
            
            if json_success or csv_success:
                self.stats['exported_events'] += len(normalized_events)
                self.logger.info(f"Exported {len(normalized_events)} events")
                return True
            else:
                return False
                
        except Exception as e:
            self.logger.error(f"Error exporting events: {e}")
            return False
    
    def run_collection_cycle(self) -> Dict[str, int]:
        """
        Run a single collection cycle.
        
        Returns:
            Dictionary with cycle statistics
        """
        self.logger.info("Starting collection cycle")
        
        # Collect logs
        cowrie_events = self.collect_cowrie_logs()
        http_events = self.collect_http_logs()
        
        # Normalize events
        normalized_events = self.normalize_events(cowrie_events, http_events)
        
        # Export events
        export_success = self.export_events(normalized_events)
        
        # Update statistics
        self.stats['last_collection'] = datetime.now().isoformat()
        
        cycle_stats = {
            'cowrie_events': len(cowrie_events),
            'http_events': len(http_events),
            'normalized_events': len(normalized_events),
            'export_success': export_success,
            'timestamp': self.stats['last_collection']
        }
        
        self.logger.info(f"Collection cycle completed: {cycle_stats}")
        return cycle_stats
    
    def start_scheduled_collection(self, interval_minutes: int = 5):
        """
        Start scheduled log collection.
        
        Args:
            interval_minutes: Collection interval in minutes
        """
        self.logger.info(f"Starting scheduled collection every {interval_minutes} minutes")
        
        schedule.every(interval_minutes).minutes.do(self.run_collection_cycle)
        
        try:
            while True:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
        except KeyboardInterrupt:
            self.logger.info("Scheduled collection stopped")
    
    def get_statistics(self) -> Dict[str, int]:
        """
        Get collector statistics.
        
        Returns:
            Dictionary with statistics
        """
        return self.stats.copy()


def main():
    """Main entry point for log collector."""
    collector = LogCollector()
    collector.initialize_parsers()
    
    # Run a single collection cycle
    stats = collector.run_collection_cycle()
    print(f"Collection cycle completed: {stats}")
    
    # Print overall statistics
    print(f"Overall statistics: {collector.get_statistics()}")


if __name__ == "__main__":
    main()