"""
Detection engine for the Dynamic Honeypot Platform.
Correlates events, applies detection rules, and generates security alerts.
"""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict
from dataclasses import dataclass, asdict
from utils.logger import get_logger
from utils.config_loader import ConfigLoader
from utils.date_utils import DateUtils
from utils.file_utils import FileUtils
from rules import RuleEngine, Alert


@dataclass
class CorrelationResult:
    """Result of event correlation analysis."""
    correlated_events: List[Dict[str, Any]]
    correlation_type: str
    confidence: float
    description: str
    timestamp: str


@dataclass
class DetectionSummary:
    """Summary of detection engine results."""
    total_events_analyzed: int
    total_alerts_generated: int
    alerts_by_severity: Dict[str, int]
    correlations_found: int
    unique_source_ips: int
    analysis_duration: float
    timestamp: str


class DetectionEngine:
    """Main detection engine for security event analysis."""
    
    def __init__(self, config_dir: str = "config"):
        """
        Initialize detection engine.
        
        Args:
            config_dir: Directory containing configuration files
        """
        self.config_loader = ConfigLoader(config_dir)
        self.logger = get_logger("DetectionEngine")
        
        # Load configuration
        self.settings = self.config_loader.load_settings("settings.yaml")
        
        # Initialize components
        self.rule_engine = RuleEngine(config_dir)
        
        # State management
        self.event_history: List[Dict[str, Any]] = []
        self.alert_history: List[Alert] = []
        self.correlation_window = self.settings.detection.get('correlation_window', 300)
        self.max_history_size = self.settings.detection.get('max_events_per_session', 1000)
        
        # Statistics
        self.stats = {
            'total_events_analyzed': 0,
            'total_alerts_generated': 0,
            'correlations_found': 0,
            'analysis_start_time': None
        }
        
        self.logger.info("Detection engine initialized")
    
    def analyze_events(self, events: List[Dict[str, Any]]) -> List[Alert]:
        """
        Analyze events and generate alerts.
        
        Args:
            events: List of normalized events
            
        Returns:
            List of generated alerts
        """
        if not events:
            self.logger.warning("No events to analyze")
            return []
        
        self.logger.info(f"Analyzing {len(events)} events")
        start_time = datetime.now()
        
        # Add events to history
        self._add_events_to_history(events)
        
        # Apply detection rules
        alerts = self.rule_engine.evaluate_events_batch(events)
        
        # Perform correlation analysis
        correlations = self._correlate_events(events)
        self.stats['correlations_found'] += len(correlations)
        
        # Enhance alerts with correlation data
        enhanced_alerts = self._enhance_alerts(alerts, correlations)
        
        # Store alerts
        self.alert_history.extend(enhanced_alerts)
        
        # Update statistics
        self.stats['total_events_analyzed'] += len(events)
        self.stats['total_alerts_generated'] += len(enhanced_alerts)
        
        analysis_duration = (datetime.now() - start_time).total_seconds()
        
        self.logger.info(
            f"Analysis complete: {len(enhanced_alerts)} alerts generated, "
            f"{len(correlations)} correlations found in {analysis_duration:.2f}s"
        )
        
        return enhanced_alerts
    
    def _add_events_to_history(self, events: List[Dict[str, Any]]):
        """Add events to history buffer."""
        self.event_history.extend(events)
        
        # Trim history if too large
        if len(self.event_history) > self.max_history_size:
            self.event_history = self.event_history[-self.max_history_size:]
        
        # Remove old events outside correlation window
        current_time = DateUtils.now()
        window_start = DateUtils.subtract_seconds(current_time, self.correlation_window)
        
        self.event_history = [
            event for event in self.event_history
            if self._is_event_in_window(event, window_start, current_time)
        ]
    
    def _is_event_in_window(self, event: Dict[str, Any], window_start: datetime, current_time: datetime) -> bool:
        """Check if event is within correlation window."""
        timestamp_str = event.get('timestamp', '')
        if not timestamp_str:
            return False
        
        event_time = DateUtils.from_iso_string(timestamp_str)
        if not event_time:
            return False
        
        return DateUtils.is_within_window(event_time, window_start, current_time)
    
    def _correlate_events(self, events: List[Dict[str, Any]]) -> List[CorrelationResult]:
        """
        Perform correlation analysis on events.
        
        Args:
            events: List of events to correlate
            
        Returns:
            List of correlation results
        """
        correlations = []
        
        # Correlate by source IP
        ip_correlations = self._correlate_by_source_ip(events)
        correlations.extend(ip_correlations)
        
        # Correlate by session
        session_correlations = self._correlate_by_session(events)
        correlations.extend(session_correlations)
        
        # Correlate by event sequence
        sequence_correlations = self._correlate_by_sequence(events)
        correlations.extend(sequence_correlations)
        
        return correlations
    
    def _correlate_by_source_ip(self, events: List[Dict[str, Any]]) -> List[CorrelationResult]:
        """Correlate events by source IP."""
        ip_events = defaultdict(list)
        
        for event in events:
            source_ip = event.get('source_ip', 'unknown')
            ip_events[source_ip].append(event)
        
        correlations = []
        for source_ip, ip_event_list in ip_events.items():
            if len(ip_event_list) >= 3:  # Minimum threshold for correlation
                correlation = CorrelationResult(
                    correlated_events=ip_event_list,
                    correlation_type='source_ip',
                    confidence=0.7,
                    description=f"Multiple events from same source IP: {source_ip}",
                    timestamp=DateUtils.to_iso_string(DateUtils.now())
                )
                correlations.append(correlation)
        
        return correlations
    
    def _correlate_by_session(self, events: List[Dict[str, Any]]) -> List[CorrelationResult]:
        """Correlate events by session ID."""
        session_events = defaultdict(list)
        
        for event in events:
            session_id = event.get('session_id', 'unknown')
            session_events[session_id].append(event)
        
        correlations = []
        for session_id, session_event_list in session_events.items():
            if len(session_event_list) >= 2:
                correlation = CorrelationResult(
                    correlated_events=session_event_list,
                    correlation_type='session',
                    confidence=0.8,
                    description=f"Multiple events in same session: {session_id}",
                    timestamp=DateUtils.to_iso_string(DateUtils.now())
                )
                correlations.append(correlation)
        
        return correlations
    
    def _correlate_by_sequence(self, events: List[Dict[str, Any]]) -> List[CorrelationResult]:
        """Correlate events by attack sequence patterns."""
        correlations = []
        
        # Look for common attack sequences
        attack_sequences = [
            ['login_success', 'command_execution'],
            ['command_execution', 'file_download'],
            ['recon_activity', 'command_execution', 'file_download'],
            ['login_failed', 'login_failed', 'login_failed']
        ]
        
        for sequence in attack_sequences:
            matched_sequence = self._find_sequence(events, sequence)
            if matched_sequence:
                correlation = CorrelationResult(
                    correlated_events=matched_sequence,
                    correlation_type='sequence',
                    confidence=0.9,
                    description=f"Attack sequence detected: {' -> '.join(sequence)}",
                    timestamp=DateUtils.to_iso_string(DateUtils.now())
                )
                correlations.append(correlation)
        
        return correlations
    
    def _find_sequence(self, events: List[Dict[str, Any]], sequence: List[str]) -> Optional[List[Dict[str, Any]]]:
        """Find a specific event sequence in events."""
        if len(events) < len(sequence):
            return None
        
        for i in range(len(events) - len(sequence) + 1):
            potential_sequence = events[i:i + len(sequence)]
            
            match = True
            for j, expected_type in enumerate(sequence):
                if potential_sequence[j].get('event_type') != expected_type:
                    match = False
                    break
            
            if match:
                return potential_sequence
        
        return None
    
    def _enhance_alerts(
        self,
        alerts: List[Alert],
        correlations: List[CorrelationResult]
    ) -> List[Alert]:
        """Enhance alerts with correlation data."""
        enhanced_alerts = []
        
        for alert in alerts:
            # Find relevant correlations
            relevant_correlations = [
                corr for corr in correlations
                if alert.event in corr.correlated_events
            ]
            
            # Add correlation data to alert
            if relevant_correlations:
                alert.metadata['correlations'] = [
                    asdict(corr) for corr in relevant_correlations
                ]
                # Boost confidence based on correlations
                alert.confidence = min(alert.confidence + 0.1, 1.0)
            
            enhanced_alerts.append(alert)
        
        return enhanced_alerts
    
    def get_alerts_by_severity(self, severity: str) -> List[Alert]:
        """
        Get alerts filtered by severity.
        
        Args:
            severity: Severity level (critical, high, medium, low)
            
        Returns:
            List of alerts
        """
        return [alert for alert in self.alert_history if alert.severity == severity]
    
    def get_alerts_by_source_ip(self, source_ip: str) -> List[Alert]:
        """
        Get alerts filtered by source IP.
        
        Args:
            source_ip: Source IP address
            
        Returns:
            List of alerts
        """
        return [alert for alert in self.alert_history if alert.source_ip == source_ip]
    
    def get_recent_alerts(self, minutes: int = 60) -> List[Alert]:
        """
        Get alerts from recent time period.
        
        Args:
            minutes: Number of minutes to look back
            
        Returns:
            List of recent alerts
        """
        current_time = DateUtils.now()
        window_start = DateUtils.subtract_seconds(current_time, minutes * 60)
        
        recent_alerts = []
        for alert in self.alert_history:
            alert_time = DateUtils.from_iso_string(alert.timestamp)
            if alert_time and DateUtils.is_within_window(alert_time, window_start, current_time):
                recent_alerts.append(alert)
        
        return recent_alerts
    
    def get_detection_summary(self) -> DetectionSummary:
        """
        Get summary of detection results.
        
        Returns:
            DetectionSummary object
        """
        # Count alerts by severity
        severity_counts = defaultdict(int)
        for alert in self.alert_history:
            severity_counts[alert.severity] += 1
        
        # Count unique source IPs
        unique_ips = set(alert.source_ip for alert in self.alert_history)
        
        # Calculate analysis duration
        analysis_duration = 0.0
        if self.stats['analysis_start_time']:
            analysis_duration = (datetime.now() - self.stats['analysis_start_time']).total_seconds()
        
        return DetectionSummary(
            total_events_analyzed=self.stats['total_events_analyzed'],
            total_alerts_generated=self.stats['total_alerts_generated'],
            alerts_by_severity=dict(severity_counts),
            correlations_found=self.stats['correlations_found'],
            unique_source_ips=len(unique_ips),
            analysis_duration=analysis_duration,
            timestamp=DateUtils.to_iso_string(DateUtils.now())
        )
    
    def export_alerts(self, output_file: str) -> bool:
        """
        Export alerts to JSON file.
        
        Args:
            output_file: Output file path
            
        Returns:
            True if successful
        """
        try:
            output_data = {
                'metadata': {
                    'exported_at': DateUtils.to_iso_string(DateUtils.now()),
                    'total_alerts': len(self.alert_history),
                    'format_version': '1.0'
                },
                'alerts': [asdict(alert) for alert in self.alert_history]
            }
            
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, default=str)
            
            self.logger.info(f"Exported {len(self.alert_history)} alerts to {output_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting alerts: {e}")
            return False
    
    def clear_history(self):
        """Clear event and alert history."""
        self.event_history.clear()
        self.alert_history.clear()
        self.logger.info("Detection history cleared")
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get detection engine statistics.
        
        Returns:
            Dictionary with statistics
        """
        summary = self.get_detection_summary()
        
        return {
            'total_events_analyzed': summary.total_events_analyzed,
            'total_alerts_generated': summary.total_alerts_generated,
            'alerts_by_severity': summary.alerts_by_severity,
            'correlations_found': summary.correlations_found,
            'unique_source_ips': summary.unique_source_ips,
            'current_history_size': len(self.event_history),
            'rule_engine_stats': self.rule_engine.get_statistics()
        }


def analyze_security_events(events: List[Dict[str, Any]]) -> List[Alert]:
    """
    Convenience function to analyze security events.
    
    Args:
        events: List of normalized events
        
    Returns:
        List of generated alerts
    """
    engine = DetectionEngine()
    return engine.analyze_events(events)


if __name__ == "__main__":
    # Example usage
    engine = DetectionEngine()
    
    # Analyze sample events
    sample_events = [
        {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'login_failed',
            'source_ip': '192.168.1.100',
            'command': None
        },
        {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'login_failed',
            'source_ip': '192.168.1.100',
            'command': None
        }
    ]
    
    alerts = engine.analyze_events(sample_events)
    print(f"Generated {len(alerts)} alerts")
    
    # Print statistics
    print(f"Statistics: {engine.get_statistics()}")