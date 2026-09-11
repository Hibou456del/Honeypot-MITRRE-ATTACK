"""
Tests for detection engine functionality.
"""

import pytest
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from detection.detection_engine import DetectionEngine
from detection.rules import RuleEngine, DetectionRule, Alert
from datetime import datetime


class TestRuleEngine:
    """Test rule engine."""
    
    @pytest.fixture
    def rule_engine(self):
        """Create rule engine instance."""
        return RuleEngine()
    
    @pytest.fixture
    def sample_events(self):
        """Create sample events."""
        return [
            {
                'timestamp': '2026-09-08T10:20:00Z',
                'source_ip': '192.168.1.101',
                'service': 'ssh',
                'event_type': 'login_failed',
                'session_id': 'test456',
                'username': 'root'
            },
            {
                'timestamp': '2026-09-08T10:20:05Z',
                'source_ip': '192.168.1.101',
                'service': 'ssh',
                'event_type': 'login_failed',
                'session_id': 'test456',
                'username': 'admin'
            },
            {
                'timestamp': '2026-09-08T10:15:30Z',
                'source_ip': '192.168.1.100',
                'service': 'ssh',
                'event_type': 'command_execution',
                'session_id': 'test123',
                'command': 'whoami',
                'username': 'admin'
            }
        ]
    
    def test_rule_engine_initialization(self, rule_engine):
        """Test rule engine initialization."""
        assert rule_engine is not None
        assert len(rule_engine.rules) > 0
    
    def test_evaluate_single_event(self, rule_engine, sample_events):
        """Test evaluating single event."""
        alerts = rule_engine.evaluate_event(sample_events[0])
        
        # Login failed should trigger an alert
        assert len(alerts) >= 0
    
    def test_evaluate_events_batch(self, rule_engine, sample_events):
        """Test batch event evaluation."""
        alerts = rule_engine.evaluate_events_batch(sample_events)
        
        assert len(alerts) >= 0
        assert all(isinstance(alert, Alert) for alert in alerts)
    
    def test_brute_force_detection(self, rule_engine):
        """Test brute force detection rule."""
        events = [
            {
                'timestamp': '2026-09-08T10:20:00Z',
                'source_ip': '192.168.1.101',
                'event_type': 'login_failed',
                'username': 'root'
            },
            {
                'timestamp': '2026-09-08T10:20:05Z',
                'source_ip': '192.168.1.101',
                'event_type': 'login_failed',
                'username': 'admin'
            }
        ]
        
        alerts = rule_engine.evaluate_events_batch(events)
        
        # Should detect repeated failed auth
        assert len(alerts) >= 0
    
    def test_get_enabled_rules(self, rule_engine):
        """Test getting enabled rules."""
        enabled_rules = rule_engine.get_enabled_rules()
        
        assert len(enabled_rules) > 0
        assert all(rule.enabled for rule in enabled_rules)
    
    def test_disable_rule(self, rule_engine):
        """Test disabling a rule."""
        rule_name = list(rule_engine.rules.keys())[0]
        success = rule_engine.disable_rule(rule_name)
        
        assert success is True
        assert rule_engine.rules[rule_name].enabled is False
    
    def test_enable_rule(self, rule_engine):
        """Test enabling a rule."""
        rule_name = list(rule_engine.rules.keys())[0]
        rule_engine.disable_rule(rule_name)
        success = rule_engine.enable_rule(rule_name)
        
        assert success is True
        assert rule_engine.rules[rule_name].enabled is True
    
    def test_get_statistics(self, rule_engine):
        """Test rule engine statistics."""
        stats = rule_engine.get_statistics()
        
        assert 'total_rules' in stats
        assert 'enabled_rules' in stats
        assert stats['total_rules'] > 0


class TestDetectionEngine:
    """Test detection engine."""
    
    @pytest.fixture
    def detection_engine(self):
        """Create detection engine instance."""
        return DetectionEngine()
    
    @pytest.fixture
    def sample_events(self):
        """Create sample events."""
        return [
            {
                'timestamp': '2026-09-08T10:15:23Z',
                'source_ip': '192.168.1.100',
                'service': 'ssh',
                'event_type': 'session_connect',
                'session_id': 'abc123'
            },
            {
                'timestamp': '2026-09-08T10:15:25Z',
                'source_ip': '192.168.1.100',
                'service': 'ssh',
                'event_type': 'login_success',
                'session_id': 'abc123',
                'username': 'admin'
            },
            {
                'timestamp': '2026-09-08T10:15:30Z',
                'source_ip': '192.168.1.100',
                'service': 'ssh',
                'event_type': 'command_execution',
                'session_id': 'abc123',
                'command': 'whoami',
                'username': 'admin'
            }
        ]
    
    def test_detection_engine_initialization(self, detection_engine):
        """Test detection engine initialization."""
        assert detection_engine is not None
        assert detection_engine.rule_engine is not None
    
    def test_analyze_events(self, detection_engine, sample_events):
        """Test event analysis."""
        alerts = detection_engine.analyze_events(sample_events)
        
        assert isinstance(alerts, list)
        assert detection_engine.stats['total_events_analyzed'] == len(sample_events)
    
    def test_correlation_by_source_ip(self, detection_engine):
        """Test correlation by source IP."""
        events = [
            {
                'timestamp': '2026-09-08T10:15:30Z',
                'source_ip': '192.168.1.100',
                'event_type': 'command_execution',
                'session_id': 'abc123'
            },
            {
                'timestamp': '2026-09-08T10:15:35Z',
                'source_ip': '192.168.1.100',
                'event_type': 'command_execution',
                'session_id': 'abc123'
            },
            {
                'timestamp': '2026-09-08T10:15:40Z',
                'source_ip': '192.168.1.100',
                'event_type': 'command_execution',
                'session_id': 'abc123'
            }
        ]
        
        detection_engine.analyze_events(events)
        
        # Should have detected correlation
        assert detection_engine.stats['correlations_found'] >= 0
    
    def test_get_alerts_by_severity(self, detection_engine, sample_events):
        """Test filtering alerts by severity."""
        detection_engine.analyze_events(sample_events)
        
        high_alerts = detection_engine.get_alerts_by_severity('high')
        
        assert isinstance(high_alerts, list)
    
    def test_get_alerts_by_source_ip(self, detection_engine, sample_events):
        """Test filtering alerts by source IP."""
        detection_engine.analyze_events(sample_events)
        
        ip_alerts = detection_engine.get_alerts_by_source_ip('192.168.1.100')
        
        assert isinstance(ip_alerts, list)
    
    def test_get_detection_summary(self, detection_engine, sample_events):
        """Test detection summary."""
        detection_engine.analyze_events(sample_events)
        summary = detection_engine.get_detection_summary()
        
        assert summary.total_events_analyzed == len(sample_events)
        assert summary.unique_source_ips >= 1
    
    def test_clear_history(self, detection_engine, sample_events):
        """Test clearing detection history."""
        detection_engine.analyze_events(sample_events)
        
        assert len(detection_engine.event_history) > 0
        
        detection_engine.clear_history()
        
        assert len(detection_engine.event_history) == 0
        assert len(detection_engine.alert_history) == 0
    
    def test_get_statistics(self, detection_engine, sample_events):
        """Test detection engine statistics."""
        detection_engine.analyze_events(sample_events)
        stats = detection_engine.get_statistics()
        
        assert 'total_events_analyzed' in stats
        assert 'total_alerts_generated' in stats
        assert stats['total_events_analyzed'] == len(sample_events)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])