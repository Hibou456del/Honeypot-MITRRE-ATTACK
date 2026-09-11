"""
Tests for log parsers (Cowrie and HTTP).
"""

import pytest
import json
from pathlib import Path
import sys
from datetime import datetime

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from collectors.parse_cowrie import CowrieParser, CowrieEvent
from collectors.parse_http import HTTPParser, HTTPEvent


class TestCowrieParser:
    """Test Cowrie log parser."""
    
    @pytest.fixture
    def sample_cowrie_log(self, tmp_path):
        """Create sample Cowrie log file."""
        log_file = tmp_path / "cowrie_test.log"
        sample_events = [
            {"eventid": "cowrie.session.connect", "timestamp": "2026-09-08T10:15:23Z", "src_ip": "192.168.1.100", "src_port": 54321, "dst_ip": "192.168.1.50", "dst_port": 2222, "session": "test123", "protocol": "ssh"},
            {"eventid": "cowrie.login.success", "timestamp": "2026-09-08T10:15:25Z", "src_ip": "192.168.1.100", "src_port": 54321, "dst_ip": "192.168.1.50", "dst_port": 2222, "session": "test123", "username": "admin", "method": "password"},
            {"eventid": "cowrie.command.input", "timestamp": "2026-09-08T10:15:30Z", "src_ip": "192.168.1.100", "src_port": 54321, "dst_ip": "192.168.1.50", "dst_port": 2222, "session": "test123", "username": "admin", "input": "whoami"}
        ]
        
        with open(log_file, 'w') as f:
            for event in sample_events:
                f.write(json.dumps(event) + '\n')
        
        return log_file
    
    def test_parser_initialization(self, sample_cowrie_log):
        """Test parser initialization."""
        parser = CowrieParser(str(sample_cowrie_log))
        assert parser.log_path == sample_cowrie_log
        assert parser.event_count == 0
        assert parser.error_count == 0
    
    def test_parse_file(self, sample_cowrie_log):
        """Test parsing entire file."""
        parser = CowrieParser(str(sample_cowrie_log))
        events = parser.parse_file()
        
        assert len(events) == 3
        assert parser.event_count == 3
        assert parser.error_count == 0
    
    def test_parse_connect_event(self, sample_cowrie_log):
        """Test parsing session connect event."""
        parser = CowrieParser(str(sample_cowrie_log))
        events = parser.parse_file()
        
        connect_event = events[0]
        assert connect_event.event_type == 'session_connect'
        assert connect_event.source_ip == '192.168.1.100'
        assert connect_event.session_id == 'test123'
    
    def test_parse_login_success(self, sample_cowrie_log):
        """Test parsing login success event."""
        parser = CowrieParser(str(sample_cowrie_log))
        events = parser.parse_file()
        
        login_event = events[1]
        assert login_event.event_type == 'login_success'
        assert login_event.username == 'admin'
        assert login_event.command is None
    
    def test_parse_command_input(self, sample_cowrie_log):
        """Test parsing command input event."""
        parser = CowrieParser(str(sample_cowrie_log))
        events = parser.parse_file()
        
        command_event = events[2]
        assert command_event.event_type == 'command_execution'
        assert command_event.command == 'whoami'
        assert command_event.username == 'admin'
    
    def test_parse_invalid_json(self, tmp_path):
        """Test parsing invalid JSON."""
        log_file = tmp_path / "invalid.log"
        with open(log_file, 'w') as f:
            f.write("invalid json content\n")
        
        parser = CowrieParser(str(log_file))
        events = parser.parse_file()
        
        assert len(events) == 0
        assert parser.error_count == 1
    
    def test_get_statistics(self, sample_cowrie_log):
        """Test parser statistics."""
        parser = CowrieParser(str(sample_cowrie_log))
        parser.parse_file()
        
        stats = parser.get_statistics()
        assert stats['total_events'] == 3
        assert stats['error_count'] == 0
        assert stats['success_rate'] == 100.0


class TestHTTPParser:
    """Test HTTP log parser."""
    
    @pytest.fixture
    def sample_http_log(self, tmp_path):
        """Create sample HTTP log file."""
        log_file = tmp_path / "http_test.log"
        sample_events = [
            {"timestamp": "2026-09-08T10:30:00Z", "source_ip": "192.168.1.102", "source_port": 54323, "destination_ip": "192.168.1.50", "destination_port": 8080, "method": "GET", "path": "/admin", "user_agent": "Mozilla/5.0", "status": 200},
            {"timestamp": "2026-09-08T10:30:05Z", "source_ip": "192.168.1.102", "source_port": 54323, "destination_ip": "192.168.1.50", "destination_port": 8080, "method": "POST", "path": "/login", "user_agent": "Mozilla/5.0", "status": 401, "post_data": {"username": "admin", "password": "test123"}}
        ]
        
        with open(log_file, 'w') as f:
            for event in sample_events:
                f.write(json.dumps(event) + '\n')
        
        return log_file
    
    def test_http_parser_initialization(self, sample_http_log):
        """Test HTTP parser initialization."""
        parser = HTTPParser(str(sample_http_log))
        assert parser.log_path == sample_http_log
    
    def test_parse_http_file(self, sample_http_log):
        """Test parsing HTTP log file."""
        parser = HTTPParser(str(sample_http_log))
        events = parser.parse_file()
        
        assert len(events) == 2
        assert parser.event_count == 2
    
    def test_sql_injection_detection(self, sample_http_log):
        """Test SQL injection detection."""
        log_file = Path(sample_http_log).parent / "sqli_test.log"
        with open(log_file, 'w') as f:
            f.write(json.dumps({
                "timestamp": "2026-09-08T10:30:10Z",
                "source_ip": "192.168.1.103",
                "method": "GET",
                "path": "/index.php?id=1' OR '1'='1",
                "status": 500
            }) + '\n')
        
        parser = HTTPParser(str(log_file))
        events = parser.parse_file()
        
        assert len(events) == 1
        assert events[0].event_type == 'sql_injection_attempt'
    
    def test_admin_access_detection(self, sample_http_log):
        """Test admin panel access detection."""
        log_file = Path(sample_http_log).parent / "admin_test.log"
        with open(log_file, 'w') as f:
            f.write(json.dumps({
                "timestamp": "2026-09-08T10:30:15Z",
                "source_ip": "192.168.1.104",
                "method": "GET",
                "path": "/admin",
                "status": 200
            }) + '\n')
        
        parser = HTTPParser(str(log_file))
        events = parser.parse_file()
        
        assert len(events) == 1
        assert events[0].event_type == 'admin_panel_access'


if __name__ == "__main__":
    pytest.main([__file__, "-v"])