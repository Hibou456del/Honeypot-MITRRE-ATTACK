"""
Flask application for the Dynamic Honeypot Platform Dashboard.
Provides web interface for monitoring and analysis.
"""

from flask import Flask, render_template, jsonify, request
from pathlib import Path
import json
from datetime import datetime
from typing import Dict, List, Any

# Initialize Flask app
app = Flask(__name__,
            template_folder=str(Path(__file__).parent / 'templates'),
            static_folder=str(Path(__file__).parent / 'static'))

app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production'

# Sample data for dashboard (in production, this would come from database)
SAMPLE_EVENTS = []
SAMPLE_ALERTS = []
SAMPLE_MITRE_MAPPINGS = []


@app.route('/')
def index():
    """Render main dashboard page."""
    return render_template('dashboard.html')


@app.route('/api/events')
def get_events():
    """Get recent events."""
    limit = request.args.get('limit', 50, type=int)
    return jsonify({
        'events': SAMPLE_EVENTS[-limit:],
        'total': len(SAMPLE_EVENTS)
    })


@app.route('/api/alerts')
def get_alerts():
    """Get recent alerts."""
    limit = request.args.get('limit', 50, type=int)
    severity = request.args.get('severity')
    
    alerts = SAMPLE_ALERTS
    if severity:
        alerts = [a for a in alerts if a.get('severity') == severity]
    
    return jsonify({
        'alerts': alerts[-limit:],
        'total': len(alerts)
    })


@app.route('/api/mitre')
def get_mitre_mappings():
    """Get MITRE ATT&CK mappings."""
    return jsonify({
        'mappings': SAMPLE_MITRE_MAPPINGS,
        'total': len(SAMPLE_MITRE_MAPPINGS)
    })


@app.route('/api/statistics')
def get_statistics():
    """Get platform statistics."""
    return jsonify({
        'total_events': len(SAMPLE_EVENTS),
        'total_alerts': len(SAMPLE_ALERTS),
        'unique_ips': len(set(e.get('source_ip') for e in SAMPLE_EVENTS)),
        'mitre_techniques': len(set(m.get('technique_id') for m in SAMPLE_MITRE_MAPPINGS)),
        'last_updated': datetime.utcnow().isoformat() + 'Z'
    })


@app.route('/api/sessions')
def get_sessions():
    """Get session information."""
    sessions = {}
    for event in SAMPLE_EVENTS:
        session_id = event.get('session_id', 'unknown')
        if session_id not in sessions:
            sessions[session_id] = {
                'session_id': session_id,
                'source_ip': event.get('source_ip'),
                'event_count': 0,
                'first_event': event.get('timestamp'),
                'last_event': event.get('timestamp')
            }
        sessions[session_id]['event_count'] += 1
        sessions[session_id]['last_event'] = event.get('timestamp')
    
    return jsonify({
        'sessions': list(sessions.values()),
        'total': len(sessions)
    })


def add_sample_data():
    """Add sample data for demonstration."""
    global SAMPLE_EVENTS, SAMPLE_ALERTS, SAMPLE_MITRE_MAPPINGS
    
    # Sample events
    SAMPLE_EVENTS = [
        {
            'timestamp': '2026-09-08T10:15:23Z',
            'source_ip': '192.168.1.100',
            'service': 'ssh',
            'event_type': 'session_connect',
            'session_id': 'abc123',
            'severity': 'info'
        },
        {
            'timestamp': '2026-09-08T10:15:25Z',
            'source_ip': '192.168.1.100',
            'service': 'ssh',
            'event_type': 'login_success',
            'session_id': 'abc123',
            'username': 'admin',
            'severity': 'medium'
        },
        {
            'timestamp': '2026-09-08T10:15:30Z',
            'source_ip': '192.168.1.100',
            'service': 'ssh',
            'event_type': 'command_execution',
            'session_id': 'abc123',
            'command': 'whoami',
            'severity': 'low'
        },
        {
            'timestamp': '2026-09-08T10:20:00Z',
            'source_ip': '192.168.1.101',
            'service': 'ssh',
            'event_type': 'login_failed',
            'session_id': 'def456',
            'username': 'root',
            'severity': 'high'
        }
    ]
    
    # Sample alerts
    SAMPLE_ALERTS = [
        {
            'alert_id': 'alert_1',
            'timestamp': '2026-09-08T10:20:14Z',
            'rule_name': 'repeated_failed_auth',
            'severity': 'high',
            'source_ip': '192.168.1.101',
            'message': 'Multiple failed login attempts from 192.168.1.101',
            'confidence': 0.8
        }
    ]
    
    # Sample MITRE mappings
    SAMPLE_MITRE_MAPPINGS = [
        {
            'technique_id': 'T1110',
            'technique_name': 'Brute Force',
            'tactic': 'Credential Access',
            'confidence': 0.8,
            'event_count': 5
        },
        {
            'technique_id': 'T1033',
            'technique_name': 'System Owner/User Discovery',
            'tactic': 'Discovery',
            'confidence': 0.7,
            'event_count': 3
        }
    ]


def run_dashboard(host='0.0.0.0', port=8000, debug=True):
    """
    Run the Flask dashboard.
    
    Args:
        host: Host to bind to
        port: Port to bind to
        debug: Enable debug mode
    """
    # Add sample data
    add_sample_data()
    
    print(f"Starting Dynamic Honeypot Dashboard on http://{host}:{port}")
    app.run(host=host, port=port, debug=debug)


if __name__ == '__main__':
    run_dashboard()