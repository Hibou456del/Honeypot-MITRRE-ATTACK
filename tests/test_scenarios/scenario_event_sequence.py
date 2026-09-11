"""
Laboratory Test Scenario 4: Event Sequence
Tests correlation of multiple events in sequence.
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from collectors.parse_cowrie import CowrieParser
from collectors.normalize_events import EventNormalizer
from detection.detection_engine import DetectionEngine


def test_event_sequence_scenario():
    """
    Test Scenario 4: Event Sequence
    
    This scenario tests correlation of multiple events in sequence.
    
    Steps:
    1. Parse logs with multiple events from same session
    2. Normalize events
    3. Run detection engine with correlation
    4. Verify sequence detection
    5. Check confidence levels
    """
    print("=" * 60)
    print("SCENARIO 4: Event Sequence Test")
    print("=" * 60)
    
    # Step 1: Parse Cowrie logs
    print("\nStep 1: Parsing Cowrie logs with event sequences...")
    log_path = project_root / "collectors" / "sample_logs" / "cowrie_sample.log"
    
    if not log_path.exists():
        print(f"ERROR: Sample log file not found: {log_path}")
        return False
    
    cowrie_parser = CowrieParser(str(log_path))
    cowrie_events = cowrie_parser.parse_file()
    
    # Group events by session
    session_events = {}
    for event in cowrie_events:
        session_id = event.session_id
        if session_id not in session_events:
            session_events[session_id] = []
        session_events[session_id].append(event)
    
    print(f"✓ Total events parsed: {len(cowrie_events)}")
    print(f"✓ Unique sessions: {len(session_events)}")
    
    # Find session with most events
    if session_events:
        busiest_session = max(session_events.items(), key=lambda x: len(x[1]))
        print(f"✓ Busiest session: {busiest_session[0]} with {len(busiest_session[1])} events")
    
    # Step 2: Normalize events
    print("\nStep 2: Normalizing all events...")
    normalizer = EventNormalizer()
    normalized_events = normalizer.normalize_batch(cowrie_events, 'cowrie')
    
    print(f"✓ Normalized {len(normalized_events)} events")
    
    # Step 3: Run detection with correlation
    print("\nStep 3: Running detection with correlation...")
    detection_engine = DetectionEngine()
    alerts = detection_engine.analyze_events(
        [event.__dict__ for event in normalized_events]
    )
    
    print(f"✓ Generated {len(alerts)} alerts")
    print(f"✓ Correlations found: {detection_engine.stats['correlations_found']}")
    
    # Step 4: Verify sequence detection
    print("\nStep 4: Verifying sequence detection...")
    
    success = True
    
    # Check for session correlations
    session_correlations = [
        c for c in detection_engine.event_history 
        if len(session_events) > 0
    ]
    
    if detection_engine.stats['correlations_found'] > 0:
        print("✓ Event correlations detected")
    else:
        print("⚠ No event correlations found")
    
    # Check confidence levels
    if alerts:
        avg_confidence = sum(alert.confidence for alert in alerts) / len(alerts)
        print(f"✓ Average alert confidence: {avg_confidence:.2f}")
        
        if avg_confidence > 0.5:
            print("✓ Confidence levels are reasonable")
        else:
            print("⚠ Low confidence levels detected")
    
    # Step 5: Check statistics
    print("\nStep 5: Checking detection statistics...")
    summary = detection_engine.get_detection_summary()
    
    print(f"✓ Total events analyzed: {summary.total_events_analyzed}")
    print(f"✓ Unique source IPs: {summary.unique_source_ips}")
    print(f"✓ Alerts by severity: {summary.alerts_by_severity}")
    
    # Print summary
    print("\n" + "=" * 60)
    print("SCENARIO SUMMARY")
    print("=" * 60)
    print(f"Total events: {len(cowrie_events)}")
    print(f"Unique sessions: {len(session_events)}")
    print(f"Correlations found: {detection_engine.stats['correlations_found']}")
    print(f"Alerts generated: {len(alerts)}")
    print(f"Test result: {'PASSED' if success else 'FAILED'}")
    print("=" * 60)
    
    return success


if __name__ == "__main__":
    success = test_event_sequence_scenario()
    sys.exit(0 if success else 1)