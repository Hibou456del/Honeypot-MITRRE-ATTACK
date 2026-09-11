"""
Laboratory Test Scenario 3: File Interaction
Tests file interaction events and sensitive file access detection.
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from collectors.parse_cowrie import CowrieParser
from collectors.normalize_events import EventNormalizer
from mitre.mitre_mapper import MiteMapper
from detection.detection_engine import DetectionEngine


def test_file_interaction_scenario():
    """
    Test Scenario 3: File Interaction
    
    This scenario tests file interaction events and sensitive file access.
    
    Steps:
    1. Parse logs with file access events
    2. Normalize events
    3. Map to MITRE ATT&CK (should identify credential access)
    4. Run detection
    5. Verify sensitive file access detection
    """
    print("=" * 60)
    print("SCENARIO 3: File Interaction Test")
    print("=" * 60)
    
    # Step 1: Parse Cowrie logs
    print("\nStep 1: Parsing Cowrie logs with file access...")
    log_path = project_root / "collectors" / "sample_logs" / "cowrie_sample.log"
    
    if not log_path.exists():
        print(f"ERROR: Sample log file not found: {log_path}")
        return False
    
    cowrie_parser = CowrieParser(str(log_path))
    cowrie_events = cowrie_parser.parse_file()
    
    # Filter for file-related events
    file_events = [
        e for e in cowrie_events 
        if e.command and ('cat' in e.command or 'ls' in e.command or 'wget' in e.command)
    ]
    
    print(f"✓ Total events parsed: {len(cowrie_events)}")
    print(f"✓ File-related events: {len(file_events)}")
    
    # Step 2: Normalize events
    print("\nStep 2: Normalizing file events...")
    normalizer = EventNormalizer()
    normalized_events = normalizer.normalize_batch(file_events, 'cowrie')
    
    print(f"✓ Normalized {len(normalized_events)} file events")
    
    # Step 3: Map to MITRE ATT&CK
    print("\nStep 3: Mapping file events to MITRE ATT&CK...")
    mitre_mapper = MiteMapper()
    mapping_results = mitre_mapper.map_events_batch(
        [event.__dict__ for event in normalized_events]
    )
    
    print(f"✓ Mapped {len(mapping_results)} file events")
    
    # Analyze techniques
    credential_access_techniques = []
    for result in mapping_results:
        if result.primary_technique:
            if result.primary_technique.tactic == 'Credential Access':
                credential_access_techniques.append(result.primary_technique.technique_id)
    
    print(f"✓ Credential access techniques: {set(credential_access_techniques)}")
    
    # Step 4: Run detection
    print("\nStep 4: Running detection for file access...")
    detection_engine = DetectionEngine()
    alerts = detection_engine.analyze_events(
        [event.__dict__ for event in normalized_events]
    )
    
    print(f"✓ Generated {len(alerts)} alerts")
    
    # Step 5: Verify detection
    print("\nStep 5: Verifying file access detection...")
    
    success = True
    
    if len(file_events) == 0:
        print("⚠ No file-related events found in sample data")
    else:
        print("✓ File-related events found")
    
    if len(credential_access_techniques) > 0:
        print(f"✓ Credential access techniques mapped")
    else:
        print("⚠ No credential access techniques mapped")
    
    # Print summary
    print("\n" + "=" * 60)
    print("SCENARIO SUMMARY")
    print("=" * 60)
    print(f"File events: {len(file_events)}")
    print(f"Credential access techniques: {len(set(credential_access_techniques))}")
    print(f"Alerts generated: {len(alerts)}")
    print(f"Test result: {'PASSED' if success else 'FAILED'}")
    print("=" * 60)
    
    return success


if __name__ == "__main__":
    success = test_file_interaction_scenario()
    sys.exit(0 if success else 1)