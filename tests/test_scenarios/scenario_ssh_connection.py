"""
Laboratory Test Scenario 1: SSH Connection
Tests SSH connection to Cowrie honeypot and verifies the complete pipeline.
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


def test_ssh_connection_scenario():
    """
    Test Scenario 1: SSH Connection
    
    This scenario simulates an SSH connection to the Cowrie honeypot
    and verifies that the complete pipeline works correctly.
    
    Steps:
    1. Parse Cowrie SSH connection logs
    2. Normalize events to standard format
    3. Map events to MITRE ATT&CK techniques
    4. Run detection engine
    5. Verify results
    """
    print("=" * 60)
    print("SCENARIO 1: SSH Connection Test")
    print("=" * 60)
    
    # Step 1: Parse Cowrie logs
    print("\nStep 1: Parsing Cowrie logs...")
    log_path = project_root / "collectors" / "sample_logs" / "cowrie_sample.log"
    
    if not log_path.exists():
        print(f"ERROR: Sample log file not found: {log_path}")
        return False
    
    cowrie_parser = CowrieParser(str(log_path))
    cowrie_events = cowrie_parser.parse_file()
    
    print(f"✓ Parsed {len(cowrie_events)} Cowrie events")
    print(f"✓ Parser statistics: {cowrie_parser.get_statistics()}")
    
    # Step 2: Normalize events
    print("\nStep 2: Normalizing events...")
    normalizer = EventNormalizer()
    normalized_events = normalizer.normalize_batch(cowrie_events, 'cowrie')
    
    print(f"✓ Normalized {len(normalized_events)} events")
    
    # Step 3: Map to MITRE ATT&CK
    print("\nStep 3: Mapping to MITRE ATT&CK...")
    mitre_mapper = MiteMapper()
    mapping_results = mitre_mapper.map_events_batch(
        [event.__dict__ for event in normalized_events]
    )
    
    print(f"✓ Mapped {len(mapping_results)} events to MITRE techniques")
    
    # Count techniques
    technique_counts = {}
    for result in mapping_results:
        if result.primary_technique:
            tid = result.primary_technique.technique_id
            technique_counts[tid] = technique_counts.get(tid, 0) + 1
    
    print(f"✓ Techniques identified: {technique_counts}")
    
    # Step 4: Run detection engine
    print("\nStep 4: Running detection engine...")
    detection_engine = DetectionEngine()
    alerts = detection_engine.analyze_events(
        [event.__dict__ for event in normalized_events]
    )
    
    print(f"✓ Generated {len(alerts)} alerts")
    
    # Step 5: Verify results
    print("\nStep 5: Verifying results...")
    
    success = True
    
    # Verify events were parsed
    if len(cowrie_events) == 0:
        print("✗ No events parsed")
        success = False
    else:
        print("✓ Events parsed successfully")
    
    # Verify normalization
    if len(normalized_events) != len(cowrie_events):
        print("✗ Normalization failed - event count mismatch")
        success = False
    else:
        print("✓ Events normalized successfully")
    
    # Verify MITRE mapping
    if len(mapping_results) == 0:
        print("✗ No MITRE mappings generated")
        success = False
    else:
        print("✓ MITRE mapping completed")
    
    # Verify detection
    if len(alerts) == 0:
        print("⚠ No alerts generated (may be expected for benign traffic)")
    else:
        print(f"✓ Detection engine generated {len(alerts)} alerts")
    
    # Print summary
    print("\n" + "=" * 60)
    print("SCENARIO SUMMARY")
    print("=" * 60)
    print(f"Cowrie events parsed: {len(cowrie_events)}")
    print(f"Events normalized: {len(normalized_events)}")
    print(f"MITRE mappings: {len(mapping_results)}")
    print(f"Alerts generated: {len(alerts)}")
    print(f"Test result: {'PASSED' if success else 'FAILED'}")
    print("=" * 60)
    
    return success


if __name__ == "__main__":
    success = test_ssh_connection_scenario()
    sys.exit(0 if success else 1)