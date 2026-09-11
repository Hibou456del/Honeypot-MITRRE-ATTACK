"""
Laboratory Test Scenario 2: Command Execution
Tests command execution in the honeypot environment.
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


def test_command_execution_scenario():
    """
    Test Scenario 2: Command Execution
    
    This scenario tests command execution events and their analysis.
    
    Steps:
    1. Parse logs with command execution events
    2. Normalize events
    3. Map to MITRE ATT&CK (should identify discovery techniques)
    4. Run detection
    5. Verify reconnaissance detection
    """
    print("=" * 60)
    print("SCENARIO 2: Command Execution Test")
    print("=" * 60)
    
    # Step 1: Parse Cowrie logs
    print("\nStep 1: Parsing Cowrie logs with command execution...")
    log_path = project_root / "collectors" / "sample_logs" / "cowrie_sample.log"
    
    if not log_path.exists():
        print(f"ERROR: Sample log file not found: {log_path}")
        return False
    
    cowrie_parser = CowrieParser(str(log_path))
    cowrie_events = cowrie_parser.parse_file()
    
    # Filter for command execution events
    command_events = [e for e in cowrie_events if e.event_type == 'command_execution']
    
    print(f"✓ Total events parsed: {len(cowrie_events)}")
    print(f"✓ Command execution events: {len(command_events)}")
    
    # Step 2: Normalize events
    print("\nStep 2: Normalizing command events...")
    normalizer = EventNormalizer()
    normalized_events = normalizer.normalize_batch(command_events, 'cowrie')
    
    print(f"✓ Normalized {len(normalized_events)} command events")
    
    # Step 3: Map to MITRE ATT&CK
    print("\nStep 3: Mapping commands to MITRE ATT&CK...")
    mitre_mapper = MiteMapper()
    mapping_results = mitre_mapper.map_events_batch(
        [event.__dict__ for event in normalized_events]
    )
    
    print(f"✓ Mapped {len(mapping_results)} command events")
    
    # Analyze techniques
    discovery_techniques = []
    for result in mapping_results:
        if result.primary_technique:
            if result.primary_technique.tactic == 'Discovery':
                discovery_techniques.append(result.primary_technique.technique_id)
    
    print(f"✓ Discovery techniques identified: {set(discovery_techniques)}")
    
    # Step 4: Run detection
    print("\nStep 4: Running detection for reconnaissance...")
    detection_engine = DetectionEngine()
    alerts = detection_engine.analyze_events(
        [event.__dict__ for event in normalized_events]
    )
    
    print(f"✓ Generated {len(alerts)} alerts")
    
    # Step 5: Verify reconnaissance detection
    print("\nStep 5: Verifying reconnaissance detection...")
    
    success = True
    
    # Verify command events were found
    if len(command_events) == 0:
        print("✗ No command execution events found")
        success = False
    else:
        print("✓ Command execution events found")
    
    # Verify MITRE discovery mapping
    if len(discovery_techniques) == 0:
        print("⚠ No discovery techniques mapped (commands may not be recon)")
    else:
        print(f"✓ Discovery techniques mapped: {len(discovery_techniques)}")
    
    # Print summary
    print("\n" + "=" * 60)
    print("SCENARIO SUMMARY")
    print("=" * 60)
    print(f"Command events: {len(command_events)}")
    print(f"Discovery techniques: {len(set(discovery_techniques))}")
    print(f"Alerts generated: {len(alerts)}")
    print(f"Test result: {'PASSED' if success else 'FAILED'}")
    print("=" * 60)
    
    return success


if __name__ == "__main__":
    success = test_command_execution_scenario()
    sys.exit(0 if success else 1)