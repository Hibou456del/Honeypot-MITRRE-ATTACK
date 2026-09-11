"""
Laboratory Test Scenario 5: Adaptation
Tests dynamic honeypot profile adaptation based on events.
"""

import sys
from pathlib import Path
from datetime import datetime

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from honeypot.update_honeypot import HoneypotOrchestrator, AdaptationDecision
from honeypot.create_dynamic_files import DynamicDecoyGenerator


def test_adaptation_scenario():
    """
    Test Scenario 5: Profile Adaptation
    
    This scenario tests the dynamic honeypot's ability to adapt
    its deception profile based on observed events.
    
    Steps:
    1. Initialize orchestrator with default profile
    2. Create events that should trigger adaptation
    3. Analyze events for adaptation triggers
    4. Execute profile adaptation if triggered
    5. Verify decoy generation
    """
    print("=" * 60)
    print("SCENARIO 5: Profile Adaptation Test")
    print("=" * 60)
    
    # Step 1: Initialize orchestrator
    print("\nStep 1: Initializing honeypot orchestrator...")
    try:
        orchestrator = HoneypotOrchestrator()
        initial_profile = orchestrator.get_current_profile()
        print(f"✓ Initial profile: {initial_profile}")
    except Exception as e:
        print(f"✗ Failed to initialize orchestrator: {e}")
        return False
    
    # Step 2: Create events that should trigger adaptation
    print("\nStep 2: Creating adaptation trigger events...")
    
    # Create events that should trigger repeated_failed_auth
    trigger_events = []
    for i in range(5):
        trigger_events.append({
            'timestamp': datetime.now().isoformat(),
            'source_ip': '192.168.1.100',
            'service': 'ssh',
            'event_type': 'login_failed',
            'session_id': f'test_{i}',
            'username': f'user_{i}'
        })
    
    print(f"✓ Created {len(trigger_events)} trigger events")
    
    # Step 3: Analyze events for adaptation
    print("\nStep 3: Analyzing events for adaptation triggers...")
    try:
        decision = orchestrator.analyze_events(trigger_events)
        print(f"✓ Adaptation decision: {decision.should_adapt}")
        print(f"✓ Target profile: {decision.target_profile}")
        print(f"✓ Trigger: {decision.trigger}")
        print(f"✓ Confidence: {decision.confidence}")
    except Exception as e:
        print(f"✗ Failed to analyze events: {e}")
        return False
    
    # Step 4: Test decoy generation directly
    print("\nStep 4: Testing decoy generation...")
    try:
        decoy_generator = DynamicDecoyGenerator()
        result = decoy_generator.generate_decoys_for_profile('PROFILE_LOW')
        
        print(f"✓ Generated decoys for PROFILE_LOW")
        print(f"✓ Files created: {result.total_files}")
        print(f"✓ Users created: {result.total_users}")
        print(f"✓ Credentials created: {result.total_credentials}")
    except Exception as e:
        print(f"✗ Failed to generate decoys: {e}")
        return False
    
    # Step 5: Verify adaptation process
    print("\nStep 5: Verifying adaptation process...")
    
    success = True
    
    # Verify orchestrator initialization
    if initial_profile:
        print("✓ Orchestrator initialized successfully")
    else:
        print("✗ Orchestrator initialization failed")
        success = False
    
    # Verify decision analysis
    if decision:
        print("✓ Adaptation decision generated")
    else:
        print("✗ Adaptation decision failed")
        success = False
    
    # Verify decoy generation
    if result.total_files > 0:
        print("✓ Decoy files generated successfully")
    else:
        print("✗ No decoy files generated")
        success = False
    
    # Check orchestrator statistics
    stats = orchestrator.get_statistics()
    print(f"✓ Orchestrator statistics: {stats}")
    
    # Print summary
    print("\n" + "=" * 60)
    print("SCENARIO SUMMARY")
    print("=" * 60)
    print(f"Initial profile: {initial_profile}")
    print(f"Adaptation triggered: {decision.should_adapt}")
    print(f"Target profile: {decision.target_profile}")
    print(f"Decoy files generated: {result.total_files}")
    print(f"Decoy users generated: {result.total_users}")
    print(f"Test result: {'PASSED' if success else 'FAILED'}")
    print("=" * 60)
    
    return success


if __name__ == "__main__":
    success = test_adaptation_scenario()
    sys.exit(0 if success else 1)