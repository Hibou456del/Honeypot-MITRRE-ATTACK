"""
Dynamic honeypot orchestrator for the Dynamic Honeypot Platform.
Analyzes events and adapts deception profiles based on observed behaviors.
"""

import json
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from utils.logger import get_logger
from utils.config_loader import ConfigLoader
from utils.file_utils import FileUtils
from utils.date_utils import DateUtils
from create_dynamic_files import DynamicDecoyGenerator, DecoyGenerationResult


@dataclass
class ProfileTransition:
    """Profile transition record."""
    timestamp: str
    from_profile: str
    to_profile: str
    trigger_event: str
    reason: str
    confidence: float


@dataclass
class AdaptationDecision:
    """Decision to adapt honeypot profile."""
    should_adapt: bool
    target_profile: str
    trigger: str
    confidence: float
    reason: str


class HoneypotOrchestrator:
    """Orchestrates dynamic honeypot adaptation based on events."""
    
    def __init__(self, config_dir: str = "config"):
        """
        Initialize honeypot orchestrator.
        
        Args:
            config_dir: Directory containing configuration files
        """
        self.config_loader = ConfigLoader(config_dir)
        self.logger = get_logger("HoneypotOrchestrator")
        
        # Load configuration
        self.settings = self.config_loader.load_settings("settings.yaml")
        self.profiles_config = self.config_loader.load_yaml("honeypot_profiles.yaml")
        self.detection_rules = self.config_loader.load_yaml("detection_rules.yaml")
        
        # Initialize components
        self.decoy_generator = DynamicDecoyGenerator(config_dir)
        
        # State
        self.current_profile = self.settings.deception.get('default_profile', 'PROFILE_LOW')
        self.last_adaptation = None
        self.adaptation_cooldown = self.settings.deception.get('adaptation_cooldown', 600)
        self.transition_history: List[ProfileTransition] = []
        
        # Event analysis state
        self.event_buffer: List[Dict[str, Any]] = []
        self.trigger_counts: Dict[str, int] = {}
        
        self.logger.info(f"Orchestrator initialized with profile: {self.current_profile}")
    
    def analyze_events(self, events: List[Dict[str, Any]]) -> AdaptationDecision:
        """
        Analyze events and determine if profile adaptation is needed.
        
        Args:
            events: List of normalized events
            
        Returns:
            AdaptationDecision with recommendation
        """
        self.logger.info(f"Analyzing {len(events)} events for adaptation")
        
        # Add events to buffer
        self.event_buffer.extend(events)
        
        # Analyze triggers
        decision = self._evaluate_triggers()
        
        if decision.should_adapt:
            self.logger.info(
                f"Adaptation recommended: {self.current_profile} -> {decision.target_profile} "
                f"(trigger: {decision.trigger}, confidence: {decision.confidence})"
            )
        
        return decision
    
    def _evaluate_triggers(self) -> AdaptationDecision:
        """Evaluate triggers based on event buffer."""
        current_time = DateUtils.now()
        
        # Check cooldown
        if self.last_adaptation:
            time_since_adaptation = DateUtils.seconds_between(
                self.last_adaptation, current_time
            )
            if time_since_adaptation < self.adaptation_cooldown:
                self.logger.debug("Adaptation cooldown active")
                return AdaptationDecision(
                    should_adapt=False,
                    target_profile=self.current_profile,
                    trigger="cooldown",
                    confidence=0.0,
                    reason="Adaptation cooldown active"
                )
        
        # Get current profile configuration
        profile_config = self.profiles_config['profiles'].get(self.current_profile)
        if not profile_config:
            self.logger.error(f"Current profile not found: {self.current_profile}")
            return AdaptationDecision(
                should_adapt=False,
                target_profile=self.current_profile,
                trigger="error",
                confidence=0.0,
                reason="Profile configuration error"
            )
        
        # Evaluate adaptation rules
        adaptation_rules = profile_config.get('adaptation_rules', [])
        triggers_config = self.profiles_config.get('triggers', {})
        
        for rule in adaptation_rules:
            trigger_name = rule.get('trigger')
            target_profile = rule.get('target_profile')
            rule_confidence = rule.get('confidence', 0.5)
            
            # Check if trigger condition is met
            if self._check_trigger(trigger_name, triggers_config):
                return AdaptationDecision(
                    should_adapt=True,
                    target_profile=target_profile,
                    trigger=trigger_name,
                    confidence=rule_confidence,
                    reason=f"Trigger '{trigger_name}' detected"
                )
        
        return AdaptationDecision(
            should_adapt=False,
            target_profile=self.current_profile,
            trigger="none",
            confidence=0.0,
            reason="No adaptation triggers detected"
        )
    
    def _check_trigger(self, trigger_name: str, triggers_config: Dict[str, Any]) -> bool:
        """
        Check if a specific trigger condition is met.
        
        Args:
            trigger_name: Name of the trigger
            triggers_config: Trigger configuration
            
        Returns:
            True if trigger condition is met
        """
        trigger_config = triggers_config.get(trigger_name)
        if not trigger_config:
            return False
        
        detection = trigger_config.get('detection', {})
        
        # Check different trigger types
        if 'event_type' in detection:
            return self._check_event_type_trigger(detection)
        elif 'command_patterns' in detection:
            return self._check_command_pattern_trigger(detection)
        elif 'file_patterns' in detection:
            return self._check_file_pattern_trigger(detection)
        elif 'http_patterns' in detection:
            return self._check_http_pattern_trigger(detection)
        
        return False
    
    def _check_event_type_trigger(self, detection: Dict[str, Any]) -> bool:
        """Check event type trigger condition."""
        event_type = detection.get('event_type')
        count = detection.get('count', 1)
        window = detection.get('window', 60)
        
        # Filter events in time window
        current_time = DateUtils.now()
        window_start = DateUtils.subtract_seconds(current_time, window)
        
        matching_events = [
            event for event in self.event_buffer
            if event.get('event_type') == event_type
            and DateUtils.from_iso_string(event.get('timestamp', ''))
            and DateUtils.is_within_window(
                DateUtils.from_iso_string(event.get('timestamp', '')),
                window_start,
                current_time
            )
        ]
        
        return len(matching_events) >= count
    
    def _check_command_pattern_trigger(self, detection: Dict[str, Any]) -> bool:
        """Check command pattern trigger condition."""
        patterns = detection.get('command_patterns', [])
        count = detection.get('count', 1)
        window = detection.get('window', 60)
        
        current_time = DateUtils.now()
        window_start = DateUtils.subtract_seconds(current_time, window)
        
        matching_events = 0
        for event in self.event_buffer:
            command = event.get('command', '')
            timestamp = event.get('timestamp', '')
            
            if not command or not timestamp:
                continue
            
            event_time = DateUtils.from_iso_string(timestamp)
            if not event_time:
                continue
            
            if not DateUtils.is_within_window(event_time, window_start, current_time):
                continue
            
            # Check if command matches any pattern
            for pattern in patterns:
                if pattern.lower() in command.lower():
                    matching_events += 1
                    break
        
        return matching_events >= count
    
    def _check_file_pattern_trigger(self, detection: Dict[str, Any]) -> bool:
        """Check file pattern trigger condition."""
        patterns = detection.get('file_patterns', [])
        count = detection.get('count', 1)
        window = detection.get('window', 60)
        
        current_time = DateUtils.now()
        window_start = DateUtils.subtract_seconds(current_time, window)
        
        matching_events = 0
        for event in self.event_buffer:
            # Check if event involves file access
            command = event.get('command', '')
            path = event.get('path', '')
            timestamp = event.get('timestamp', '')
            
            if not timestamp:
                continue
            
            event_time = DateUtils.from_iso_string(timestamp)
            if not event_time:
                continue
            
            if not DateUtils.is_within_window(event_time, window_start, current_time):
                continue
            
            # Check patterns in command or path
            text_to_check = f"{command} {path}".lower()
            for pattern in patterns:
                if pattern.lower() in text_to_check:
                    matching_events += 1
                    break
        
        return matching_events >= count
    
    def _check_http_pattern_trigger(self, detection: Dict[str, Any]) -> bool:
        """Check HTTP pattern trigger condition."""
        patterns = detection.get('http_patterns', [])
        count = detection.get('count', 1)
        window = detection.get('window', 60)
        
        current_time = DateUtils.now()
        window_start = DateUtils.subtract_seconds(current_time, window)
        
        matching_events = 0
        for event in self.event_buffer:
            path = event.get('path', '')
            timestamp = event.get('timestamp', '')
            
            if not path or not timestamp:
                continue
            
            event_time = DateUtils.from_iso_string(timestamp)
            if not event_time:
                continue
            
            if not DateUtils.is_within_window(event_time, window_start, current_time):
                continue
            
            # Check if path matches any pattern
            for pattern in patterns:
                if pattern.lower() in path.lower():
                    matching_events += 1
                    break
        
        return matching_events >= count
    
    def adapt_profile(self, decision: AdaptationDecision) -> Optional[DecoyGenerationResult]:
        """
        Adapt honeypot profile based on decision.
        
        Args:
            decision: Adaptation decision
            
        Returns:
            DecoyGenerationResult if adaptation performed
        """
        if not decision.should_adapt:
            self.logger.info("No adaptation needed")
            return None
        
        if decision.target_profile == self.current_profile:
            self.logger.info("Already at target profile")
            return None
        
        self.logger.info(f"Adapting profile: {self.current_profile} -> {decision.target_profile}")
        
        # Generate decoys for new profile
        try:
            generation_result = self.decoy_generator.generate_decoys_for_profile(
                decision.target_profile
            )
            
            # Record transition
            transition = ProfileTransition(
                timestamp=datetime.now().isoformat(),
                from_profile=self.current_profile,
                to_profile=decision.target_profile,
                trigger_event=decision.trigger,
                reason=decision.reason,
                confidence=decision.confidence
            )
            
            self.transition_history.append(transition)
            self.current_profile = decision.target_profile
            self.last_adaptation = DateUtils.now()
            
            # Clear event buffer after adaptation
            self.event_buffer.clear()
            
            self.logger.info(
                f"Profile adaptation completed: {generation_result.total_files} files, "
                f"{generation_result.total_users} users generated"
            )
            
            return generation_result
            
        except Exception as e:
            self.logger.error(f"Error adapting profile: {e}")
            return None
    
    def get_current_profile(self) -> str:
        """Get current profile name."""
        return self.current_profile
    
    def get_transition_history(self) -> List[ProfileTransition]:
        """Get profile transition history."""
        return self.transition_history
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get orchestrator statistics.
        
        Returns:
            Dictionary with statistics
        """
        return {
            'current_profile': self.current_profile,
            'total_transitions': len(self.transition_history),
            'last_adaptation': self.last_adaptation.isoformat() if self.last_adaptation else None,
            'buffered_events': len(self.event_buffer),
            'cooldown_remaining': max(0, self.adaptation_cooldown - (
                DateUtils.seconds_between(self.last_adaptation, DateUtils.now())
                if self.last_adaptation else self.adaptation_cooldown
            ))
        }
    
    def save_state(self, state_file: str = "data/orchestrator_state.json"):
        """
        Save orchestrator state to file.
        
        Args:
            state_file: Path to state file
        """
        state = {
            'current_profile': self.current_profile,
            'last_adaptation': self.last_adaptation.isoformat() if self.last_adaptation else None,
            'transition_history': [asdict(t) for t in self.transition_history],
            'saved_at': datetime.now().isoformat()
        }
        
        FileUtils.save_json(state_file, state)
        self.logger.info(f"Orchestrator state saved to {state_file}")
    
    def load_state(self, state_file: str = "data/orchestrator_state.json"):
        """
        Load orchestrator state from file.
        
        Args:
            state_file: Path to state file
        """
        state_data = FileUtils.load_json(state_file)
        if state_data:
            self.current_profile = state_data.get('current_profile', 'PROFILE_LOW')
            
            last_adaptation_str = state_data.get('last_adaptation')
            if last_adaptation_str:
                self.last_adaptation = DateUtils.from_iso_string(last_adaptation_str)
            
            transitions = state_data.get('transition_history', [])
            self.transition_history = [
                ProfileTransition(**t) for t in transitions
            ]
            
            self.logger.info(f"Orchestrator state loaded from {state_file}")


def analyze_and_adapt(events: List[Dict[str, Any]]) -> Optional[DecoyGenerationResult]:
    """
    Convenience function to analyze events and adapt if needed.
    
    Args:
        events: List of normalized events
        
    Returns:
        DecoyGenerationResult if adaptation performed
    """
    orchestrator = HoneypotOrchestrator()
    decision = orchestrator.analyze_events(events)
    
    if decision.should_adapt:
        return orchestrator.adapt_profile(decision)
    
    return None


if __name__ == "__main__":
    # Example usage
    orchestrator = HoneypotOrchestrator()
    
    # Analyze sample events
    sample_events = [
        {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'login_failed',
            'source_ip': '192.168.1.100',
            'command': None
        }
    ]
    
    decision = orchestrator.analyze_events(sample_events)
    print(f"Adaptation decision: {decision}")
    
    if decision.should_adapt:
        result = orchestrator.adapt_profile(decision)
        print(f"Adaptation result: {result}")