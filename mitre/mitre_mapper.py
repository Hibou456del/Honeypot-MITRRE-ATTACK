"""
MITRE ATT&CK mapper for the Dynamic Honeypot Platform.
Maps observed events to MITRE ATT&CK techniques with confidence scoring.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from utils.logger import get_logger
from utils.config_loader import ConfigLoader
from utils.date_utils import DateUtils


@dataclass
class TechniqueMapping:
    """MITRE ATT&CK technique mapping result."""
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float
    reason: str
    source_event: Dict[str, Any]
    mapping_id: str
    timestamp: str
    required_fields: List[str]
    boost_factors: Dict[str, float]


@dataclass
class MappingResult:
    """Complete mapping result for an event."""
    event: Dict[str, Any]
    techniques: List[TechniqueMapping]
    primary_technique: Optional[TechniqueMapping]
    overall_confidence: float
    timestamp: str


class MiteMapper:
    """Maps honeypot events to MITRE ATT&CK techniques."""
    
    def __init__(self, config_dir: str = "config"):
        """
        Initialize MITRE mapper.
        
        Args:
            config_dir: Directory containing configuration files
        """
        self.config_loader = ConfigLoader(config_dir)
        self.logger = get_logger("MiteMapper")
        
        # Load configuration
        self.settings = self.config_loader.load_settings("settings.yaml")
        self.mapping_config = self.config_loader.load_json("mitre_attack_mapping.json")
        
        # Validate mapping configuration
        self._validate_mapping_config()
        
        # Statistics
        self.stats = {
            'total_events_mapped': 0,
            'total_techniques_identified': 0,
            'mapping_count_by_technique': {},
            'average_confidence': 0.0
        }
    
    def _validate_mapping_config(self):
        """Validate MITRE mapping configuration."""
        if not self.mapping_config:
            raise ValueError("MITRE mapping configuration is empty")
        
        if 'mappings' not in self.mapping_config:
            raise ValueError("MITRE mapping configuration missing 'mappings' key")
        
        self.logger.info(
            f"Loaded {len(self.mapping_config['mappings'])} MITRE technique mappings"
        )
    
    def map_event(self, event: Dict[str, Any]) -> MappingResult:
        """
        Map a single event to MITRE ATT&CK techniques.
        
        Args:
            event: Normalized event dictionary
            
        Returns:
            MappingResult with technique mappings
        """
        self.logger.debug(f"Mapping event: {event.get('event_type', 'unknown')}")
        
        techniques = []
        
        # Try to match event against all mappings
        for mapping in self.mapping_config['mappings']:
            technique_match = self._evaluate_mapping(event, mapping)
            if technique_match:
                techniques.append(technique_match)
        
        # Determine primary technique (highest confidence)
        primary_technique = None
        if techniques:
            techniques.sort(key=lambda t: t.confidence, reverse=True)
            primary_technique = techniques[0]
        
        # Calculate overall confidence
        overall_confidence = self._calculate_overall_confidence(techniques)
        
        # Update statistics
        self.stats['total_events_mapped'] += 1
        self.stats['total_techniques_identified'] += len(techniques)
        
        for technique in techniques:
            tid = technique.technique_id
            self.stats['mapping_count_by_technique'][tid] = \
                self.stats['mapping_count_by_technique'].get(tid, 0) + 1
        
        result = MappingResult(
            event=event,
            techniques=techniques,
            primary_technique=primary_technique,
            overall_confidence=overall_confidence,
            timestamp=DateUtils.to_iso_string(DateUtils.now())
        )
        
        self.logger.debug(
            f"Mapped event to {len(techniques)} techniques, "
            f"primary confidence: {overall_confidence:.2f}"
        )
        
        return result
    
    def _evaluate_mapping(
        self,
        event: Dict[str, Any],
        mapping: Dict[str, Any]
    ) -> Optional[TechniqueMapping]:
        """
        Evaluate if an event matches a specific mapping.
        
        Args:
            event: Event dictionary
            mapping: Mapping configuration
            
        Returns:
            TechniqueMapping if match found, None otherwise
        """
        event_pattern = mapping.get('event_pattern', '')
        base_confidence = mapping.get('confidence', 0.0)
        required_fields = mapping.get('required_fields', [])
        boost_factors = mapping.get('boost_factors', {})
        
        # Check required fields
        for field in required_fields:
            if field not in event or not event[field]:
                return None
        
        # Evaluate pattern match
        match_confidence = self._evaluate_pattern_match(event, event_pattern, base_confidence)
        
        if match_confidence <= 0:
            return None
        
        # Apply boost factors
        final_confidence = self._apply_boost_factors(event, match_confidence, boost_factors)
        
        # Ensure confidence doesn't exceed 1.0
        final_confidence = min(final_confidence, 1.0)
        
        # Check against confidence threshold
        confidence_threshold = self.settings.mitre.get('confidence_threshold', 0.5)
        if final_confidence < confidence_threshold:
            return None
        
        return TechniqueMapping(
            technique_id=mapping.get('technique_id', ''),
            technique_name=mapping.get('technique_name', ''),
            tactic=mapping.get('tactic', ''),
            confidence=final_confidence,
            reason=mapping.get('reason', ''),
            source_event=event,
            mapping_id=mapping.get('id', ''),
            timestamp=DateUtils.to_iso_string(DateUtils.now()),
            required_fields=required_fields,
            boost_factors=boost_factors
        )
    
    def _evaluate_pattern_match(
        self,
        event: Dict[str, Any],
        pattern: str,
        base_confidence: float
    ) -> float:
        """
        Evaluate if event matches pattern.
        
        Args:
            event: Event dictionary
            pattern: Event pattern string
            base_confidence: Base confidence from mapping
            
        Returns:
            Confidence score if match, 0 otherwise
        """
        # Pattern format: "event_type:specific_value" or just "event_type"
        if ':' in pattern:
            event_type, specific_value = pattern.split(':', 1)
            event_value = event.get(event_type, '')
            
            if event_value and specific_value.lower() in str(event_value).lower():
                return base_confidence
        else:
            # Simple event type match
            if event.get('event_type') == pattern:
                return base_confidence
        
        return 0.0
    
    def _apply_boost_factors(
        self,
        event: Dict[str, Any],
        base_confidence: float,
        boost_factors: Dict[str, float]
    ) -> float:
        """
        Apply confidence boost factors.
        
        Args:
            event: Event dictionary
            base_confidence: Base confidence
            boost_factors: Dictionary of boost factors
            
        Returns:
            Adjusted confidence
        """
        adjusted_confidence = base_confidence
        
        for factor_name, boost_value in boost_factors.items():
            if self._check_boost_factor(event, factor_name):
                adjusted_confidence += boost_value
        
        return adjusted_confidence
    
    def _check_boost_factor(self, event: Dict[str, Any], factor_name: str) -> bool:
        """
        Check if a specific boost factor applies.
        
        Args:
            event: Event dictionary
            factor_name: Name of boost factor
            
        Returns:
            True if factor applies
        """
        # This is a simplified implementation
        # In a real system, this would be more sophisticated
        event_type = event.get('event_type', '')
        command = event.get('command', '')
        
        if factor_name == 'repeated_attempts':
            # Would check if this is a repeated pattern
            return False
        elif factor_name == 'multiple_users':
            # Would check if multiple users involved
            return False
        elif factor_name == 'followed_by_hostname':
            # Would check if followed by hostname command
            return False
        elif factor_name == 'suspicious_domain':
            # Would check if command contains suspicious domain
            if command:
                suspicious_domains = ['malicious.com', 'evil.com', 'bad.com']
                return any(domain in command for domain in suspicious_domains)
            return False
        elif factor_name == 'followed_by_chmod':
            # Would check if followed by chmod
            return False
        elif factor_name == 'output_redirection':
            # Would check for output redirection in command
            if command:
                return '>' in command or '>>' in command
            return False
        elif factor_name == 'to_root':
            # Would check if targeting root
            if command:
                return 'root' in command or 'sudo' in command
            return False
        elif factor_name == 'executable_bit':
            # Would check for executable bit setting
            if command:
                return 'chmod +x' in command or 'chmod 755' in command
            return False
        elif factor_name == 'recursive':
            # Would check for recursive operations
            if command:
                return '-R' in command or '-r' in command or 'recursive' in command
            return False
        
        return False
    
    def _calculate_overall_confidence(self, techniques: List[TechniqueMapping]) -> float:
        """
        Calculate overall confidence from multiple technique matches.
        
        Args:
            techniques: List of technique mappings
            
        Returns:
            Overall confidence score
        """
        if not techniques:
            return 0.0
        
        # Use maximum confidence as overall confidence
        return max(t.confidence for t in techniques)
    
    def map_events_batch(self, events: List[Dict[str, Any]]) -> List[MappingResult]:
        """
        Map a batch of events to MITRE ATT&CK techniques.
        
        Args:
            events: List of normalized events
            
        Returns:
            List of MappingResult objects
        """
        results = []
        
        for event in events:
            try:
                result = self.map_event(event)
                results.append(result)
            except Exception as e:
                self.logger.error(f"Error mapping event: {e}")
        
        self.logger.info(f"Mapped {len(results)} events to MITRE techniques")
        return results
    
    def get_techniques_by_tactic(self, tactic: str) -> List[Dict[str, Any]]:
        """
        Get all techniques for a specific tactic.
        
        Args:
            tactic: Tactic name
            
        Returns:
            List of technique dictionaries
        """
        techniques = []
        
        for mapping in self.mapping_config['mappings']:
            if mapping.get('tactic') == tactic:
                techniques.append({
                    'id': mapping.get('technique_id'),
                    'name': mapping.get('technique_name'),
                    'confidence': mapping.get('confidence', 0.0)
                })
        
        return techniques
    
    def get_all_tactics(self) -> List[str]:
        """
        Get all available tactics.
        
        Returns:
            List of tactic names
        """
        tactics_config = self.mapping_config.get('tactics', {})
        return list(tactics_config.keys())
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get mapping statistics.
        
        Returns:
            Dictionary with statistics
        """
        total_techniques = self.stats['total_techniques_identified']
        total_events = self.stats['total_events_mapped']
        
        avg_confidence = 0.0
        if total_events > 0:
            avg_confidence = total_techniques / total_events
        
        return {
            'total_events_mapped': total_events,
            'total_techniques_identified': total_techniques,
            'mapping_count_by_technique': self.stats['mapping_count_by_technique'],
            'average_confidence': avg_confidence,
            'available_tactics': len(self.get_all_tactics()),
            'available_mappings': len(self.mapping_config['mappings'])
        }
    
    def export_mapping_results(
        self,
        results: List[MappingResult],
        output_file: str
    ) -> bool:
        """
        Export mapping results to JSON file.
        
        Args:
            results: List of MappingResult objects
            output_file: Output file path
            
        Returns:
            True if successful
        """
        try:
            output_data = {
                'metadata': {
                    'exported_at': DateUtils.to_iso_string(DateUtils.now()),
                    'total_results': len(results),
                    'format_version': '1.0'
                },
                'results': [asdict(result) for result in results]
            }
            
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, default=str)
            
            self.logger.info(f"Exported mapping results to {output_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting mapping results: {e}")
            return False


def map_event_to_mitre(event: Dict[str, Any]) -> MappingResult:
    """
    Convenience function to map a single event.
    
    Args:
        event: Normalized event dictionary
        
    Returns:
        MappingResult
    """
    mapper = MiteMapper()
    return mapper.map_event(event)


def map_events_to_mitre(events: List[Dict[str, Any]]) -> List[MappingResult]:
    """
    Convenience function to map multiple events.
    
    Args:
        events: List of normalized events
        
    Returns:
        List of MappingResult objects
    """
    mapper = MiteMapper()
    return mapper.map_events_batch(events)