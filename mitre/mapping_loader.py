"""
MITRE ATT&CK mapping loader for the Dynamic Honeypot Platform.
Loads and validates MITRE ATT&CK technique mappings from configuration.
"""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from utils.logger import get_logger
from utils.config_loader import ConfigLoader


class MappingLoader:
    """Loads and validates MITRE ATT&CK technique mappings."""
    
    def __init__(self, config_dir: str = "config"):
        """
        Initialize mapping loader.
        
        Args:
            config_dir: Directory containing configuration files
        """
        self.config_loader = ConfigLoader(config_dir)
        self.logger = get_logger("MappingLoader")
        self.mapping_data: Optional[Dict[str, Any]] = None
    
    def load_mappings(self, mapping_file: str = "mitre_attack_mapping.json") -> Dict[str, Any]:
        """
        Load MITRE ATT&CK mappings from configuration file.
        
        Args:
            mapping_file: Name of mapping file
            
        Returns:
            Dictionary with mapping data
        """
        try:
            self.mapping_data = self.config_loader.load_json(mapping_file)
            self._validate_mappings(self.mapping_data)
            
            self.logger.info(
                f"Loaded {len(self.mapping_data['mappings'])} MITRE technique mappings"
            )
            
            return self.mapping_data
            
        except Exception as e:
            self.logger.error(f"Error loading mappings: {e}")
            raise
    
    def _validate_mappings(self, mapping_data: Dict[str, Any]):
        """
        Validate MITRE mapping data structure.
        
        Args:
            mapping_data: Mapping data dictionary
        """
        if not isinstance(mapping_data, dict):
            raise ValueError("Mapping data must be a dictionary")
        
        if 'mappings' not in mapping_data:
            raise ValueError("Mapping data must contain 'mappings' key")
        
        if not isinstance(mapping_data['mappings'], list):
            raise ValueError("'mappings' must be a list")
        
        # Validate each mapping
        for i, mapping in enumerate(mapping_data['mappings']):
            self._validate_mapping(mapping, i)
    
    def _validate_mapping(self, mapping: Dict[str, Any], index: int):
        """
        Validate individual mapping structure.
        
        Args:
            mapping: Individual mapping dictionary
            index: Index of mapping in list
        """
        required_fields = [
            'id', 'event_pattern', 'technique_id', 'technique_name',
            'tactic', 'confidence', 'reason'
        ]
        
        for field in required_fields:
            if field not in mapping:
                raise ValueError(
                    f"Mapping at index {index} missing required field: {field}"
                )
        
        # Validate confidence is between 0 and 1
        confidence = mapping.get('confidence', 0.0)
        if not 0.0 <= confidence <= 1.0:
            raise ValueError(
                f"Mapping {mapping.get('id')} has invalid confidence: {confidence}"
            )
        
        # Validate technique ID format
        technique_id = mapping.get('technique_id', '')
        if not technique_id.startswith('T'):
            raise ValueError(
                f"Mapping {mapping.get('id')} has invalid technique ID: {technique_id}"
            )
    
    def get_mapping_by_id(self, mapping_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a specific mapping by ID.
        
        Args:
            mapping_id: Mapping ID
            
        Returns:
            Mapping dictionary or None if not found
        """
        if not self.mapping_data:
            self.load_mappings()
        
        for mapping in self.mapping_data['mappings']:
            if mapping.get('id') == mapping_id:
                return mapping
        
        return None
    
    def get_mappings_by_technique(self, technique_id: str) -> List[Dict[str, Any]]:
        """
        Get all mappings for a specific technique.
        
        Args:
            technique_id: MITRE technique ID
            
        Returns:
            List of mapping dictionaries
        """
        if not self.mapping_data:
            self.load_mappings()
        
        return [
            mapping for mapping in self.mapping_data['mappings']
            if mapping.get('technique_id') == technique_id
        ]
    
    def get_mappings_by_tactic(self, tactic: str) -> List[Dict[str, Any]]:
        """
        Get all mappings for a specific tactic.
        
        Args:
            tactic: MITRE tactic name
            
        Returns:
            List of mapping dictionaries
        """
        if not self.mapping_data:
            self.load_mappings()
        
        return [
            mapping for mapping in self.mapping_data['mappings']
            if mapping.get('tactic') == tactic
        ]
    
    def get_all_techniques(self) -> List[str]:
        """
        Get all unique technique IDs.
        
        Returns:
            List of technique IDs
        """
        if not self.mapping_data:
            self.load_mappings()
        
        techniques = set()
        for mapping in self.mapping_data['mappings']:
            technique_id = mapping.get('technique_id')
            if technique_id:
                techniques.add(technique_id)
        
        return sorted(list(techniques))
    
    def get_all_tactics(self) -> List[str]:
        """
        Get all unique tactic names.
        
        Returns:
            List of tactic names
        """
        if not self.mapping_data:
            self.load_mappings()
        
        tactics_config = self.mapping_data.get('tactics', {})
        return list(tactics_config.keys())
    
    def search_mappings(self, search_term: str) -> List[Dict[str, Any]]:
        """
        Search mappings by event pattern, technique name, or tactic.
        
        Args:
            search_term: Search term
            
        Returns:
            List of matching mappings
        """
        if not self.mapping_data:
            self.load_mappings()
        
        search_term_lower = search_term.lower()
        results = []
        
        for mapping in self.mapping_data['mappings']:
            # Search in event pattern
            if search_term_lower in mapping.get('event_pattern', '').lower():
                results.append(mapping)
                continue
            
            # Search in technique name
            if search_term_lower in mapping.get('technique_name', '').lower():
                results.append(mapping)
                continue
            
            # Search in tactic
            if search_term_lower in mapping.get('tactic', '').lower():
                results.append(mapping)
                continue
        
        return results
    
    def get_mapping_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about loaded mappings.
        
        Returns:
            Dictionary with statistics
        """
        if not self.mapping_data:
            self.load_mappings()
        
        mappings = self.mapping_data['mappings']
        
        # Count by tactic
        tactic_counts = {}
        for mapping in mappings:
            tactic = mapping.get('tactic', 'unknown')
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
        
        # Count by confidence level
        confidence_levels = {'high': 0, 'medium': 0, 'low': 0}
        confidence_thresholds = self.mapping_data.get('confidence_levels', {})
        high_threshold = confidence_thresholds.get('high', 0.8)
        low_threshold = confidence_thresholds.get('low', 0.3)
        
        for mapping in mappings:
            confidence = mapping.get('confidence', 0.0)
            if confidence >= high_threshold:
                confidence_levels['high'] += 1
            elif confidence >= low_threshold:
                confidence_levels['medium'] += 1
            else:
                confidence_levels['low'] += 1
        
        return {
            'total_mappings': len(mappings),
            'unique_techniques': len(self.get_all_techniques()),
            'unique_tactics': len(self.get_all_tactics()),
            'mappings_by_tactic': tactic_counts,
            'confidence_distribution': confidence_levels,
            'version': self.mapping_data.get('version', 'unknown'),
            'last_updated': self.mapping_data.get('last_updated', 'unknown')
        }
    
    def reload_mappings(self, mapping_file: str = "mitre_attack_mapping.json") -> Dict[str, Any]:
        """
        Reload mappings from file.
        
        Args:
            mapping_file: Name of mapping file
            
        Returns:
            Dictionary with mapping data
        """
        self.logger.info("Reloading MITRE mappings")
        return self.load_mappings(mapping_file)