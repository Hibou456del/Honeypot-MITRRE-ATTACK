"""
Configuration loader for the Dynamic Honeypot Platform.
Handles loading and validation of YAML and JSON configuration files.
"""

import yaml
import json
from pathlib import Path
from typing import Any, Dict, Optional
from pydantic import BaseModel, ValidationError
import os
from dotenv import load_dotenv


class Settings(BaseModel):
    """Main settings model."""
    environment: str = "development"
    platform: str = "windows"
    paths: Dict[str, str] = {}
    cowrie: Dict[str, Any] = {}
    http_honeypot: Dict[str, Any] = {}
    database: Dict[str, Any] = {}
    dashboard: Dict[str, Any] = {}
    detection: Dict[str, Any] = {}
    mitre: Dict[str, Any] = {}
    deception: Dict[str, Any] = {}
    logging: Dict[str, Any] = {}
    security: Dict[str, Any] = {}


class ConfigLoader:
    """Load and manage configuration files."""
    
    def __init__(self, config_dir: str = "config"):
        """
        Initialize configuration loader.
        
        Args:
            config_dir: Directory containing configuration files
        """
        self.config_dir = Path(config_dir)
        self.settings: Optional[Settings] = None
        self._load_env()
    
    def _load_env(self):
        """Load environment variables from .env file."""
        env_file = Path(".env")
        if env_file.exists():
            load_dotenv(env_file)
    
    def load_settings(self, settings_file: str = "settings.yaml") -> Settings:
        """
        Load main settings file.
        
        Args:
            settings_file: Name of settings file
            
        Returns:
            Settings object
        """
        settings_path = self.config_dir / settings_file
        
        if not settings_path.exists():
            raise FileNotFoundError(f"Settings file not found: {settings_path}")
        
        with open(settings_path, 'r', encoding='utf-8') as f:
            config_data = yaml.safe_load(f)
        
        # Replace environment variables
        config_data = self._replace_env_vars(config_data)
        
        try:
            self.settings = Settings(**config_data)
            return self.settings
        except ValidationError as e:
            raise ValueError(f"Configuration validation error: {e}")
    
    def load_yaml(self, filename: str) -> Dict[str, Any]:
        """
        Load a YAML configuration file.
        
        Args:
            filename: Name of YAML file
            
        Returns:
            Dictionary with configuration data
        """
        file_path = self.config_dir / filename
        
        if not file_path.exists():
            raise FileNotFoundError(f"YAML file not found: {file_path}")
        
        with open(file_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    
    def load_json(self, filename: str) -> Dict[str, Any]:
        """
        Load a JSON configuration file.
        
        Args:
            filename: Name of JSON file
            
        Returns:
            Dictionary with configuration data
        """
        file_path = self.config_dir / filename
        
        if not file_path.exists():
            raise FileNotFoundError(f"JSON file not found: {file_path}")
        
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def _replace_env_vars(self, config: Any) -> Any:
        """
        Replace environment variable placeholders in configuration.
        
        Args:
            config: Configuration data (can be dict, list, or string)
            
        Returns:
            Configuration with environment variables replaced
        """
        if isinstance(config, dict):
            return {k: self._replace_env_vars(v) for k, v in config.items()}
        elif isinstance(config, list):
            return [self._replace_env_vars(item) for item in config]
        elif isinstance(config, str):
            # Replace ${VAR_NAME} with environment variable value
            if config.startswith("${") and config.endswith("}"):
                var_name = config[2:-1]
                return os.getenv(var_name, config)
            return config
        else:
            return config
    
    def get_env_var(self, var_name: str, default: Optional[str] = None) -> Optional[str]:
        """
        Get environment variable with optional default.
        
        Args:
            var_name: Environment variable name
            default: Default value if not found
            
        Returns:
            Environment variable value or default
        """
        return os.getenv(var_name, default)
    
    def get_path(self, path_key: str) -> Path:
        """
        Get a path from settings, resolving relative paths.
        
        Args:
            path_key: Key in settings.paths
            
        Returns:
            Resolved Path object
        """
        if not self.settings:
            raise RuntimeError("Settings not loaded. Call load_settings() first.")
        
        path_str = self.settings.paths.get(path_key)
        if not path_str:
            raise KeyError(f"Path key not found: {path_key}")
        
        # Resolve relative paths from base directory
        if not Path(path_str).is_absolute():
            base_dir = Path(self.settings.paths.get('base_dir', '.'))
            return base_dir / path_str
        
        return Path(path_str)


# Global configuration loader instance
_config_loader: Optional[ConfigLoader] = None


def get_config_loader(config_dir: str = "config") -> ConfigLoader:
    """
    Get global configuration loader instance.
    
    Args:
        config_dir: Directory containing configuration files
        
    Returns:
        ConfigLoader instance
    """
    global _config_loader
    if _config_loader is None:
        _config_loader = ConfigLoader(config_dir)
    return _config_loader


def load_settings(settings_file: str = "settings.yaml") -> Settings:
    """
    Convenience function to load settings.
    
    Args:
        settings_file: Name of settings file
        
    Returns:
        Settings object
    """
    loader = get_config_loader()
    return loader.load_settings(settings_file)