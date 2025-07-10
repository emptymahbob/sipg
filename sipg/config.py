"""
Configuration management for SIPG.
"""

import json
import os
from pathlib import Path
from typing import Optional, Dict, Any


class Config:
    """Configuration manager for SIPG."""
    
    def __init__(self, config_file: Optional[str] = None):
        """Initialize configuration manager.
        
        Args:
            config_file: Path to configuration file. If None, uses default location.
        """
        if config_file is None:
            # Use user's home directory for config file
            self.config_dir = Path.home() / ".sipg"
            self.config_file = self.config_dir / "config.json"
        else:
            self.config_file = Path(config_file)
            self.config_dir = self.config_file.parent
            
        self._ensure_config_dir()
        self._load_config()
    
    def _ensure_config_dir(self) -> None:
        """Ensure configuration directory exists."""
        self.config_dir.mkdir(parents=True, exist_ok=True)
    
    def _load_config(self) -> None:
        """Load configuration from file."""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    self._config = json.load(f)
            except (json.JSONDecodeError, IOError):
                self._config = {}
        else:
            self._config = {}
    
    def _save_config(self) -> None:
        """Save configuration to file."""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self._config, f, indent=2, ensure_ascii=False)
        except IOError as e:
            raise RuntimeError(f"Failed to save configuration: {e}")
    
    def get_api_key(self) -> Optional[str]:
        """Get Shodan API key from configuration.
        
        Returns:
            API key if found, None otherwise.
        """
        return self._config.get('api_key')
    
    def set_api_key(self, api_key: str) -> None:
        """Set Shodan API key in configuration.
        
        Args:
            api_key: The Shodan API key to store.
        """
        self._config['api_key'] = api_key
        self._save_config()
    
    def get_setting(self, key: str, default: Any = None) -> Any:
        """Get a configuration setting.
        
        Args:
            key: Setting key.
            default: Default value if key not found.
            
        Returns:
            Setting value or default.
        """
        return self._config.get(key, default)
    
    def set_setting(self, key: str, value: Any) -> None:
        """Set a configuration setting.
        
        Args:
            key: Setting key.
            value: Setting value.
        """
        self._config[key] = value
        self._save_config()
    
    def get_all_settings(self) -> Dict[str, Any]:
        """Get all configuration settings.
        
        Returns:
            Dictionary of all settings.
        """
        return self._config.copy()
    
    def clear_api_key(self) -> None:
        """Clear the stored API key."""
        if 'api_key' in self._config:
            del self._config['api_key']
            self._save_config()
    
    def is_configured(self) -> bool:
        """Check if API key is configured.
        
        Returns:
            True if API key is set, False otherwise.
        """
        return self.get_api_key() is not None 