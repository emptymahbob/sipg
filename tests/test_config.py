"""
Tests for the configuration module.
"""

import tempfile
import json
import os
from pathlib import Path
import pytest

from sipg.config import Config


class TestConfig:
    """Test cases for the Config class."""
    
    def test_config_initialization(self):
        """Test config initialization with default path."""
        config = Config()
        assert config.config_dir == Path.home() / ".sipg"
        assert config.config_file == config.config_dir / "config.json"
    
    def test_config_with_custom_path(self):
        """Test config initialization with custom path."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "test_config.json"
            config = Config(str(config_file))
            assert config.config_file == config_file
    
    def test_api_key_operations(self):
        """Test API key get/set operations."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "test_config.json"
            config = Config(str(config_file))
            
            # Initially no API key
            assert config.get_api_key() is None
            
            # Set API key
            test_key = "test_api_key_123"
            config.set_api_key(test_key)
            assert config.get_api_key() == test_key
            
            # Clear API key
            config.clear_api_key()
            assert config.get_api_key() is None
    
    def test_settings_operations(self):
        """Test general settings operations."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "test_config.json"
            config = Config(str(config_file))
            
            # Test setting and getting
            config.set_setting("test_key", "test_value")
            assert config.get_setting("test_key") == "test_value"
            
            # Test default value
            assert config.get_setting("non_existent", "default") == "default"
            
            # Test getting all settings
            all_settings = config.get_all_settings()
            assert "test_key" in all_settings
            assert all_settings["test_key"] == "test_value"
    
    def test_is_configured(self):
        """Test is_configured method."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "test_config.json"
            config = Config(str(config_file))
            
            # Initially not configured
            assert not config.is_configured()
            
            # After setting API key
            config.set_api_key("test_key")
            assert config.is_configured()
            
            # After clearing API key
            config.clear_api_key()
            assert not config.is_configured()
    
    def test_config_file_persistence(self):
        """Test that config is properly saved to and loaded from file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "test_config.json"
            
            # Create config and set values
            config1 = Config(str(config_file))
            config1.set_api_key("test_api_key")
            config1.set_setting("custom_setting", "custom_value")
            
            # Create new config instance (should load from file)
            config2 = Config(str(config_file))
            assert config2.get_api_key() == "test_api_key"
            assert config2.get_setting("custom_setting") == "custom_value" 