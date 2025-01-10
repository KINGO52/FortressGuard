import configparser
import os
from pathlib import Path

class ConfigManager:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ConfigManager, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
            
        self._initialized = True
        self.config = configparser.ConfigParser()
        self.load_config()
    
    def load_config(self):
        """Load configuration from the config file"""
        config_path = Path.home() / '.fortressguard' / 'config' / 'config.ini'
        
        if not config_path.exists():
            raise FileNotFoundError(
                "Configuration file not found. Please run setup.py first."
            )
        
        self.config.read(str(config_path))
    
    def get_path(self, path_name):
        """Get a path from the configuration"""
        return self.config.get('Paths', path_name)
    
    def get_security_setting(self, setting_name):
        """Get a security setting from the configuration"""
        return self.config.get('Security', setting_name)
    
    def set_security_setting(self, setting_name, value):
        """Update a security setting"""
        self.config.set('Security', setting_name, str(value))
        self.save_config()
    
    def save_config(self):
        """Save current configuration to file"""
        config_path = Path(self.get_path('config_dir')) / 'config.ini'
        with open(config_path, 'w') as f:
            self.config.write(f)
    
    @property
    def app_dir(self):
        return self.get_path('app_dir')
    
    @property
    def keys_dir(self):
        return self.get_path('keys_dir')
    
    @property
    def logs_dir(self):
        return self.get_path('logs_dir')
    
    @property
    def config_dir(self):
        return self.get_path('config_dir')
    
    @property
    def passwords_file(self):
        return self.get_path('passwords_file')
    
    @property
    def icon_path(self):
        return self.get_path('icon_path') 