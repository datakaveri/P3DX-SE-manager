#!/usr/bin/env python3
"""
Configuration loader for P3DX Enclave Manager.
"""

import os
import sys
import yaml
import warnings
from pathlib import Path
from typing import Dict, List, Any, Optional
from dotenv import load_dotenv


class ConfigError(Exception):
    """Configuration error."""
    pass


class Config:
    """Configuration manager for P3DX Enclave Manager."""
    
    def __init__(self, env_file: Optional[str] = None, config_file: Optional[str] = None):
        """
        Initialize configuration.
        
        Args:
            env_file: Path to .env file (default: .env in project root)
            config_file: Path to config.yml file (default: config.yml in project root)
        """
        # Determine project root 
        self._script_dir = Path(__file__).parent.absolute()
        self._project_root = self._script_dir.parent
        
        # Load .env file first
        if env_file is None:
            env_file = self._project_root / '.env'
        
        if os.path.exists(env_file):
            load_dotenv(env_file)
            print(f"Loaded environment from: {env_file}")
        else:
            warnings.warn(f".env file not found at {env_file}. Using defaults.")
        
        # Get BASE_DIR from environment or use project root as default
        self._base_dir = os.getenv('BASE_DIR', str(self._project_root))
        self._user = os.getenv('USER', os.getenv('USERNAME', 'user'))
        
        # Load config.yml
        if config_file is None:
            config_file = self._project_root / 'config.yml'
        
        if not os.path.exists(config_file):
            raise ConfigError(f"config.yml not found at {config_file}")
        
        with open(config_file, 'r') as f:
            self._raw_config = yaml.safe_load(f)
        
        print(f"Loaded configuration from: {config_file}")
        
        # Expand environment variables in config
        self._config = self._expand_env_vars(self._raw_config)
        
        # Initialize path objects
        self._init_paths()
        
        # Validate and auto-create directories
        self._validate_and_create_dirs()
    
    def _expand_env_vars(self, obj: Any) -> Any:
        """Recursively expand environment variables in config values."""
        if isinstance(obj, dict):
            return {k: self._expand_env_vars(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._expand_env_vars(item) for item in obj]
        elif isinstance(obj, str):
            # Expand ${VAR} style variables
            result = obj
            if '${BASE_DIR}' in result:
                result = result.replace('${BASE_DIR}', self._base_dir)
            if '${USER}' in result:
                result = result.replace('${USER}', self._user)
            # Also expand standard $VAR and ${VAR} using os.path.expandvars
            result = os.path.expandvars(result)
            return result
        else:
            return obj
    
    def _init_paths(self):
        """Initialize path objects for easy access."""
        paths_config = self._config.get('paths', {})
        
        # Create a namespace object for paths
        class PathNamespace:
            pass
        
        self.paths = PathNamespace()
        
        # Set path attributes
        for key, value in paths_config.items():
            setattr(self.paths, key, value)
        
        # Create similar namespace for files
        files_config = self._config.get('files', {})
        self.files = PathNamespace()
        for key, value in files_config.items():
            setattr(self.files, key, value)
        
        # Azure endpoints
        azure_config = self._config.get('azure', {})
        self.azure = PathNamespace()
        for key, value in azure_config.items():
            setattr(self.azure, key, value)
        
        # Commands
        commands_config = self._config.get('commands', {})
        self.commands = PathNamespace()
        for key, value in commands_config.items():
            setattr(self.commands, key, value)
        
        # Service configuration
        service_config = self._config.get('service', {})
        self.service = PathNamespace()
        for key, value in service_config.items():
            setattr(self.service, key, value)
        
        # CORS configuration
        cors_config = self._config.get('cors', {})
        self.cors = PathNamespace()
        for key, value in cors_config.items():
            setattr(self.cors, key, value)

        # Minimal anonymisation demo (run_anonymisation.py)
        demo_config = self._config.get('demo', {})
        self.demo = PathNamespace()
        for key, value in demo_config.items():
            setattr(self.demo, key, value)
    
    def _validate_and_create_dirs(self):
        """Validate paths and auto-create missing directories."""
        # Directories that should be auto-created
        auto_create_dirs = [
            self.paths.keys_dir,
            self.paths.bundle_dir,
            self.paths.tee_input_data,
            self.paths.tee_input_config,
            self.paths.tee_output,
            self.paths.tee_urls,
        ]
        
        for dir_path in auto_create_dirs:
            if not os.path.exists(dir_path):
                try:
                    os.makedirs(dir_path, exist_ok=True)
                    print(f"✓ Created directory: {dir_path}")
                except Exception as e:
                    warnings.warn(f"⚠ Could not create directory {dir_path}: {e}")
            else:
                # Directory exists, just validate it's actually a directory
                if not os.path.isdir(dir_path):
                    warnings.warn(f"⚠ Path exists but is not a directory: {dir_path}")
        
        # Check base_dir exists
        if not os.path.exists(self.base_dir):
            warnings.warn(f"⚠ BASE_DIR does not exist: {self.base_dir}")
        
        # Check guest_attestation directory (should already exist)
        if not os.path.exists(self.paths.guest_attestation):
            warnings.warn(f"⚠ Guest attestation directory not found: {self.paths.guest_attestation}")
    
    @property
    def base_dir(self) -> str:
        """Get base directory path."""
        return self._base_dir
    
    @property
    def user(self) -> str:
        """Get system user."""
        return self._user
    
    def get_path(self, path_name: str, *parts: str) -> str:
        """
        Get a full path by combining path components.
        
        Args:
            path_name: Name of the base path (e.g., 'keys_dir', 'jwt_response')
            *parts: Additional path components to join
        
        Returns:
            Full resolved path as string
        
        Example:
            config.get_path('keys_dir', 'jwt-response.txt')
            # Returns: /home/user/P3DX-SE-manager/keys/jwt-response.txt
        """
        # Check if it's a file name first
        if hasattr(self.files, path_name):
            file_name = getattr(self.files, path_name)
            # Most files go in keys directory
            if path_name in ['jwt_response', 'deployment_nonce', 'pcr_values', 
                           'public_key', 'private_key', 'code_hash', 'image_hash']:
                base = self.paths.keys_dir
            elif path_name == 'encrypted_bundle':
                base = self.paths.bundle_dir
            elif path_name == 'decrypted_urls':
                base = self.paths.tee_urls
            elif path_name == 'status':
                base = self.paths.tee_output
            elif path_name == 'docker_compose':
                base = self.base_dir
            elif path_name == 'config_file':
                base = self.base_dir
            else:
                base = self.base_dir
            return os.path.join(base, file_name, *parts)
        
        # Check if it's a directory path
        if hasattr(self.paths, path_name):
            base = getattr(self.paths, path_name)
            if parts:
                return os.path.join(base, *parts)
            return base
        
        raise ConfigError(f"Unknown path name: {path_name}")
    
    def get_command(self, command_name: str, use_sudo: Optional[bool] = None) -> List[str]:
        """
        Get command as a list suitable for subprocess.
        """
        if not hasattr(self.commands, command_name):
            raise ConfigError(f"Unknown command: {command_name}")
        
        cmd = getattr(self.commands, command_name)
        
        # Determine if sudo should be used
        if use_sudo is None:
            use_sudo = self.commands.use_sudo
        
        if use_sudo and not isinstance(cmd, list):
            return ['sudo', cmd]
        elif use_sudo and isinstance(cmd, list):
            return ['sudo'] + cmd
        elif isinstance(cmd, list):
            return cmd
        else:
            return [cmd]
    
    def get_docker_command(self, *args: str, use_sudo: Optional[bool] = None) -> List[str]:
        """
        Get docker-compose command with arguments.
        """
        base_cmd = self.get_command('docker_compose', use_sudo=use_sudo)
        return base_cmd + list(args)


# Singleton instance
_config_instance: Optional[Config] = None


def get_config(reload: bool = False) -> Config:
    """
    Get or create the singleton Config instance.
    """
    global _config_instance
    
    if _config_instance is None or reload:
        _config_instance = Config()
    
    return _config_instance


# Convenience: import config directly
config = get_config()


if __name__ == '__main__':
    # Test configuration loading
    print("=" * 60)
    print("Configuration Test")
    print("=" * 60)
    
    cfg = get_config()
    
    print(f"\nBase Directory: {cfg.base_dir}")
    print(f"User: {cfg.user}")
    print(f"\nPaths:")
    print(f"  Keys: {cfg.paths.keys_dir}")
    print(f"  Bundle: {cfg.paths.bundle_dir}")
    print(f"  TEE Input Data: {cfg.paths.tee_input_data}")
    print(f"  TEE Output: {cfg.paths.tee_output}")
    
    print(f"\nFile paths:")
    print(f"  JWT Response: {cfg.get_path('jwt_response')}")
    print(f"  PCR Values: {cfg.get_path('pcr_values')}")
    print(f"  Private Key: {cfg.get_path('private_key')}")
    
    print(f"\nCommands:")
    print(f"  Python: {cfg.get_command('python')}")
    print(f"  Docker Compose up: {cfg.get_docker_command('up', '-d')}")
    
    print(f"\nService:")
    print(f"  Name: {cfg.service.name}")
    print(f"  Port: {cfg.service.port}")
    print(f"  Host: {cfg.service.host}")
    
    print(f"\nCORS Origins:")
    for origin in cfg.cors.origins:
        print(f"  - {origin}")
    
    print("\n" + "=" * 60)
    print("Configuration loaded successfully!")
    print("=" * 60)
