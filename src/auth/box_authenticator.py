"""Box API Authentication Module"""

import os
import sys
import logging
from pathlib import Path
from boxsdk import JWTAuth, Client
from boxsdk.exception import BoxAPIException

logger = logging.getLogger(__name__)


class BoxAuthenticator:
    """Handles Box API authentication using JWT"""
    
    def __init__(self, config_path=None):
        """
        Initialize Box authenticator
        
        Args:
            config_path: Path to Box JWT config file. If None, checks environment variable
        """
        self.config_path = config_path or os.environ.get('BOX_CONFIG_PATH', 'box_config.json')
        self.client = None
        self.auth = None
        
    def authenticate(self):
        """
        Authenticate with Box API using JWT
        
        Returns:
            Box Client object
            
        Raises:
            FileNotFoundError: If config file not found
            BoxAPIException: If authentication fails
        """
        config_file = Path(self.config_path)
        
        if not config_file.exists():
            raise FileNotFoundError(
                f"Box config file not found at: {self.config_path}\n"
                "Please follow BOX_API_SETUP.md to create your config file."
            )
            
        try:
            self.auth = JWTAuth.from_settings_file(str(config_file))
            self.client = Client(self.auth)
            
            # Test authentication
            user = self.client.user().get()
            logger.info(f"Authenticated as: {user.name} (Enterprise: {user.enterprise.name})")
            
            return self.client
            
        except BoxAPIException as e:
            if 'unauthorized' in str(e).lower():
                raise BoxAPIException(
                    "Authentication failed. Please ensure:\n"
                    "1. Your app is authorized in the Box Admin Console\n"
                    "2. The Enterprise ID in your config is correct\n"
                    "3. Your JWT keys are valid"
                )
            raise
            
    def get_enterprise_id(self):
        """Get the enterprise ID from authenticated session"""
        if not self.client:
            raise RuntimeError("Not authenticated. Call authenticate() first.")
            
        user = self.client.user().get()
        return user.enterprise.id
        
    def get_as_user_client(self, user_id):
        """
        Get a client that acts on behalf of a specific user
        
        Args:
            user_id: Box user ID
            
        Returns:
            Box Client for the specified user
        """
        if not self.auth:
            raise RuntimeError("Not authenticated. Call authenticate() first.")
            
        user_auth = JWTAuth(
            client_id=self.auth.client_id,
            client_secret=self.auth.client_secret,
            enterprise_id=self.auth._enterprise_id,
            jwt_key_id=self.auth._jwt_key_id,
            rsa_private_key_data=self.auth._rsa_private_key_data,
            rsa_private_key_passphrase=self.auth._rsa_private_key_passphrase,
            user=user_id
        )
        
        return Client(user_auth)