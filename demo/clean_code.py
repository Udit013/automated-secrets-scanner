"""
Example of clean, secure code
No hardcoded secrets here!
"""

import os
from typing import Optional

class SecureConfig:
    """Secure configuration loading from environment"""
    
    @staticmethod
    def get_api_key() -> Optional[str]:
        """Load API key from environment variable"""
        return os.getenv("API_KEY")
    
    @staticmethod
    def get_database_url() -> Optional[str]:
        """Load database URL from environment"""
        return os.getenv("DATABASE_URL")
    
    def __init__(self):
        self.api_key = self.get_api_key()
        self.db_url = self.get_database_url()
        
        if not self.api_key:
            raise ValueError("API_KEY environment variable not set")
        if not self.db_url:
            raise ValueError("DATABASE_URL environment variable not set")

# Usage
config = SecureConfig()
print("Configuration loaded successfully from environment variables")
