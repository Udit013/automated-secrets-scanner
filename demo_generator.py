"""
Generate demonstration files for the secrets scanner
Creates realistic examples of code with secrets and placeholders
"""

import os
from pathlib import Path

def create_demo_directory():
    """Create demo directory structure"""
    demo_dir = Path("demo")
    demo_dir.mkdir(exist_ok=True)
    
    # Sample code with real secret formats (sanitized for demo)
    sample_code = '''"""
Example application configuration
WARNING: This file contains example secrets for demonstration purposes
"""

import os

class Config:
    """Application configuration"""
    
    # AWS Credentials - REAL FORMAT (sanitized)
    AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
    AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    
    # GitHub Personal Access Token
    GITHUB_TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"
    
    # Database connection string
    DATABASE_URL = "postgresql://admin:SuperSecret123!@localhost:5432/mydb"
    
    # API Keys
    STRIPE_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
    GOOGLE_API_KEY = "AIzaSyC9XqLyjWDarjtT1zdp7dcABCDEFGHIJKL"
    
    # Generic secrets
    API_SECRET = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
    PASSWORD = "MyP@ssw0rd!2024"
    
    # JWT Token
    AUTH_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

def get_config():
    """Load configuration"""
    return Config()
'''
    
    # Placeholder examples
    placeholder_code = '''"""
Template configuration file
These are placeholder values - replace with actual credentials
"""

class ConfigTemplate:
    """Configuration template"""
    
    # TODO: Replace these placeholders with actual values
    
    # AWS Credentials - PLACEHOLDER
    AWS_ACCESS_KEY = "YOUR_AWS_ACCESS_KEY_HERE"
    AWS_SECRET_KEY = "your-aws-secret-key"
    
    # API Keys - PLACEHOLDER
    API_KEY = "XXXXXXXXXXXXXXXXXXXX"
    SECRET_KEY = "${SECRET_KEY}"
    ANOTHER_KEY = "<YOUR_API_KEY>"
    
    # Database - PLACEHOLDER
    DB_PASSWORD = "example-password"
    DB_CONNECTION = "postgresql://user:password@localhost/db"
    
    # Dummy values
    DUMMY_TOKEN = "dummy-token-value"
    SAMPLE_KEY = "sample_key_123"
'''
    
    # Mixed content
    mixed_code = '''"""
Partially configured application
Mix of real and placeholder values
"""

import requests

# This is a real key format (sanitized for demo)
REAL_API_KEY = "sk_test_4eC39HqLyjWDarjtT1zdp7dc"

# This is a placeholder
PLACEHOLDER_KEY = "your-key-here"

def make_api_call():
    """Call external API"""
    headers = {
        "Authorization": f"Bearer {REAL_API_KEY}",
        "Content-Type": "application/json"
    }
    
    # Another real format
    slack_webhook = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX"
    
    response = requests.post(slack_webhook, headers=headers)
    return response.json()

# Configuration with secrets
config = {
    "api_endpoint": "https://api.example.com",
    "api_key": "AKIAIOSFODNN7EXAMPLE",  # Real format
    "placeholder": "${API_KEY}",  # Placeholder
    "password": "MySecretP@ss2024"  # Real password
}
'''
    
    # .env file example
    env_file = '''# Environment variables
# Production configuration

# AWS
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_REGION=us-east-1

# Database
DATABASE_URL=postgresql://dbuser:SecurePass123!@prod-db.example.com:5432/maindb

# Third-party APIs
STRIPE_API_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc
SENDGRID_API_KEY=SG.1234567890123456789012.1234567890123456789012345678901234567890

# Application
SECRET_KEY=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0
JWT_SECRET=MyJWTSecretKey2024!WithSpecialChars
'''
    
    # JSON config
    json_config = '''{
  "application": {
    "name": "MyApp",
    "version": "1.0.0"
  },
  "aws": {
    "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
    "secretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "region": "us-west-2"
  },
  "database": {
    "host": "localhost",
    "port": 5432,
    "username": "admin",
    "password": "DatabaseP@ssw0rd123!"
  },
  "api": {
    "github_token": "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
    "stripe_key": "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
  }
}'''
    
    # Clean code (no secrets)
    clean_code = '''"""
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
'''
    
    # Write all files
    files = {
        'sample_code.py': sample_code,
        'placeholders.py': placeholder_code,
        'mixed_content.py': mixed_code,
        'config.json': json_config,
        'clean_code.py': clean_code,
        '.env.example': env_file,
    }
    
    for filename, content in files.items():
        filepath = demo_dir / filename
        with open(filepath, 'w') as f:
            f.write(content)
        print(f"Created: {filepath}")
    
    # Create a subdirectory with more files
    subdir = demo_dir / "config"
    subdir.mkdir(exist_ok=True)
    
    (subdir / "settings.py").write_text(sample_code)
    (subdir / "template.py").write_text(placeholder_code)
    
    print(f"\nDemo directory created at: {demo_dir.absolute()}")
    print("\nYou can now run:")
    print(f"  python cli.py -d {demo_dir}")
    print(f"  python cli.py -f {demo_dir}/sample_code.py")
    print(f"  python cli.py -d {demo_dir} --stats")

if __name__ == "__main__":
    create_demo_directory()