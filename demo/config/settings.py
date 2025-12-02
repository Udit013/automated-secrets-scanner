"""
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
