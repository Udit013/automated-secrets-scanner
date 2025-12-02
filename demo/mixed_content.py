"""
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
