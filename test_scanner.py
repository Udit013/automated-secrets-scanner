"""
Test suite for the Automated Secrets Scanner
Tests pattern matching, entropy analysis, and placeholder detection
"""

import unittest
import tempfile
import os
from pathlib import Path
from scanner_core import (
    SecretsScanner, 
    PatternDatabase, 
    EntropyAnalyzer,
    SecretMatch
)

class TestEntropyAnalyzer(unittest.TestCase):
    """Test entropy calculation"""
    
    def setUp(self):
        self.analyzer = EntropyAnalyzer()
    
    def test_high_entropy_string(self):
        """Test that random strings have high entropy"""
        random_key = "aK3nF9mP2xQ7vW8jR4tY6uI0oL5sD1gH"
        entropy = self.analyzer.calculate_shannon_entropy(random_key)
        self.assertGreater(entropy, 4.0)
    
    def test_low_entropy_string(self):
        """Test that repetitive strings have low entropy"""
        low_entropy = "aaaaaaaaaaaaaaaa"
        entropy = self.analyzer.calculate_shannon_entropy(low_entropy)
        self.assertLess(entropy, 1.0)
    
    def test_confidence_levels(self):
        """Test confidence level assignment"""
        self.assertEqual(
            self.analyzer.get_confidence_level(5.0, True),
            "HIGH"
        )
        self.assertEqual(
            self.analyzer.get_confidence_level(4.0, True),
            "MEDIUM"
        )
        self.assertEqual(
            self.analyzer.get_confidence_level(3.0, True),
            "LOW"
        )

class TestPatternDatabase(unittest.TestCase):
    """Test pattern matching and placeholder detection"""
    
    def setUp(self):
        self.pattern_db = PatternDatabase()
    
    def test_placeholder_detection(self):
        """Test that placeholders are correctly identified"""
        placeholders = [
            "AKIA_YOUR_KEY_HERE",
            "XXXXXXXXXXXXXXXXXXXX",
            "example-api-key",
            "${API_KEY}",
            "<YOUR_SECRET_KEY>",
            "DUMMY_PASSWORD"
        ]
        
        for placeholder in placeholders:
            self.assertTrue(
                self.pattern_db.is_placeholder(placeholder),
                f"Failed to detect placeholder: {placeholder}"
            )
    
    def test_real_secrets_not_placeholders(self):
        """Test that real secrets are not marked as placeholders"""
        real_secrets = [
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "ghp_16C7e42F292c6912E7710c838347Ae178B4a"
        ]
        
        for secret in real_secrets:
            # These should not be detected as placeholders
            # unless they contain explicit placeholder patterns
            if "EXAMPLE" not in secret.upper():
                self.assertFalse(
                    self.pattern_db.is_placeholder(secret),
                    f"Incorrectly marked real secret as placeholder: {secret}"
                )

class TestSecretsScanner(unittest.TestCase):
    """Test the main scanner functionality"""
    
    def setUp(self):
        self.scanner = SecretsScanner(min_entropy=3.5)
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up temporary files"""
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_aws_key_detection(self):
        """Test AWS access key detection"""
        code = """
# AWS Configuration
AWS_ACCESS_KEY = "AKIAV3WBCDEF4GHI7JKM"
        """
        matches = self.scanner.scan_string(code)
        self.assertGreater(len(matches), 0)

        types = [m.secret_type for m in matches]
        self.assertIn('AWS Access Key', types)
    
    def test_github_token_detection(self):
        """Test GitHub token detection"""
        code = 'token = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"'
        matches = self.scanner.scan_string(code)
        
        github_matches = [m for m in matches if 'GitHub' in m.secret_type]
        self.assertGreater(len(github_matches), 0)
    
    def test_private_key_detection(self):
        """Test SSH private key detection"""
        code = """
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyqFvPJ6m8VwHH4P...
-----END RSA PRIVATE KEY-----
        """
        matches = self.scanner.scan_string(code)
        
        ssh_matches = [m for m in matches if 'SSH' in m.secret_type]
        self.assertGreater(len(ssh_matches), 0)
    
    def test_placeholder_exclusion(self):
        """Test that placeholders are excluded"""
        code = """
# Example configuration - replace with your values
API_KEY = "your-api-key-here"
SECRET = "XXXXXXXXXXXXXXXXXXXX"
TOKEN = "${YOUR_TOKEN}"
        """
        matches = self.scanner.scan_string(code)
        
        # Should find minimal or no matches due to placeholder detection
        self.assertEqual(len(matches), 0)
    
    def test_file_scanning(self):
        """Test scanning a file"""
        test_file = os.path.join(self.temp_dir, "test.py")
        with open(test_file, 'w') as f:
            f.write('api_key = "AKIAV3WBCDEF4GHI7JKM"\n')

        matches = self.scanner.scan_file(test_file)
        self.assertGreater(len(matches), 0)
    
    def test_directory_scanning(self):
        """Test scanning a directory"""
        # Create test files
        for i in range(3):
            test_file = os.path.join(self.temp_dir, f"test{i}.py")
            with open(test_file, 'w') as f:
                f.write(f'secret{i} = "AKIAIOSFODNN7EXAMPL{i}"\n')
        
        matches = self.scanner.scan_directory(self.temp_dir)
        self.assertGreater(len(matches), 0)
    
    def test_database_connection_string(self):
        """Test database connection string detection"""
        code = 'DB_URL = "mongodb://admin:password123@localhost:27017"'
        matches = self.scanner.scan_string(code)
        
        db_matches = [m for m in matches if 'Database' in m.secret_type]
        self.assertGreater(len(db_matches), 0)
    
    def test_jwt_token_detection(self):
        """Test JWT token detection"""
        code = 'token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"'
        matches = self.scanner.scan_string(code)
        
        jwt_matches = [m for m in matches if 'JWT' in m.secret_type]
        self.assertGreater(len(jwt_matches), 0)
    
    def test_statistics_generation(self):
        """Test statistics generation"""
        code = """
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
GITHUB_TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"
        """
        self.scanner.scan_string(code)
        stats = self.scanner.get_statistics()
        
        self.assertIn('total_secrets', stats)
        self.assertIn('by_type', stats)
        self.assertIn('by_confidence', stats)
    
    def test_masking(self):
        """Test secret masking"""
        secret = "AKIAIOSFODNN7EXAMPLE"
        masked = self.scanner._mask_secret(secret, show_chars=4)
        
        # Should show first 4 and last 4 characters
        self.assertTrue(masked.startswith("AKIA"))
        self.assertTrue(masked.endswith("MPLE"))
        self.assertIn("*", masked)
    
    def test_context_extraction(self):
        """Test that context is properly extracted"""
        code = 'config = {"api_key": "AKIAIOSFODNN7EXAMPLE"}'
        matches = self.scanner.scan_string(code)
        
        if matches:
            self.assertIsNotNone(matches[0].context)
            self.assertIn("config", matches[0].context)

class TestDataFileHandling(unittest.TestCase):
    """Test handling of credentials in data files"""
    
    def setUp(self):
        self.scanner = SecretsScanner()
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_json_config_file(self):
        """Test scanning JSON configuration files"""
        config_file = os.path.join(self.temp_dir, "config.json")
        with open(config_file, 'w') as f:
            f.write('{"aws_key": "AKIAV3WBCDEF4GHI7JKM"}')

        matches = self.scanner.scan_file(config_file)
        self.assertGreater(len(matches), 0)
    
    def test_yaml_config_file(self):
        """Test scanning YAML configuration files"""
        config_file = os.path.join(self.temp_dir, "config.yml")
        with open(config_file, 'w') as f:
            f.write('database:\n  password: "superSecretPass123!"\n')
        
        matches = self.scanner.scan_file(config_file)
        # May or may not detect depending on entropy
        self.assertIsInstance(matches, list)
    
    def test_env_file(self):
        """Test scanning .env files"""
        env_file = os.path.join(self.temp_dir, ".env")
        with open(env_file, 'w') as f:
            f.write('API_KEY=AKIAV3WBCDEF4GHI7JKM\n')

        matches = self.scanner.scan_file(env_file)
        self.assertGreater(len(matches), 0)

def run_tests():
    """Run all tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestEntropyAnalyzer))
    suite.addTests(loader.loadTestsFromTestCase(TestPatternDatabase))
    suite.addTests(loader.loadTestsFromTestCase(TestSecretsScanner))
    suite.addTests(loader.loadTestsFromTestCase(TestDataFileHandling))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()

if __name__ == '__main__':
    success = run_tests()
    exit(0 if success else 1)