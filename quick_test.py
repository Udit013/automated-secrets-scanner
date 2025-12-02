"""Quick test to verify scanner works"""
from scanner_core import SecretsScanner

# Test cases
test_cases = [
    ('AWS Key', 'key = "AKIAIOSFODNN7EXAMPLE"'),
    ('GitHub Token', 'token = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"'),
    ('SSH Key', '-----BEGIN RSA PRIVATE KEY-----'),
    ('Database', 'db = "postgresql://user:pass@localhost/db"'),
]

scanner = SecretsScanner(min_entropy=3.0)  # Lower threshold for testing

print("Testing Secret Detection:\n")
for name, test in test_cases:
    results = scanner.scan_string(test)
    status = "✓ PASS" if len(results) > 0 else "✗ FAIL"
    print(f"{status} - {name}: Found {len(results)} secrets")
    if results:
        print(f"       Type: {results[0].secret_type}, Entropy: {results[0].entropy}")
    print()