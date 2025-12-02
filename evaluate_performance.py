"""
Comprehensive evaluation script for the secrets scanner
Tests against known ground truth and compares with baselines
"""

import time
import json
from pathlib import Path
from collections import defaultdict
from scanner_core import SecretsScanner, EntropyAnalyzer
import re

class EvaluationSuite:
    """Evaluation suite for secrets scanner"""
    
    def __init__(self):
        self.results = {
            'pattern_matching': {},
            'entropy_analysis': {},
            'placeholder_detection': {},
            'full_scanner': {},
            'performance': {}
        }
        
    def create_test_cases(self):
        """Create test cases with ground truth"""
        test_cases = {
            'true_positives': {
                'AWS Keys': [
                    'AKIAIOSFODNN7EXAMPLE',
                    'AKIAI44QH8DHBEXAMPLE',
                    'AKIA1234567890ABCDEF',
                ],
                'GitHub Tokens': [
                    'ghp_16C7e42F292c6912E7710c838347Ae178B4a',
                    'gho_16C7e42F292c6912E7710c838347Ae178B4a',
                    'ghs_16C7e42F292c6912E7710c838347Ae178B4a',
                ],
                'Private Keys': [
                    '-----BEGIN RSA PRIVATE KEY-----',
                    '-----BEGIN OPENSSH PRIVATE KEY-----',
                ],
                'API Keys': [
                    'AIzaSyC9XqLyjWDarjtT1zdp7dcABCDEFGHIJKL',
                    'sk_live_4eC39HqLyjWDarjtT1zdp7dc',
                ],
                'Database URLs': [
                    'mongodb://admin:password123@localhost:27017',
                    'postgresql://user:SecureP@ss!@db.example.com:5432/maindb',
                ],
                'JWT Tokens': [
                    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N',
                ],
            },
            'placeholders': [
                'AKIAEXAMPLEKEY123456',
                'your-api-key-here',
                'XXXXXXXXXXXXXXXXXXXX',
                '${API_KEY}',
                '<YOUR_SECRET_KEY>',
                'example-password',
                'dummy-token',
                'sample_key_value',
            ],
            'false_positives': [
                'console.log("Hello World");',
                'def calculate_hash():',
                'import hashlib',
                '# This is a comment',
                'Lorem ipsum dolor sit amet',
            ]
        }
        return test_cases
    
    def test_pattern_matching(self):
        """Test pattern matching accuracy"""
        print("\n" + "="*60)
        print("TESTING PATTERN MATCHING")
        print("="*60)
        
        from scanner_core import PatternDatabase
        pattern_db = PatternDatabase()
        
        test_cases = self.create_test_cases()
        results = {
            'true_positives_detected': 0,
            'total_true_positives': 0,
            'false_positives': 0,
            'by_type': defaultdict(lambda: {'detected': 0, 'total': 0})
        }
        
        # Test true positives
        for secret_type, secrets in test_cases['true_positives'].items():
            for secret in secrets:
                results['total_true_positives'] += 1
                results['by_type'][secret_type]['total'] += 1
                
                detected = False
                for pattern_name, pattern in pattern_db.patterns.items():
                    if re.search(pattern, secret):
                        detected = True
                        results['true_positives_detected'] += 1
                        results['by_type'][secret_type]['detected'] += 1
                        print(f"✓ Detected: {secret[:30]}... as {pattern_name}")
                        break
                
                if not detected:
                    print(f"✗ Missed: {secret[:30]}...")
        
        # Test false positives
        for text in test_cases['false_positives']:
            for pattern_name, pattern in pattern_db.patterns.items():
                if re.search(pattern, text):
                    results['false_positives'] += 1
                    print(f"✗ False positive: {text[:30]}... matched {pattern_name}")
                    break
        
        # Calculate metrics
        recall = results['true_positives_detected'] / results['total_true_positives']
        
        print(f"\nPattern Matching Results:")
        print(f"  Detected: {results['true_positives_detected']}/{results['total_true_positives']}")
        print(f"  Recall: {recall:.2%}")
        print(f"  False Positives: {results['false_positives']}")
        
        self.results['pattern_matching'] = results
        return results
    
    def test_entropy_analysis(self):
        """Test entropy calculation"""
        print("\n" + "="*60)
        print("TESTING ENTROPY ANALYSIS")
        print("="*60)
        
        analyzer = EntropyAnalyzer()
        
        test_strings = {
            'high_entropy': [
                ('AKIAIOSFODNN7EXAMPLE', 4.5),
                ('a1B2c3D4e5F6g7H8i9J0', 4.0),
                ('wJalrXUtnFEMI/K7MDENG', 4.5),
            ],
            'low_entropy': [
                ('aaaaaaaaaaaaaaaa', 1.0),
                ('12345678901234567890', 2.5),
                ('example-example-example', 3.0),
            ]
        }
        
        results = {'correct': 0, 'total': 0}
        
        for category, strings in test_strings.items():
            print(f"\n{category.upper().replace('_', ' ')}:")
            for string, expected_min in strings:
                entropy = analyzer.calculate_shannon_entropy(string)
                results['total'] += 1
                
                if category == 'high_entropy':
                    correct = entropy >= expected_min
                else:
                    correct = entropy < expected_min
                
                if correct:
                    results['correct'] += 1
                    
                status = "✓" if correct else "✗"
                print(f"  {status} '{string[:20]}...': {entropy:.2f} (expected {'≥' if category == 'high_entropy' else '<'}{expected_min})")
        
        accuracy = results['correct'] / results['total']
        print(f"\nEntropy Analysis Accuracy: {accuracy:.2%}")
        
        self.results['entropy_analysis'] = results
        return results
    
    def test_placeholder_detection(self):
        """Test placeholder detection"""
        print("\n" + "="*60)
        print("TESTING PLACEHOLDER DETECTION")
        print("="*60)
        
        from scanner_core import PatternDatabase
        pattern_db = PatternDatabase()
        
        test_cases = self.create_test_cases()
        
        results = {
            'correctly_identified': 0,
            'total': len(test_cases['placeholders']),
            'false_negatives': []
        }
        
        for placeholder in test_cases['placeholders']:
            is_placeholder = pattern_db.is_placeholder(placeholder)
            if is_placeholder:
                results['correctly_identified'] += 1
                print(f"✓ Detected placeholder: {placeholder}")
            else:
                results['false_negatives'].append(placeholder)
                print(f"✗ Missed placeholder: {placeholder}")
        
        accuracy = results['correctly_identified'] / results['total']
        print(f"\nPlaceholder Detection Accuracy: {accuracy:.2%}")
        
        self.results['placeholder_detection'] = results
        return results
    
    def test_full_scanner(self):
        """Test complete scanner with integration"""
        print("\n" + "="*60)
        print("TESTING FULL SCANNER")
        print("="*60)
        
        scanner = SecretsScanner(min_entropy=3.5)
        test_cases = self.create_test_cases()
        
        # Create test content
        test_content = ""
        ground_truth = []
        
        # Add true positives
        line_num = 1
        for secret_type, secrets in test_cases['true_positives'].items():
            for secret in secrets:
                test_content += f"secret = '{secret}'\n"
                ground_truth.append(line_num)
                line_num += 1
        
        # Add placeholders (should not detect)
        for placeholder in test_cases['placeholders']:
            test_content += f"placeholder = '{placeholder}'\n"
            line_num += 1
        
        # Add false positives
        for fp in test_cases['false_positives']:
            test_content += f"{fp}\n"
            line_num += 1
        
        # Scan
        matches = scanner.scan_string(test_content, "test_file.py")
        
        detected_lines = [m.line_number for m in matches]
        
        # Calculate metrics
        tp = len(set(detected_lines) & set(ground_truth))
        fp = len(set(detected_lines) - set(ground_truth))
        fn = len(set(ground_truth) - set(detected_lines))
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        print(f"\nFull Scanner Results:")
        print(f"  True Positives: {tp}")
        print(f"  False Positives: {fp}")
        print(f"  False Negatives: {fn}")
        print(f"  Precision: {precision:.2%}")
        print(f"  Recall: {recall:.2%}")
        print(f"  F1 Score: {f1:.3f}")
        
        results = {
            'tp': tp, 'fp': fp, 'fn': fn,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'detected': len(matches)
        }
        
        self.results['full_scanner'] = results
        return results
    
    def test_performance(self):
        """Test performance metrics"""
        print("\n" + "="*60)
        print("TESTING PERFORMANCE")
        print("="*60)
        
        scanner = SecretsScanner()
        
        # Generate test content
        test_content = "secret = 'AKIAIOSFODNN7EXAMPLE'\n" * 1000
        
        # Time scanning
        iterations = 10
        times = []
        
        for i in range(iterations):
            start = time.time()
            scanner.scan_string(test_content, "perf_test.py")
            end = time.time()
            times.append(end - start)
        
        avg_time = sum(times) / len(times)
        lines_per_second = 1000 / avg_time
        
        print(f"\nPerformance Results:")
        print(f"  Average scan time: {avg_time*1000:.2f} ms")
        print(f"  Lines per second: {lines_per_second:.0f}")
        print(f"  Throughput: ~{lines_per_second*50/1000:.0f} files/second (assuming 50 lines/file)")
        
        results = {
            'avg_time_ms': avg_time * 1000,
            'lines_per_second': lines_per_second
        }
        
        self.results['performance'] = results
        return results
    
    def run_all_tests(self):
        """Run complete evaluation suite"""
        print("\n" + "="*70)
        print(" "*20 + "EVALUATION SUITE")
        print("="*70)
        
        self.test_pattern_matching()
        self.test_entropy_analysis()
        self.test_placeholder_detection()
        self.test_full_scanner()
        self.test_performance()
        
        self.print_summary()
        self.export_results()
    
    def print_summary(self):
        """Print evaluation summary"""
        print("\n" + "="*70)
        print(" "*25 + "SUMMARY")
        print("="*70)
        
        # Full scanner metrics
        fs = self.results['full_scanner']
        print(f"\nOverall Performance:")
        print(f"  Precision: {fs['precision']:.1%}")
        print(f"  Recall: {fs['recall']:.1%}")
        print(f"  F1 Score: {fs['f1']:.3f}")
        
        # Component accuracy
        pm = self.results['pattern_matching']
        print(f"\nPattern Matching:")
        print(f"  Detection Rate: {pm['true_positives_detected']}/{pm['total_true_positives']}")
        
        ph = self.results['placeholder_detection']
        print(f"\nPlaceholder Detection:")
        print(f"  Accuracy: {ph['correctly_identified']}/{ph['total']}")
        
        perf = self.results['performance']
        print(f"\nPerformance:")
        print(f"  Scan Speed: {perf['lines_per_second']:.0f} lines/second")
        
        print("\n" + "="*70)
    
    def export_results(self):
        """Export results to JSON"""
        output_file = "evaluation_results.json"
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        print(f"\nResults exported to: {output_file}")

def main():
    """Run evaluation"""
    evaluator = EvaluationSuite()
    evaluator.run_all_tests()

if __name__ == "__main__":
    main()