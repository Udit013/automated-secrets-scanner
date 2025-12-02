"""
Core scanning engine for sensitive data detection
Implements pattern matching, entropy analysis, and Git history scanning
"""

import re
import math
import os
from collections import defaultdict
from typing import List, Dict, Tuple, Optional
import json
from dataclasses import dataclass, asdict
from pathlib import Path

@dataclass
class SecretMatch:
    """Data class for storing detected secrets"""
    file_path: str
    line_number: int
    secret_type: str
    matched_string: str
    entropy: float
    confidence: str
    context: str
    commit_hash: Optional[str] = None
    
class PatternDatabase:
    """Database of patterns for secret detection"""
    
    def __init__(self):
        self.patterns = {
            'AWS Access Key': r'AKIA[0-9A-Z]{16}',
            'AWS Secret Key': r'aws.*["\'][0-9a-zA-Z/+]{40}["\']',
            'GitHub Token': r'gh[pousr]_[0-9a-zA-Z]{36}',
            'Generic API Key': r'[aA][pP][iI].*[kK][eE][yY].*["\'][0-9a-zA-Z]{32,45}["\']',
            'Private SSH Key': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
            'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
            'Slack Token': r'xox[baprs]-[0-9a-zA-Z]{10,48}',
            'Stripe API Key': r'sk_live_[0-9a-zA-Z]{24}',
            'Generic Secret': r'[sS][eE][cC][rR][eE][tT].*["\'][0-9a-zA-Z]{16,}["\']',
            'Password': r'[pP][aA][sS][sS].*["\'][^"\']{8,}["\']',
            'Database Connection': r'(mongodb|mysql|postgres|postgresql)://[^\s"\'\)]+',
            'JWT Token': r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_.-]+',
            'Azure Key': r'[0-9a-zA-Z]{8}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{12}',
        }
        
        # Patterns that indicate placeholders/sanitized keys
        
        self.placeholder_patterns = [
            r'(xxx|XXX){3,}',
            r'(example|EXAMPLE|sample|SAMPLE)',
            r'(your|YOUR)[-_]?(key|token|secret|password|api)',
            r'(placeholder|PLACEHOLDER)',
            r'(dummy|DUMMY)',
            r'<[^>]+>',  # XML-style placeholders
            r'\$\{[^}]+\}',  # Variable placeholders
            r'%[^%]+%',  # Environment variable style
            r'(here|HERE)$',  # Ends with "here"
        ]
        
    def is_placeholder(self, text: str) -> bool:
        """Check if the matched string is likely a placeholder"""
        for pattern in self.placeholder_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

class EntropyAnalyzer:
    """Analyzes string entropy to detect high-entropy secrets"""
    
    @staticmethod
    def calculate_shannon_entropy(data: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not data:
            return 0.0
        
        entropy = 0.0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        return entropy
    
    @staticmethod
    def get_confidence_level(entropy: float, has_pattern: bool) -> str:
        """Determine confidence level based on entropy and pattern match"""
        if has_pattern and entropy > 4.5:
            return "HIGH"
        elif has_pattern and entropy > 3.5:
            return "MEDIUM"
        elif entropy > 5.0:
            return "MEDIUM"
        else:
            return "LOW"

class SecretsScanner:
    """Main scanner class"""
    
    def __init__(self, min_entropy: float = 3.5):
        self.pattern_db = PatternDatabase()
        self.entropy_analyzer = EntropyAnalyzer()
        self.min_entropy = min_entropy
        self.results: List[SecretMatch] = []
        
        # File extensions to scan
        self.scannable_extensions = {
            '.py', '.js', '.java', '.cpp', '.c', '.h', '.cs', '.go', 
            '.rb', '.php', '.swift', '.kt', '.ts', '.tsx', '.jsx',
            '.yaml', '.yml', '.json', '.xml', '.conf', '.config',
            '.env', '.properties', '.txt', '.md', '.sh', '.bash'
        }
        
        # Directories to ignore
        self.ignore_dirs = {
            '.git', 'node_modules', 'venv', '__pycache__', 
            '.idea', '.vscode', 'build', 'dist', 'target'
        }
    
    def scan_string(self, content: str, file_path: str = "string", 
                   commit_hash: Optional[str] = None) -> List[SecretMatch]:
        """Scan a string for secrets"""
        matches = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for secret_type, pattern in self.pattern_db.patterns.items():
                for match in re.finditer(pattern, line):
                    matched_text = match.group(0)
                    
                    # Skip if it's a placeholder
                    if self.pattern_db.is_placeholder(matched_text):
                        continue
                    
                    # Calculate entropy
                    entropy = self.entropy_analyzer.calculate_shannon_entropy(matched_text)
                    
                    # Special handling for format-specific secrets
                    # AWS keys, SSH keys, etc. should pass even with lower entropy
                    format_specific = secret_type in [
                        'AWS Access Key', 'Private SSH Key', 'Stripe API Key',
                        'Google API Key', 'GitHub Token'
                    ]
                    
                    # Only report if entropy is above threshold OR it's format-specific
                    if entropy >= self.min_entropy or format_specific:
                        confidence = self.entropy_analyzer.get_confidence_level(
                            entropy, True
                        )
                        
                        # Get context (truncated line)
                        context = line.strip()[:100]
                        
                        secret_match = SecretMatch(
                            file_path=file_path,
                            line_number=line_num,
                            secret_type=secret_type,
                            matched_string=self._mask_secret(matched_text),
                            entropy=round(entropy, 2),
                            confidence=confidence,
                            context=context,
                            commit_hash=commit_hash
                        )
                        matches.append(secret_match)
        
        return matches
    
    def scan_file(self, file_path: str) -> List[SecretMatch]:
            """Scan a single file"""
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                matches = self.scan_string(content, file_path)
                self.results.extend(matches)  # ADD THIS LINE
                return matches
            except Exception as e:
                print(f"Error scanning file {file_path}: {e}")
                return []
    
    def scan_directory(self, directory: str, recursive: bool = True) -> List[SecretMatch]:
        """Scan a directory for secrets"""
        all_matches = []
        
        for root, dirs, files in os.walk(directory):
            # Remove ignored directories
            dirs[:] = [d for d in dirs if d not in self.ignore_dirs]
            
            for file in files:
                file_path = os.path.join(root, file)
                ext = os.path.splitext(file)[1]
                
                if ext in self.scannable_extensions or file.startswith('.env'):
                    matches = self.scan_file(file_path)
                    all_matches.extend(matches)
            
            if not recursive:
                break
        
        self.results.extend(all_matches)
        return all_matches
    
    def scan_git_history(self, repo_path: str, max_commits: int = 100) -> List[SecretMatch]:
        """Scan Git repository history"""
        try:
            import git
        except ImportError:
            print("GitPython not installed. Install with: pip install GitPython")
            return []
        
        try:
            repo = git.Repo(repo_path)
            all_matches = []
            
            commits = list(repo.iter_commits('HEAD', max_count=max_commits))
            
            for commit in commits:
                try:
                    for item in commit.tree.traverse():
                        if item.type == 'blob':
                            try:
                                content = item.data_stream.read().decode('utf-8', errors='ignore')
                                matches = self.scan_string(
                                    content, 
                                    item.path, 
                                    commit.hexsha[:8]
                                )
                                all_matches.extend(matches)
                            except Exception:
                                continue
                except Exception:
                    continue
            
            self.results.extend(all_matches)
            return all_matches
            
        except Exception as e:
            print(f"Error scanning Git repository: {e}")
            return []
    
    def _mask_secret(self, secret: str, show_chars: int = 4) -> str:
        """Mask a secret for safe display"""
        if len(secret) <= show_chars * 2:
            return '*' * len(secret)
        return secret[:show_chars] + '*' * (len(secret) - show_chars * 2) + secret[-show_chars:]
    
    def get_statistics(self) -> Dict:
        """Get scanning statistics"""
        stats = {
            'total_secrets': len(self.results),
            'by_type': defaultdict(int),
            'by_confidence': defaultdict(int),
            'by_file': defaultdict(int),
            'high_risk_count': 0
        }
        
        for result in self.results:
            stats['by_type'][result.secret_type] += 1
            stats['by_confidence'][result.confidence] += 1
            stats['by_file'][result.file_path] += 1
            if result.confidence == 'HIGH':
                stats['high_risk_count'] += 1
        
        return dict(stats)
    
    def export_results(self, output_file: str, format: str = 'json'):
        """Export results to file"""
        if format == 'json':
            with open(output_file, 'w') as f:
                json.dump([asdict(r) for r in self.results], f, indent=2)
        elif format == 'csv':
            import csv
            with open(output_file, 'w', newline='') as f:
                if self.results:
                    writer = csv.DictWriter(f, fieldnames=asdict(self.results[0]).keys())
                    writer.writeheader()
                    for result in self.results:
                        writer.writerow(asdict(result))
    
    def print_results(self):
        """Print results to console"""
        if not self.results:
            print("\n✓ No secrets detected!")
            return
        
        print(f"\n⚠ Found {len(self.results)} potential secrets:\n")
        
        for i, result in enumerate(self.results, 1):
            print(f"{i}. [{result.confidence}] {result.secret_type}")
            print(f"   File: {result.file_path}:{result.line_number}")
            print(f"   Matched: {result.matched_string}")
            print(f"   Entropy: {result.entropy}")
            if result.commit_hash:
                print(f"   Commit: {result.commit_hash}")
            print(f"   Context: {result.context}")
            print()