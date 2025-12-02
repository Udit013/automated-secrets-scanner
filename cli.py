"""
Command-line interface for the Automated Secrets Scanner
"""

import argparse
import sys
from pathlib import Path
from scanner_core import SecretsScanner
import json

def create_parser():
    """Create and configure argument parser"""
    parser = argparse.ArgumentParser(
        description='Automated Sensitive Data Scanner - Detect secrets in code',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan current directory
  python cli.py -d .
  
  # Scan specific file
  python cli.py -f config.py
  
  # Scan Git history
  python cli.py -g /path/to/repo --max-commits 50
  
  # Export results to JSON
  python cli.py -d . -o results.json
  
  # Set custom entropy threshold
  python cli.py -d . --min-entropy 4.0
        """
    )
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        '-f', '--file',
        help='Scan a specific file'
    )
    input_group.add_argument(
        '-d', '--directory',
        help='Scan a directory'
    )
    input_group.add_argument(
        '-g', '--git',
        help='Scan Git repository history'
    )
    input_group.add_argument(
        '-s', '--string',
        help='Scan a string directly'
    )
    
    # Scanning options
    parser.add_argument(
        '--min-entropy',
        type=float,
        default=3.5,
        help='Minimum entropy threshold (default: 3.5)'
    )
    parser.add_argument(
        '--max-commits',
        type=int,
        default=100,
        help='Maximum commits to scan in Git history (default: 100)'
    )
    parser.add_argument(
        '--recursive',
        action='store_true',
        default=True,
        help='Recursively scan directories (default: True)'
    )
    
    # Output options
    parser.add_argument(
        '-o', '--output',
        help='Output file for results'
    )
    parser.add_argument(
        '--format',
        choices=['json', 'csv', 'console'],
        default='console',
        help='Output format (default: console)'
    )
    parser.add_argument(
        '--stats',
        action='store_true',
        help='Show statistics summary'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Verbose output'
    )
    
    return parser

def print_banner():
    """Print application banner"""
    banner = """
╔═══════════════════════════════════════════════════════════╗
║     Automated Sensitive Data Scanner v1.0                 ║
║     Detecting hardcoded secrets in your codebase          ║
╚═══════════════════════════════════════════════════════════╝
    """
    print(banner)

def print_statistics(stats):
    """Print scanning statistics"""
    print("\n" + "="*60)
    print("SCANNING STATISTICS")
    print("="*60)
    print(f"Total Secrets Found: {stats['total_secrets']}")
    print(f"High Risk Secrets: {stats['high_risk_count']}")
    
    print("\nBy Confidence Level:")
    for conf, count in stats['by_confidence'].items():
        print(f"  {conf}: {count}")
    
    print("\nBy Secret Type:")
    for secret_type, count in sorted(stats['by_type'].items(), 
                                     key=lambda x: x[1], reverse=True):
        print(f"  {secret_type}: {count}")
    
    print("\nTop Files with Secrets:")
    sorted_files = sorted(stats['by_file'].items(), 
                         key=lambda x: x[1], reverse=True)[:5]
    for file_path, count in sorted_files:
        print(f"  {file_path}: {count}")
    print("="*60 + "\n")

def main():
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    print_banner()
    
    # Create scanner instance
    scanner = SecretsScanner(min_entropy=args.min_entropy)
    
    # Perform scanning based on input type
    try:
        if args.file:
            print(f"Scanning file: {args.file}")
            if not Path(args.file).exists():
                print(f"Error: File '{args.file}' not found")
                sys.exit(1)
            scanner.scan_file(args.file)
            
        elif args.directory:
            print(f"Scanning directory: {args.directory}")
            if not Path(args.directory).exists():
                print(f"Error: Directory '{args.directory}' not found")
                sys.exit(1)
            scanner.scan_directory(args.directory, recursive=args.recursive)
            
        elif args.git:
            print(f"Scanning Git repository: {args.git}")
            print(f"Analyzing last {args.max_commits} commits...")
            if not Path(args.git).exists():
                print(f"Error: Repository '{args.git}' not found")
                sys.exit(1)
            scanner.scan_git_history(args.git, max_commits=args.max_commits)
            
        elif args.string:
            print("Scanning provided string...")
            scanner.scan_string(args.string)
        
        # Handle output
        if args.output:
            format_type = args.format if args.format != 'console' else 'json'
            scanner.export_results(args.output, format=format_type)
            print(f"\n✓ Results exported to: {args.output}")
        
        # Print results to console
        if args.format == 'console' or not args.output:
            scanner.print_results()
        
        # Print statistics if requested
        if args.stats:
            stats = scanner.get_statistics()
            print_statistics(stats)
        
        # Exit with appropriate code
        if scanner.results:
            print(f"\n⚠ Warning: {len(scanner.results)} potential secrets detected!")
            sys.exit(1)
        else:
            print("\n✓ Scan complete. No secrets detected.")
            sys.exit(0)
            
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n✗ Error during scanning: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()