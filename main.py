#!/usr/bin/env python3
"""
AD Enumeration Tool
A comprehensive tool for Active Directory environment enumeration
"""

import argparse
import sys
import os
import asyncio
from typing import List

# Add modules directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'modules'))

from utils import validate_ips, setup_logging, create_output_directory
from port_scanner import PortScanner
from enumerators.full_enum import FullEnumerator
from enumerators.vuln_enum import VulnEnumerator
from enumerators.auth_enum import AuthEnumerator


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="AD Enumeration Tool - Automated Active Directory enumeration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -ps 10.1.1.1,10.1.1.2     Port scan specific IPs
  %(prog)s -f 192.168.1.0/24         Full enumeration of network range
  %(prog)s -f 10.1.1.1,10.1.1.5     Full enumeration of specific IPs
  %(prog)s -vulns 10.1.1.1,10.1.1.2 Vulnerability scan specific IPs
  %(prog)s -auth 10.1.1.1 -user domain/user -p password    Authenticated enumeration
  %(prog)s -auth 192.168.1.0/24 -user user -p pass --local-auth    Auth enum with local auth
  %(prog)s -f 10.1.1.1 -o custom_scan --output-path /tmp    Custom output location
        """
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        '-ps', '--portscan',
        metavar='IPs',
        help='Perform port scan only. Comma-separated IPs (e.g., 10.1.1.1,10.1.1.2)'
    )
    group.add_argument(
        '-f', '--full',
        metavar='IPs',
        help='Full enumeration. Comma-separated IPs or CIDR (e.g., 192.168.1.0/24)'
    )
    group.add_argument(
        '-vulns', '--vulnerabilities',
        metavar='IPs',
        help='Vulnerability scan using NetExec modules. Comma-separated IPs (e.g., 10.1.1.1,10.1.1.2)'
    )
    group.add_argument(
        '-auth', '--authenticated',
        metavar='IPs',
        help='Authenticated enumeration using provided credentials. Comma-separated IPs (e.g., 10.1.1.1,10.1.1.2)'
    )
    
    parser.add_argument(
        '--path-prefix',
        metavar='PREFIX',
        default='ad_enum_results',
        help='Output directory prefix, will end up like "ad_enum_results_20251121_155849" (default: ad_enum_results)'
    )
    
    parser.add_argument(
        '-o', '--output-dir',
        metavar='DIR',
        help='Custom path for output directory, where time-based result directories will reside (default: current directory)'
    )
    
    parser.add_argument(
        '-t', '--threads',
        type=int,
        default=10,
        help='Number of threads for scanning (default: 10)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )
    
    # Credential-based enumeration options
    parser.add_argument(
        '-user', '--username',
        metavar='DOMAIN/USERNAME',
        help='Domain username for authenticated enumeration (format: domain/username or username)'
    )
    
    parser.add_argument(
        '-p', '--password',
        metavar='PASSWORD',
        help='Password for authenticated enumeration'
    )
    
    parser.add_argument(
        '-hashes', '--hashes',
        metavar='NTLM_HASH',
        help='NTLM hash for authenticated enumeration (format: LM:NT or :NT)'
    )
    
    parser.add_argument(
        '--local-auth',
        action='store_true',
        help='Use local authentication instead of domain authentication'
    )

    parser.add_argument(
        '--rustscan',
        action='store_true',
        dest='rustscan',
        help='Use RustScan for faster port scanning (default: disabled).'
    )
    
    parser.add_argument(
        '-AD', '--ad-only',
        action='store_true',
        dest='ad_only',
        help='Only scan Windows/AD hosts (uses NetExec to identify Windows systems)'
    )
    
    return parser.parse_args()


async def main():
    """Main function"""
    args = parse_arguments()
    
    # Validate credential parameters for authenticated mode
    if args.authenticated:
        if not args.username:
            print("Error: Username (-user) is required for authenticated enumeration")
            return 1
        if not args.password and not args.hashes:
            print("Error: Either password (-p) or NTLM hash (-hashes) is required for authenticated enumeration")
            return 1
        if args.password and args.hashes:
            print("Error: Cannot use both password (-p) and hash (-hashes) simultaneously")
            return 1
    
    # Setup logging and output directory
    logger = setup_logging(args.verbose)
    
    # Determine scan mode for directory structure
    scan_mode = "authenticated" if args.authenticated else "full"
    username = args.username if args.authenticated else None
    output_dir = create_output_directory(args.output_dir, args.path_prefix, scan_mode, port_scan_only=(args.portscan is not None), username=username)
    
    logger.info(f"AD Enumeration Tool started")
    logger.info(f"Output directory: {output_dir}")
    
    # Parse and validate IP addresses
    if args.portscan:
        ips = validate_ips(args.portscan)
        if not ips:
            logger.error("No valid IPs provided for port scan")
            return 1
            
        logger.info(f"Starting port scan for {len(ips)} targets")
        # If --rustscan provided, use rustscan
        scanner = PortScanner(output_dir, args.threads, use_rustscan=args.rustscan, ad_only=args.ad_only)
        results = await scanner.scan_targets(ips, ip_input=args.portscan)
        
        logger.info(f"Port scan completed. Results saved to {output_dir}")
        
    elif args.full:
        ips = validate_ips(args.full)
        if not ips:
            logger.error("No valid IPs provided for full enumeration")
            return 1
            
        logger.info(f"Starting full enumeration for {len(ips)} targets")
        enumerator = FullEnumerator(output_dir, args.threads, use_rustscan=args.rustscan, ad_only=args.ad_only)
        results = await enumerator.enumerate_targets(ips, ip_input=args.full)
        
        logger.info(f"Full enumeration completed. Results saved to {output_dir}")
        
    elif args.vulnerabilities:
        ips = validate_ips(args.vulnerabilities)
        if not ips:
            logger.error("No valid IPs provided for vulnerability scan")
            return 1
            
        logger.info(f"Starting vulnerability scan for {len(ips)} targets")
        vuln_scanner = VulnEnumerator(output_dir)
        results = await vuln_scanner.scan_vulnerabilities(ips)
        
        # Generate and display summary
        summary = await vuln_scanner.generate_summary(results)
        logger.info("Vulnerability scan summary:")
        for line in summary.split('\n'):
            logger.info(line)
        
        logger.info(f"Vulnerability scan completed. Results saved to {output_dir}")
        
    elif args.authenticated:
        ips = validate_ips(args.authenticated)
        if not ips:
            logger.error("No valid IPs provided for authenticated enumeration")
            return 1
            
        logger.info(f"Starting authenticated enumeration for {len(ips)} targets")
        auth_scanner = AuthEnumerator(output_dir, args.username, args.password, args.local_auth, args.hashes)
        results = await auth_scanner.enumerate_targets(ips)
        
        # Generate and display summary
        summary = await auth_scanner.generate_summary(results)
        logger.info("Authenticated enumeration summary:")
        for line in summary.split('\n'):
            logger.info(line)
        
        logger.info(f"Authenticated enumeration completed. Results saved to {output_dir}")
    
    return 0


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)