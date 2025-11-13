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


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="AD Enumeration Tool - Automated Active Directory enumeration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -pc 10.1.1.1,10.1.1.2     Port scan specific IPs
  %(prog)s -f 192.168.1.0/24         Full enumeration of network range
  %(prog)s -f 10.1.1.1,10.1.1.5     Full enumeration of specific IPs
        """
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        '-pc', '--portscan',
        metavar='IPs',
        help='Perform port scan only. Comma-separated IPs (e.g., 10.1.1.1,10.1.1.2)'
    )
    group.add_argument(
        '-f', '--full',
        metavar='IPs',
        help='Full enumeration. Comma-separated IPs or CIDR (e.g., 192.168.1.0/24)'
    )
    
    parser.add_argument(
        '-o', '--output',
        metavar='DIR',
        default='ad_enum_results',
        help='Output directory (default: ad_enum_results)'
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
    
    return parser.parse_args()


async def main():
    """Main function"""
    args = parse_arguments()
    
    # Setup logging and output directory
    logger = setup_logging(args.verbose)
    output_dir = create_output_directory(args.output)
    
    logger.info(f"AD Enumeration Tool started")
    logger.info(f"Output directory: {output_dir}")
    
    # Parse and validate IP addresses
    if args.portscan:
        ips = validate_ips(args.portscan)
        if not ips:
            logger.error("No valid IPs provided for port scan")
            return 1
            
        logger.info(f"Starting port scan for {len(ips)} targets")
        scanner = PortScanner(output_dir, args.threads)
        results = await scanner.scan_targets(ips)
        
        logger.info(f"Port scan completed. Results saved to {output_dir}")
        
    elif args.full:
        ips = validate_ips(args.full)
        if not ips:
            logger.error("No valid IPs provided for full enumeration")
            return 1
            
        logger.info(f"Starting full enumeration for {len(ips)} targets")
        enumerator = FullEnumerator(output_dir, args.threads)
        results = await enumerator.enumerate_targets(ips)
        
        logger.info(f"Full enumeration completed. Results saved to {output_dir}")
    
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