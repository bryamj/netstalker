#!/usr/bin/env python3
"""
Pentest Toolkit - Main Entry Point

A comprehensive penetration testing automation framework.
Supports both CLI arguments and interactive menu mode.

Usage:
    Interactive Mode:
        python pentest.py

    CLI Mode:
        python pentest.py -t <target> --scan quick
        python pentest.py -t <target> --scan full --scripts
        python pentest.py -t <target> --web gobuster
        python pentest.py -t <target> --smb enum4linux
        python pentest.py -t <target> --ad asrep -d DOMAIN

For authorized security assessments only.
"""

import argparse
import sys
from pathlib import Path

# Add the toolkit directory to path
TOOLKIT_DIR = Path(__file__).parent
sys.path.insert(0, str(TOOLKIT_DIR))

from configs.config import (
    SCAN_PROFILES, RESULTS_DIR, get_installed_tools,
    TargetConfig
)
from modules.utils import (
    Colors, print_banner, print_section, print_success,
    print_error, print_warning, print_info, validate_ip,
    OutputManager
)
from modules.scanning import Scanner, run_scan_menu
from modules.web_enum import WebEnumerator, run_web_menu
from modules.services import ServiceEnumerator, run_services_menu
from modules.ad_enum import ADEnumerator, run_ad_menu
from modules.anon_login import AnonymousLoginTester, run_anon_menu


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Pentest Toolkit - Automated Penetration Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Interactive mode:
    python pentest.py

  Quick scan:
    python pentest.py -t 10.10.10.10 --scan quick

  Full scan with scripts:
    python pentest.py -t 10.10.10.10 --scan full --scripts

  Web enumeration:
    python pentest.py -t http://10.10.10.10 --web gobuster

  SMB enumeration:
    python pentest.py -t 10.10.10.10 --smb enum4linux

  AD enumeration:
    python pentest.py -t 10.10.10.10 -d DOMAIN.LOCAL --ad asrep

  Kerberoasting:
    python pentest.py -t 10.10.10.10 -d DOMAIN.LOCAL --ad kerberoast -u user -p pass

  Anonymous login testing:
    python pentest.py -t 10.10.10.10 --anon all
    python pentest.py -t 10.10.10.10 --anon ftp
    python pentest.py -t 10.10.10.10 --anon smb

  Scan + Anonymous login testing:
    python pentest.py -t 10.10.10.10 --scan quick --scan-anon

  Active Directory scans:
    python pentest.py -t 10.10.10.10 --scan ad
    python pentest.py -t 10.10.10.10 --smb genhosts

  Web application scans:
    python pentest.py -t 10.10.10.10 --scan web
        """
    )

    # Target options
    parser.add_argument('-t', '--target',
                        help='Target IP address or hostname')
    parser.add_argument('-d', '--domain',
                        help='Domain name (for AD enumeration)')

    # Scan options
    parser.add_argument('--scan',
                        choices=['quick', 'full', 'stealth', 'smb', 'http', 'vuln', 'udp', 'ad', 'web'],
                        help='Run a scan profile')
    parser.add_argument('--scripts', action='store_true',
                        help='Include vulnerability scripts in scan')
    parser.add_argument('-p', '--ports',
                        help='Specific ports to scan (e.g., "22,80,443" or "1-1000")')

    # Anonymous login testing options
    parser.add_argument('--anon',
                        choices=['all', 'ftp', 'smb', 'ldap', 'mysql', 'postgresql', 'redis',
                                 'mongodb', 'snmp', 'nfs', 'rsync', 'telnet', 'rpc'],
                        help='Test anonymous/null logins for services')
    parser.add_argument('--scan-anon', action='store_true',
                        help='Run scan and automatically test anonymous logins')

    # Web enumeration options
    parser.add_argument('--web',
                        choices=['gobuster', 'ffuf', 'nikto', 'nuclei', 'full'],
                        help='Run web enumeration')
    parser.add_argument('-w', '--wordlist',
                        default='dirb_common',
                        help='Wordlist for directory brute-forcing')
    parser.add_argument('-x', '--extensions',
                        help='File extensions for web enumeration')

    # Service enumeration options
    parser.add_argument('--smb',
                        choices=['enum4linux', 'smbclient', 'cme', 'rpcclient', 'genhosts', 'full'],
                        help='Run SMB enumeration')
    parser.add_argument('--hosts-file',
                        default='/etc/hosts',
                        help='Path to hosts file for NetExec generation (default: /etc/hosts)')

    # AD enumeration options
    parser.add_argument('--ad',
                        choices=['asrep', 'kerberoast', 'secretsdump', 'lookupsid', 'psexec', 'wmiexec', 'full'],
                        help='Run AD enumeration')

    # Authentication options
    parser.add_argument('-u', '--username',
                        help='Username for authentication')
    parser.add_argument('-P', '--password',
                        help='Password for authentication')
    parser.add_argument('-H', '--hash',
                        help='NTLM hash for pass-the-hash')
    parser.add_argument('--users-file',
                        help='File containing usernames')

    # Output options
    parser.add_argument('-o', '--output-dir',
                        help='Custom output directory')
    parser.add_argument('--no-color', action='store_true',
                        help='Disable colored output')

    # Utility options
    parser.add_argument('--check-tools', action='store_true',
                        help='Check installed tools and exit')
    parser.add_argument('--list-profiles', action='store_true',
                        help='List available scan profiles')

    return parser.parse_args()


def check_tools():
    """Check and display installed tools."""
    print_section("Tool Availability Check")

    tools = get_installed_tools()

    categories = {
        "Scanning": ["rustscan", "nmap"],
        "Web Enumeration": ["gobuster", "ffuf", "nikto", "nuclei"],
        "SMB/Services": ["enum4linux", "enum4linux-ng", "smbclient", "crackmapexec", "netexec"],
        "Active Directory": [
            "impacket-GetNPUsers", "impacket-GetUserSPNs",
            "impacket-secretsdump", "impacket-psexec",
            "impacket-wmiexec", "impacket-smbexec"
        ]
    }

    for category, tool_list in categories.items():
        print(f"\n{Colors.BOLD}{category}:{Colors.RESET}")
        for tool in tool_list:
            if tool in tools:
                status = f"{Colors.GREEN}✓{Colors.RESET}" if tools[tool] else f"{Colors.RED}✗{Colors.RESET}"
                print(f"  {status} {tool}")


def list_profiles():
    """List available scan profiles."""
    print_section("Available Scan Profiles")

    for name, profile in SCAN_PROFILES.items():
        print(f"\n{Colors.BOLD}{name}{Colors.RESET}: {profile.name}")
        print(f"  {Colors.CYAN}{profile.description}{Colors.RESET}")
        if profile.nmap_args:
            print(f"  Nmap args: {' '.join(profile.nmap_args)}")
        if profile.scripts:
            print(f"  Scripts: {', '.join(profile.scripts)}")


def run_interactive_mode():
    """Run the interactive menu mode."""
    print_banner()

    while True:
        print_section("Main Menu")

        print("  [1] Port Scanning (RustScan/Nmap)")
        print("  [2] Web Enumeration")
        print("  [3] SMB/Service Enumeration")
        print("  [4] Active Directory Enumeration")
        print("  [5] Anonymous Login Testing")
        print("  [6] Scan + Anonymous Login Testing")
        print("  [7] Check Installed Tools")
        print("  [8] List Scan Profiles")
        print("  [0] Exit")

        choice = input(f"\n{Colors.CYAN}Select option: {Colors.RESET}").strip()

        if choice == '0':
            print_info("Goodbye!")
            sys.exit(0)

        elif choice == '1':
            target = input(f"{Colors.CYAN}Enter target IP/hostname: {Colors.RESET}").strip()
            if validate_ip(target):
                run_scan_menu(target)
            else:
                print_error("Invalid target")

        elif choice == '2':
            target = input(f"{Colors.CYAN}Enter target URL: {Colors.RESET}").strip()
            if target:
                run_web_menu(target)
            else:
                print_error("Target required")

        elif choice == '3':
            target = input(f"{Colors.CYAN}Enter target IP: {Colors.RESET}").strip()
            if validate_ip(target):
                run_services_menu(target)
            else:
                print_error("Invalid target")

        elif choice == '4':
            target = input(f"{Colors.CYAN}Enter DC IP: {Colors.RESET}").strip()
            domain = input(f"{Colors.CYAN}Enter domain name: {Colors.RESET}").strip()
            if validate_ip(target) and domain:
                run_ad_menu(target, domain)
            else:
                print_error("Target IP and domain required")

        elif choice == '5':
            target = input(f"{Colors.CYAN}Enter target IP: {Colors.RESET}").strip()
            if validate_ip(target):
                run_anon_menu(target)
            else:
                print_error("Invalid target")

        elif choice == '6':
            target = input(f"{Colors.CYAN}Enter target IP: {Colors.RESET}").strip()
            if validate_ip(target):
                scanner = Scanner(target)
                scanner.scan_and_test_anon(profile="quick")
            else:
                print_error("Invalid target")

        elif choice == '7':
            check_tools()

        elif choice == '8':
            list_profiles()

        else:
            print_error("Invalid option")

        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.RESET}")


def run_cli_mode(args):
    """Run in CLI mode with command line arguments."""
    print_banner()

    if not args.target:
        print_error("Target is required. Use -t <target>")
        sys.exit(1)

    if not validate_ip(args.target) and not args.target.startswith('http'):
        print_error(f"Invalid target: {args.target}")
        sys.exit(1)

    # Setup output manager
    target_for_output = args.target.replace('http://', '').replace('https://', '').split('/')[0]
    output_dir = Path(args.output_dir) if args.output_dir else RESULTS_DIR
    output_manager = OutputManager(output_dir, target_for_output)

    # Run scans based on arguments
    if args.scan:
        scanner = Scanner(args.target, output_manager)

        # Check if we should also run anonymous login tests
        if args.scan_anon:
            scanner.scan_and_test_anon(profile=args.scan)
        elif args.scan == 'quick':
            scanner.quick_scan()
        elif args.scan == 'full':
            scanner.full_scan(with_scripts=args.scripts)
        elif args.scan == 'stealth':
            scanner.stealth_scan()
        elif args.scan == 'smb':
            scanner.smb_scan()
        elif args.scan == 'http':
            scanner.http_scan()
        elif args.scan == 'vuln':
            scanner.vuln_scan(ports=args.ports)
        elif args.scan == 'udp':
            scanner.udp_scan()
        elif args.scan == 'ad':
            scanner.ad_scan(ports=args.ports)
        elif args.scan == 'web':
            scanner.web_scan(ports=args.ports)

    elif args.anon:
        tester = AnonymousLoginTester(args.target, output_manager)

        if args.anon == 'all':
            tester.test_all_services()
        elif args.anon == 'ftp':
            tester.test_ftp_anonymous()
        elif args.anon == 'smb':
            tester.test_smb_anonymous()
            tester.test_smb_share_access()
        elif args.anon == 'ldap':
            tester.test_ldap_anonymous()
        elif args.anon == 'mysql':
            tester.test_mysql_anonymous()
        elif args.anon == 'postgresql':
            tester.test_postgresql_anonymous()
        elif args.anon == 'redis':
            tester.test_redis_anonymous()
        elif args.anon == 'mongodb':
            tester.test_mongodb_anonymous()
        elif args.anon == 'snmp':
            tester.test_snmp_public()
        elif args.anon == 'nfs':
            tester.test_nfs_exports()
        elif args.anon == 'rsync':
            tester.test_rsync_anonymous()
        elif args.anon == 'telnet':
            tester.test_telnet_banner()
        elif args.anon == 'rpc':
            tester.test_rpc_anonymous()

    elif args.web:
        enumerator = WebEnumerator(args.target, output_manager)

        if args.web == 'gobuster':
            enumerator.gobuster_dir(
                wordlist=args.wordlist,
                extensions=args.extensions
            )
        elif args.web == 'ffuf':
            enumerator.ffuf(wordlist=args.wordlist)
        elif args.web == 'nikto':
            enumerator.nikto()
        elif args.web == 'nuclei':
            enumerator.nuclei()
        elif args.web == 'full':
            enumerator.full_enum(
                wordlist=args.wordlist,
                extensions=args.extensions or "php,html,txt,js"
            )

    elif args.smb:
        enumerator = ServiceEnumerator(args.target, output_manager)

        if args.smb == 'enum4linux':
            enumerator.enum4linux(args.username, args.password)
        elif args.smb == 'smbclient':
            enumerator.smbclient_list(args.username, args.password)
        elif args.smb == 'cme':
            enumerator.crackmapexec_smb(args.username, args.password)
        elif args.smb == 'rpcclient':
            enumerator.rpcclient_enum(args.username, args.password)
        elif args.smb == 'genhosts':
            enumerator.netexec_generate_hosts(hosts_file=args.hosts_file)
        elif args.smb == 'full':
            enumerator.smb_full_enum(args.username, args.password)

    elif args.ad:
        if not args.domain:
            print_error("Domain is required for AD enumeration. Use -d DOMAIN")
            sys.exit(1)

        enumerator = ADEnumerator(args.target, args.domain, output_manager)

        if args.ad == 'asrep':
            enumerator.get_np_users(
                username=args.username,
                password=args.password,
                users_file=args.users_file
            )
        elif args.ad == 'kerberoast':
            if not args.username:
                print_error("Username required for Kerberoasting")
                sys.exit(1)
            enumerator.get_user_spns(
                username=args.username,
                password=args.password,
                hash_val=args.hash
            )
        elif args.ad == 'secretsdump':
            if not args.username:
                print_error("Username required for secretsdump")
                sys.exit(1)
            enumerator.secretsdump(
                username=args.username,
                password=args.password,
                hash_val=args.hash
            )
        elif args.ad == 'lookupsid':
            enumerator.lookupsid(args.username, args.password)
        elif args.ad == 'psexec':
            if not args.username:
                print_error("Username required for PSExec")
                sys.exit(1)
            enumerator.psexec(
                username=args.username,
                password=args.password,
                hash_val=args.hash
            )
        elif args.ad == 'wmiexec':
            if not args.username:
                print_error("Username required for WMIExec")
                sys.exit(1)
            enumerator.wmiexec(
                username=args.username,
                password=args.password,
                hash_val=args.hash
            )
        elif args.ad == 'full':
            enumerator.ad_full_enum(
                username=args.username,
                password=args.password,
                hash_val=args.hash,
                users_file=args.users_file
            )

    else:
        print_warning("No action specified. Use --scan, --web, --smb, --ad, or --anon")
        print_info("Run with -h for help or without arguments for interactive mode")


def main():
    """Main entry point."""
    args = parse_arguments()

    # Handle no-color mode
    if args.no_color:
        Colors.disable()

    # Handle utility commands
    if args.check_tools:
        print_banner()
        check_tools()
        sys.exit(0)

    if args.list_profiles:
        print_banner()
        list_profiles()
        sys.exit(0)

    # Run in appropriate mode
    if args.target or args.scan or args.web or args.smb or args.ad or args.anon:
        run_cli_mode(args)
    else:
        run_interactive_mode()


if __name__ == "__main__":
    main()
