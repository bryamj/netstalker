#!/usr/bin/env python3
"""
Scanning module for the Pentest Toolkit.
Handles RustScan, Nmap, and combined scanning operations.
"""

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional, List, Dict, Tuple
from dataclasses import dataclass, field

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from configs.config import (
    TargetConfig, ScanProfile, SCAN_PROFILES,
    check_tool_installed, RESULTS_DIR
)
from modules.utils import (
    OutputManager, CommandExecutor, CommandResult,
    print_section, print_success, print_error, print_warning, print_info,
    Colors, parse_ports, format_ports
)


@dataclass
class ScanResult:
    """Result of a scan operation."""
    target: str
    ports: List[int] = field(default_factory=list)
    services: Dict[int, Dict] = field(default_factory=dict)
    os_info: Optional[str] = None
    raw_output: str = ""
    xml_output: Optional[str] = None

    def get_service_ports(self) -> Dict[str, List[int]]:
        """
        Get ports grouped by service type for anonymous login testing.

        Returns:
            Dictionary mapping service names to port lists
        """
        service_mapping = {
            'ftp': ['ftp'],
            'smb': ['microsoft-ds', 'netbios-ssn', 'smb'],
            'ldap': ['ldap', 'ldaps'],
            'mysql': ['mysql'],
            'postgresql': ['postgresql', 'postgres'],
            'redis': ['redis'],
            'mongodb': ['mongodb', 'mongod'],
            'snmp': ['snmp'],
            'nfs': ['nfs', 'nfsd'],
            'rsync': ['rsync'],
            'telnet': ['telnet'],
            'rpc': ['rpcbind', 'sunrpc'],
            'ssh': ['ssh'],
            'http': ['http', 'https', 'http-alt', 'http-proxy'],
            'vnc': ['vnc'],
            'rdp': ['ms-wbt-server', 'rdp'],
            'mssql': ['ms-sql-s', 'mssql'],
            'oracle': ['oracle', 'oracle-tns'],
        }

        result = {}
        for port, info in self.services.items():
            service_name = info.get('service', '').lower()
            for category, names in service_mapping.items():
                if any(name in service_name for name in names):
                    if category not in result:
                        result[category] = []
                    result[category].append(port)
                    break

        return result


class Scanner:
    """Handles scanning operations with RustScan and Nmap."""

    def __init__(self, target: str, output_manager: Optional[OutputManager] = None):
        self.target = target
        self.output_manager = output_manager or OutputManager(RESULTS_DIR, target)
        self.executor = CommandExecutor(self.output_manager)

        # Check tool availability
        self.has_rustscan = check_tool_installed("rustscan")
        self.has_nmap = check_tool_installed("nmap")

        if not self.has_nmap:
            print_warning("Nmap is not installed. Some features will be unavailable.")
        if not self.has_rustscan:
            print_warning("RustScan is not installed. Using Nmap for port discovery.")

    def rustscan(
        self,
        ports: Optional[str] = None,
        ulimit: int = 5000,
        batch_size: int = 1500,
        timeout: int = 3000,
        greppable: bool = True,
        additional_args: Optional[List[str]] = None
    ) -> Tuple[List[int], CommandResult]:
        """
        Run RustScan for fast port discovery.

        Args:
            ports: Port range (e.g., "1-65535" or "22,80,443")
            ulimit: File descriptor limit
            batch_size: Batch size for scanning
            timeout: Timeout in milliseconds
            greppable: Output in greppable format
            additional_args: Additional RustScan arguments

        Returns:
            Tuple of (list of open ports, command result)
        """
        if not self.has_rustscan:
            print_error("RustScan is not installed. Install it or use Nmap instead.")
            return [], CommandResult("", -1, "", "RustScan not installed", 0, False)

        print_section("RustScan Port Discovery")

        cmd_parts = ["rustscan", "-a", self.target]
        cmd_parts.extend(["--ulimit", str(ulimit)])
        cmd_parts.extend(["-b", str(batch_size)])
        cmd_parts.extend(["--timeout", str(timeout)])

        if ports:
            if "-" in ports or ports.isdigit():
                cmd_parts.extend(["--range" if "-" in ports else "-p", ports])
            else:
                cmd_parts.extend(["-p", ports])

        if greppable:
            cmd_parts.append("-g")

        if additional_args:
            cmd_parts.extend(additional_args)

        command = " ".join(cmd_parts)
        result = self.executor.run(command, timeout=600, live_output=True)

        # Parse open ports from output
        open_ports = self._parse_rustscan_output(result.stdout)

        # Save output
        if self.output_manager:
            self.output_manager.save_output(
                'scans',
                f"rustscan_{self.target.replace('.', '_')}.txt",
                result.stdout
            )

        if open_ports:
            print_success(f"Found {len(open_ports)} open ports: {format_ports(open_ports)}")
        else:
            print_warning("No open ports found")

        return open_ports, result

    def _parse_rustscan_output(self, output: str) -> List[int]:
        """Parse RustScan output to extract open ports."""
        ports = []

        # Pattern for greppable output: IP -> [ports]
        greppable_pattern = r'\d+\.\d+\.\d+\.\d+\s*->\s*\[([\d,\s]+)\]'
        match = re.search(greppable_pattern, output)
        if match:
            port_str = match.group(1)
            ports = [int(p.strip()) for p in port_str.split(',') if p.strip()]
            return sorted(set(ports))

        # Pattern for regular output
        port_pattern = r'Open\s+(\d+\.\d+\.\d+\.\d+):(\d+)'
        for match in re.finditer(port_pattern, output):
            ports.append(int(match.group(2)))

        # Alternative pattern
        alt_pattern = r'(\d+)/tcp'
        for match in re.finditer(alt_pattern, output):
            ports.append(int(match.group(1)))

        return sorted(set(ports))

    def nmap(
        self,
        ports: Optional[str] = None,
        scan_type: str = "-sV",
        scripts: Optional[List[str]] = None,
        timing: str = "-T4",
        output_xml: bool = True,
        output_normal: bool = True,
        additional_args: Optional[List[str]] = None,
        sudo: bool = False
    ) -> Tuple[ScanResult, CommandResult]:
        """
        Run Nmap scan.

        Args:
            ports: Ports to scan (comma-separated or range)
            scan_type: Scan type flags (e.g., "-sV", "-sS", "-sU")
            scripts: NSE scripts to run
            timing: Timing template (-T0 to -T5)
            output_xml: Generate XML output
            output_normal: Generate normal output
            additional_args: Additional Nmap arguments
            sudo: Run with sudo (required for SYN scans)

        Returns:
            Tuple of (ScanResult, CommandResult)
        """
        if not self.has_nmap:
            print_error("Nmap is not installed.")
            return ScanResult(self.target), CommandResult("", -1, "", "Nmap not installed", 0, False)

        print_section("Nmap Scan")

        cmd_parts = ["nmap", scan_type, timing]

        if ports:
            cmd_parts.extend(["-p", ports])

        if scripts:
            script_str = ",".join(scripts)
            cmd_parts.extend(["--script", script_str])

        # Output files - always use -oA for all formats (.nmap, .xml, .gnmap)
        timestamp = self.output_manager.session_time if self.output_manager else "scan"
        base_name = f"nmap_{self.target.replace('.', '_')}_{timestamp}"
        output_base = self.output_manager.get_output_path('scans', base_name)

        # Use -oA to save all formats
        cmd_parts.extend(["-oA", str(output_base)])

        if additional_args:
            cmd_parts.extend(additional_args)

        cmd_parts.append(self.target)

        command = " ".join(cmd_parts)
        result = self.executor.run(command, timeout=3600, live_output=True, sudo=sudo)

        # Parse results
        scan_result = ScanResult(target=self.target, raw_output=result.stdout)

        # Parse XML output (generated by -oA)
        xml_path = Path(str(output_base) + ".xml")
        if xml_path.exists():
            scan_result = self._parse_nmap_xml(xml_path, scan_result)

        return scan_result, result

    def _parse_nmap_xml(self, xml_path: Path, scan_result: ScanResult) -> ScanResult:
        """Parse Nmap XML output."""
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()

            for host in root.findall('.//host'):
                # Get OS info
                for osmatch in host.findall('.//osmatch'):
                    scan_result.os_info = osmatch.get('name', '')
                    break

                # Get ports and services
                for port in host.findall('.//port'):
                    port_id = int(port.get('portid', 0))
                    protocol = port.get('protocol', 'tcp')

                    state = port.find('state')
                    if state is not None and state.get('state') == 'open':
                        scan_result.ports.append(port_id)

                        service = port.find('service')
                        service_info = {
                            'protocol': protocol,
                            'state': 'open',
                            'service': service.get('name', 'unknown') if service is not None else 'unknown',
                            'version': service.get('version', '') if service is not None else '',
                            'product': service.get('product', '') if service is not None else '',
                            'extrainfo': service.get('extrainfo', '') if service is not None else '',
                        }
                        scan_result.services[port_id] = service_info

            with open(xml_path, 'r') as f:
                scan_result.xml_output = f.read()

        except ET.ParseError as e:
            print_error(f"Failed to parse Nmap XML: {e}")

        return scan_result

    def rustscan_to_nmap(
        self,
        profile: str = "full",
        custom_nmap_args: Optional[List[str]] = None
    ) -> Tuple[ScanResult, List[CommandResult]]:
        """
        Run RustScan for port discovery, then pipe results to Nmap.

        Args:
            profile: Scan profile name from SCAN_PROFILES
            custom_nmap_args: Override Nmap arguments

        Returns:
            Tuple of (ScanResult, list of CommandResults)
        """
        print_section(f"RustScan → Nmap Pipeline ({profile})")

        results = []
        scan_profile = SCAN_PROFILES.get(profile, SCAN_PROFILES["full"])

        # Step 1: RustScan port discovery
        print_info(f"Profile: {scan_profile.name} - {scan_profile.description}")

        rustscan_args = scan_profile.rustscan_args.copy()

        # Extract port range if specified
        port_range = None
        for i, arg in enumerate(rustscan_args):
            if arg == "--range" and i + 1 < len(rustscan_args):
                port_range = rustscan_args[i + 1]
                break
            elif arg == "-p" and i + 1 < len(rustscan_args):
                port_range = rustscan_args[i + 1]
                break

        # Filter out arguments that are already handled by rustscan() method parameters
        # to avoid duplicates (--ulimit, -b/batch size, --timeout are set via method params)
        filtered_args = []
        skip_next = False
        for i, arg in enumerate(rustscan_args):
            if skip_next:
                skip_next = False
                continue
            # Skip arguments that are handled by method parameters
            if arg in ["--range", "-p", "--ulimit", "-b", "--timeout"]:
                skip_next = True  # Skip this arg and its value
                continue
            # Skip port range value
            if arg == port_range:
                continue
            filtered_args.append(arg)

        open_ports, rs_result = self.rustscan(
            ports=port_range,
            additional_args=filtered_args if filtered_args else None
        )
        results.append(rs_result)

        if not open_ports:
            print_warning("No open ports found. Skipping Nmap scan.")
            return ScanResult(self.target), results

        # Step 2: Nmap service enumeration
        ports_str = ",".join(map(str, open_ports))
        nmap_args = custom_nmap_args or scan_profile.nmap_args.copy()

        # Determine if sudo is needed
        needs_sudo = "-sS" in nmap_args or "-sU" in nmap_args or "-O" in nmap_args

        scan_result, nmap_result = self.nmap(
            ports=ports_str,
            scan_type=nmap_args[0] if nmap_args else "-sV",
            scripts=scan_profile.scripts if scan_profile.scripts else None,
            additional_args=nmap_args[1:] if len(nmap_args) > 1 else None,
            sudo=needs_sudo
        )
        results.append(nmap_result)

        # Print summary
        self._print_scan_summary(scan_result)

        return scan_result, results

    def quick_scan(self) -> Tuple[ScanResult, List[CommandResult]]:
        """Run a quick scan (fast port discovery + basic service detection)."""
        return self.rustscan_to_nmap(profile="quick")

    def full_scan(self, with_scripts: bool = False) -> Tuple[ScanResult, List[CommandResult]]:
        """Run a full scan (all ports + comprehensive service detection)."""
        profile = "full_scripts" if with_scripts else "full"
        return self.rustscan_to_nmap(profile=profile)

    def stealth_scan(self) -> Tuple[ScanResult, List[CommandResult]]:
        """Run a stealth scan (slow, evasive)."""
        return self.rustscan_to_nmap(profile="stealth")

    def smb_scan(self) -> Tuple[ScanResult, CommandResult]:
        """Run SMB-focused scan with enumeration scripts."""
        print_section("SMB Enumeration Scan")

        profile = SCAN_PROFILES["smb"]
        return self.nmap(
            ports="139,445",
            scripts=["smb-enum-shares", "smb-enum-users", "smb-os-discovery",
                    "smb-security-mode", "smb-protocols", "smb2-security-mode"],
            additional_args=["-sV", "-sC"]
        )

    def http_scan(self, ports: str = "80,443,8080,8443,8000,8888") -> Tuple[ScanResult, CommandResult]:
        """Run HTTP-focused scan with web scripts."""
        print_section("HTTP Enumeration Scan")

        return self.nmap(
            ports=ports,
            scripts=["http-enum", "http-headers", "http-methods", "http-title",
                    "http-robots.txt", "http-sitemap-generator", "http-vuln-*"],
            additional_args=["-sV"]
        )

    def vuln_scan(self, ports: Optional[str] = None) -> Tuple[ScanResult, CommandResult]:
        """Run vulnerability scan."""
        print_section("Vulnerability Scan")

        return self.nmap(
            ports=ports,
            scripts=["vuln"],
            additional_args=["-sV", "--open"]
        )

    def udp_scan(self, top_ports: int = 100) -> Tuple[ScanResult, CommandResult]:
        """Run UDP scan (requires sudo)."""
        print_section("UDP Scan")

        return self.nmap(
            scan_type="-sU",
            additional_args=["-sV", "--top-ports", str(top_ports), "--open"],
            sudo=True
        )

    def ad_scan(self, ports: Optional[str] = None) -> Tuple[ScanResult, CommandResult]:
        """
        Run Active Directory-focused Nmap scan with all AD enumeration scripts.

        This scan runs comprehensive AD-related NSE scripts including:
        - LDAP enumeration
        - Kerberos enumeration
        - SMB signing and security checks
        - Domain controller identification

        Args:
            ports: Specific ports to scan (defaults to common AD ports)

        Returns:
            Tuple of (ScanResult, CommandResult)
        """
        print_section("Active Directory Enumeration Scan")

        # Common AD ports if none specified
        if not ports:
            ports = "53,88,135,139,389,445,464,593,636,3268,3269,5985,5986"
            print_info(f"Scanning common AD ports: {ports}")

        # Comprehensive AD scripts
        ad_scripts = [
            # SMB/NetBIOS scripts
            "smb-enum-domains",
            "smb-enum-groups",
            "smb-enum-shares",
            "smb-enum-users",
            "smb-os-discovery",
            "smb-security-mode",
            "smb-protocols",
            "smb2-security-mode",
            "smb2-capabilities",
            "smb2-time",
            # LDAP scripts
            "ldap-rootdse",
            "ldap-search",
            # Kerberos scripts
            "krb5-enum-users",
            # RPC scripts
            "msrpc-enum",
            # DNS scripts
            "dns-nsid",
            "dns-srv-enum",
        ]

        print_info(f"Running {len(ad_scripts)} Active Directory NSE scripts...")

        return self.nmap(
            ports=ports,
            scripts=ad_scripts,
            additional_args=["-sV", "-sC", "--script-args", "ldap.maxObjects=1000"]
        )

    def web_scan(self, ports: Optional[str] = None, target_url: Optional[str] = None) -> Tuple[ScanResult, CommandResult]:
        """
        Run comprehensive web application-focused Nmap scan.

        This scan runs web application NSE scripts including:
        - Directory enumeration
        - Vulnerability detection
        - Header analysis
        - Common web vulnerabilities (SQLi, XSS indicators)

        Args:
            ports: Specific ports to scan (defaults to common web ports)
            target_url: Optional specific URL to test

        Returns:
            Tuple of (ScanResult, CommandResult)
        """
        print_section("Web Application Enumeration Scan")

        # Common web ports if none specified
        if not ports:
            ports = "80,443,8000,8008,8080,8443,8888,9000,9090"
            print_info(f"Scanning common web ports: {ports}")

        # Comprehensive web scripts
        web_scripts = [
            # Discovery
            "http-enum",
            "http-headers",
            "http-methods",
            "http-title",
            "http-robots.txt",
            "http-sitemap-generator",
            "http-server-header",
            "http-generator",
            # Security
            "http-security-headers",
            "http-csrf",
            "http-passwd",
            "http-shellshock",
            # Vulnerability detection
            "http-sql-injection",
            "http-stored-xss",
            "http-dombased-xss",
            "http-phpself-xss",
            # Common vulnerabilities
            "http-vuln-*",
            # Authentication
            "http-auth-finder",
            "http-auth",
            # Web technologies
            "http-waf-detect",
            "http-waf-fingerprint",
        ]

        print_info(f"Running {len(web_scripts)} web application NSE scripts...")

        script_args = []
        if target_url:
            script_args = ["--script-args", f"http.url={target_url}"]

        return self.nmap(
            ports=ports,
            scripts=web_scripts,
            additional_args=["-sV", "-sC"] + (script_args if script_args else [])
        )

    def custom_nmap(
        self,
        ports: str,
        scripts: List[str],
        additional_args: Optional[List[str]] = None
    ) -> Tuple[ScanResult, CommandResult]:
        """Run a custom Nmap scan."""
        print_section("Custom Nmap Scan")

        return self.nmap(
            ports=ports,
            scripts=scripts,
            additional_args=additional_args
        )

    def scan_and_test_anon(
        self,
        profile: str = "quick"
    ) -> Tuple[ScanResult, Dict]:
        """
        Run a scan and automatically test anonymous logins on discovered services.

        Args:
            profile: Scan profile to use

        Returns:
            Tuple of (ScanResult, anonymous test results)
        """
        print_section(f"Scan + Anonymous Login Testing")

        # Step 1: Run the scan
        scan_result, _ = self.rustscan_to_nmap(profile=profile)

        if not scan_result.services:
            print_warning("No services discovered. Skipping anonymous login tests.")
            return scan_result, {}

        # Step 2: Get service ports for testing
        service_ports = scan_result.get_service_ports()

        if not service_ports:
            print_warning("No testable services discovered.")
            return scan_result, {}

        print_info(f"Discovered services for anonymous testing:")
        for svc, ports in service_ports.items():
            print_info(f"  {svc}: {ports}")

        # Step 3: Run anonymous login tests
        from modules.anon_login import AnonymousLoginTester

        tester = AnonymousLoginTester(self.target, self.output_manager)
        anon_results = tester.test_all_services(ports=service_ports)

        return scan_result, anon_results

    def _print_scan_summary(self, scan_result: ScanResult):
        """Print a summary of scan results."""
        print_section("Scan Summary")

        print_info(f"Target: {scan_result.target}")
        print_info(f"Open Ports: {len(scan_result.ports)}")

        if scan_result.os_info:
            print_info(f"OS Detection: {scan_result.os_info}")

        if scan_result.services:
            print("\n  Port      Service           Version")
            print("  " + "-" * 50)
            for port, info in sorted(scan_result.services.items()):
                service = info.get('service', 'unknown')
                product = info.get('product', '')
                version = info.get('version', '')
                version_str = f"{product} {version}".strip() or "-"
                print(f"  {port:<9} {service:<17} {version_str}")


def run_scan_menu(target: str) -> Optional[ScanResult]:
    """Interactive menu for running scans."""
    from modules.utils import print_banner

    print_banner()
    print_section(f"Scanning: {target}")

    scanner = Scanner(target)

    options = [
        ("1", "Quick Scan", scanner.quick_scan),
        ("2", "Full Scan (all ports)", lambda: scanner.full_scan(with_scripts=False)),
        ("3", "Full Scan + Scripts", lambda: scanner.full_scan(with_scripts=True)),
        ("4", "Stealth Scan", scanner.stealth_scan),
        ("5", "SMB Enumeration", scanner.smb_scan),
        ("6", "HTTP Enumeration", scanner.http_scan),
        ("7", "Vulnerability Scan", scanner.vuln_scan),
        ("8", "UDP Scan (top 100)", scanner.udp_scan),
        ("9", "Active Directory Scan (All AD Scripts)", scanner.ad_scan),
        ("a", "Web Application Scan (All Web Scripts)", scanner.web_scan),
        ("b", "Quick Scan + Anonymous Login Tests", lambda: scanner.scan_and_test_anon("quick")),
        ("c", "Full Scan + Anonymous Login Tests", lambda: scanner.scan_and_test_anon("full")),
        ("0", "Back to Main Menu", None),
    ]

    print("\nSelect scan type:")
    for key, name, _ in options:
        print(f"  [{key}] {name}")

    choice = input(f"\n{Colors.CYAN}Enter choice: {Colors.RESET}").strip().lower()

    for key, name, func in options:
        if choice == key:
            if func is None:
                return None
            print_info(f"Starting {name}...")
            result = func()
            # Handle both single result and tuple returns
            if isinstance(result, tuple):
                return result[0]
            return result

    print_error("Invalid choice")
    return None


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python scanning.py <target>")
        sys.exit(1)

    target = sys.argv[1]
    run_scan_menu(target)
