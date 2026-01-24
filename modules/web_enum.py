#!/usr/bin/env python3
"""
Web enumeration module for the Pentest Toolkit.
Handles directory brute-forcing, fuzzing, and web vulnerability scanning.
"""

import re
from pathlib import Path
from typing import Optional, List, Dict, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from configs.config import (
    check_tool_installed, find_wordlist, RESULTS_DIR, DEFAULT_WORDLISTS
)
from modules.utils import (
    OutputManager, CommandExecutor, CommandResult,
    print_section, print_success, print_error, print_warning, print_info,
    Colors
)


@dataclass
class WebEnumResult:
    """Result of web enumeration."""
    target: str
    discovered_paths: List[Dict] = field(default_factory=list)
    vulnerabilities: List[Dict] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    raw_output: str = ""


class WebEnumerator:
    """Handles web enumeration with various tools."""

    def __init__(self, target: str, output_manager: Optional[OutputManager] = None):
        # Normalize target URL
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        self.target = target
        self.target_host = urlparse(target).netloc

        self.output_manager = output_manager or OutputManager(RESULTS_DIR, self.target_host)
        self.executor = CommandExecutor(self.output_manager)

        # Check tool availability
        self.has_gobuster = check_tool_installed("gobuster")
        self.has_ffuf = check_tool_installed("ffuf")
        self.has_nikto = check_tool_installed("nikto")
        self.has_nuclei = check_tool_installed("nuclei")

    def gobuster_dir(
        self,
        wordlist: str = "dirb_common",
        extensions: Optional[str] = None,
        threads: int = 50,
        status_codes: str = "200,204,301,302,307,308,401,403,405",
        timeout: int = 10,
        follow_redirect: bool = False,
        additional_args: Optional[List[str]] = None
    ) -> Tuple[WebEnumResult, CommandResult]:
        """
        Run Gobuster directory brute-force.

        Args:
            wordlist: Wordlist name or path
            extensions: File extensions to search (e.g., "php,html,txt")
            threads: Number of concurrent threads
            status_codes: Status codes to consider as valid
            timeout: Request timeout in seconds
            follow_redirect: Follow redirects
            additional_args: Additional Gobuster arguments
        """
        if not self.has_gobuster:
            print_error("Gobuster is not installed.")
            return WebEnumResult(self.target), CommandResult("", -1, "", "Gobuster not installed", 0, False)

        print_section("Gobuster Directory Brute-Force")

        # Find wordlist
        wl_path = find_wordlist(wordlist)
        if not wl_path:
            print_error(f"Wordlist not found: {wordlist}")
            print_info("Available wordlists: " + ", ".join(DEFAULT_WORDLISTS.keys()))
            return WebEnumResult(self.target), CommandResult("", -1, "", "Wordlist not found", 0, False)

        print_info(f"Using wordlist: {wl_path}")

        # Build command
        output_file = self.output_manager.get_output_path('web', f"gobuster_dir_{self.target_host}.txt")

        cmd_parts = [
            "gobuster", "dir",
            "-u", self.target,
            "-w", str(wl_path),
            "-t", str(threads),
            "-s", status_codes,
            "--timeout", f"{timeout}s",
            "-o", str(output_file),
            "--no-error"
        ]

        if extensions:
            cmd_parts.extend(["-x", extensions])

        if follow_redirect:
            cmd_parts.append("-r")

        if additional_args:
            cmd_parts.extend(additional_args)

        command = " ".join(cmd_parts)
        result = self.executor.run(command, timeout=3600, live_output=True)

        # Parse results
        web_result = WebEnumResult(target=self.target, raw_output=result.stdout)
        web_result.discovered_paths = self._parse_gobuster_output(result.stdout)

        print_success(f"Found {len(web_result.discovered_paths)} paths")
        return web_result, result

    def gobuster_vhost(
        self,
        wordlist: str = "seclists_common",
        threads: int = 50,
        additional_args: Optional[List[str]] = None
    ) -> Tuple[WebEnumResult, CommandResult]:
        """Run Gobuster virtual host discovery."""
        if not self.has_gobuster:
            print_error("Gobuster is not installed.")
            return WebEnumResult(self.target), CommandResult("", -1, "", "Gobuster not installed", 0, False)

        print_section("Gobuster Virtual Host Discovery")

        wl_path = find_wordlist(wordlist)
        if not wl_path:
            # Try subdomains wordlist
            wl_path = find_wordlist("subdomains")
            if not wl_path:
                print_error(f"Wordlist not found: {wordlist}")
                return WebEnumResult(self.target), CommandResult("", -1, "", "Wordlist not found", 0, False)

        output_file = self.output_manager.get_output_path('web', f"gobuster_vhost_{self.target_host}.txt")

        cmd_parts = [
            "gobuster", "vhost",
            "-u", self.target,
            "-w", str(wl_path),
            "-t", str(threads),
            "-o", str(output_file),
            "--no-error"
        ]

        if additional_args:
            cmd_parts.extend(additional_args)

        command = " ".join(cmd_parts)
        result = self.executor.run(command, timeout=3600, live_output=True)

        web_result = WebEnumResult(target=self.target, raw_output=result.stdout)
        return web_result, result

    def _parse_gobuster_output(self, output: str) -> List[Dict]:
        """Parse Gobuster output."""
        paths = []
        # Pattern: /path (Status: 200) [Size: 1234]
        pattern = r'(/\S*)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]'

        for match in re.finditer(pattern, output):
            paths.append({
                'path': match.group(1),
                'status': int(match.group(2)),
                'size': int(match.group(3))
            })

        return paths

    def ffuf(
        self,
        wordlist: str = "dirb_common",
        fuzz_type: str = "dir",
        extensions: Optional[str] = None,
        threads: int = 50,
        match_codes: str = "200,204,301,302,307,401,403,405",
        filter_size: Optional[str] = None,
        filter_words: Optional[str] = None,
        filter_lines: Optional[str] = None,
        recursion: bool = False,
        recursion_depth: int = 2,
        additional_args: Optional[List[str]] = None
    ) -> Tuple[WebEnumResult, CommandResult]:
        """
        Run ffuf for fuzzing.

        Args:
            wordlist: Wordlist name or path
            fuzz_type: Type of fuzzing (dir, param, vhost)
            extensions: File extensions
            threads: Number of threads
            match_codes: Status codes to match
            filter_size: Filter by response size
            filter_words: Filter by word count
            filter_lines: Filter by line count
            recursion: Enable recursion
            recursion_depth: Recursion depth
            additional_args: Additional ffuf arguments
        """
        if not self.has_ffuf:
            print_error("ffuf is not installed.")
            return WebEnumResult(self.target), CommandResult("", -1, "", "ffuf not installed", 0, False)

        print_section(f"ffuf Fuzzing ({fuzz_type})")

        wl_path = find_wordlist(wordlist)
        if not wl_path:
            print_error(f"Wordlist not found: {wordlist}")
            return WebEnumResult(self.target), CommandResult("", -1, "", "Wordlist not found", 0, False)

        print_info(f"Using wordlist: {wl_path}")

        # Build URL with FUZZ keyword
        if fuzz_type == "dir":
            fuzz_url = f"{self.target.rstrip('/')}/FUZZ"
        elif fuzz_type == "param":
            fuzz_url = f"{self.target}?FUZZ=test"
        elif fuzz_type == "vhost":
            fuzz_url = self.target
        else:
            fuzz_url = f"{self.target.rstrip('/')}/FUZZ"

        output_file = self.output_manager.get_output_path('web', f"ffuf_{fuzz_type}_{self.target_host}.txt")
        json_file = self.output_manager.get_output_path('web', f"ffuf_{fuzz_type}_{self.target_host}.json")

        cmd_parts = [
            "ffuf",
            "-u", fuzz_url,
            "-w", str(wl_path),
            "-t", str(threads),
            "-mc", match_codes,
            "-o", str(json_file),
            "-of", "json"
        ]

        if extensions:
            cmd_parts.extend(["-e", extensions])

        if filter_size:
            cmd_parts.extend(["-fs", filter_size])

        if filter_words:
            cmd_parts.extend(["-fw", filter_words])

        if filter_lines:
            cmd_parts.extend(["-fl", filter_lines])

        if recursion:
            cmd_parts.append("-recursion")
            cmd_parts.extend(["-recursion-depth", str(recursion_depth)])

        if fuzz_type == "vhost":
            cmd_parts.extend(["-H", f"Host: FUZZ.{self.target_host}"])

        if additional_args:
            cmd_parts.extend(additional_args)

        command = " ".join(cmd_parts)
        result = self.executor.run(command, timeout=3600, live_output=True)

        # Save text output
        self.output_manager.save_output('web', f"ffuf_{fuzz_type}_{self.target_host}.txt", result.stdout)

        web_result = WebEnumResult(target=self.target, raw_output=result.stdout)
        web_result.discovered_paths = self._parse_ffuf_output(result.stdout)

        print_success(f"Found {len(web_result.discovered_paths)} results")
        return web_result, result

    def _parse_ffuf_output(self, output: str) -> List[Dict]:
        """Parse ffuf output."""
        paths = []
        # Pattern varies, try common formats
        pattern = r'(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)'

        for match in re.finditer(pattern, output):
            paths.append({
                'path': match.group(1),
                'status': int(match.group(2)),
                'size': int(match.group(3))
            })

        return paths

    def nikto(
        self,
        tuning: Optional[str] = None,
        plugins: Optional[str] = None,
        ssl: bool = False,
        additional_args: Optional[List[str]] = None
    ) -> Tuple[WebEnumResult, CommandResult]:
        """
        Run Nikto web vulnerability scanner.

        Args:
            tuning: Scan tuning options (1-9, a-c, x)
                1 - Interesting File / Seen in logs
                2 - Misconfiguration / Default File
                3 - Information Disclosure
                4 - Injection (XSS/Script/HTML)
                5 - Remote File Retrieval - Inside Web Root
                6 - Denial of Service
                7 - Remote File Retrieval - Server Wide
                8 - Command Execution / Remote Shell
                9 - SQL Injection
                a - Authentication Bypass
                b - Software Identification
                c - Remote Source Inclusion
                x - Reverse Tuning Options (exclude instead of include)
            plugins: Specific plugins to run
            ssl: Force SSL
            additional_args: Additional Nikto arguments
        """
        if not self.has_nikto:
            print_error("Nikto is not installed.")
            return WebEnumResult(self.target), CommandResult("", -1, "", "Nikto not installed", 0, False)

        print_section("Nikto Vulnerability Scan")

        output_file = self.output_manager.get_output_path('web', f"nikto_{self.target_host}.txt")
        html_file = self.output_manager.get_output_path('web', f"nikto_{self.target_host}.html")

        cmd_parts = [
            "nikto",
            "-h", self.target,
            "-o", str(output_file),
            "-Format", "txt"
        ]

        if tuning:
            cmd_parts.extend(["-Tuning", tuning])

        if plugins:
            cmd_parts.extend(["-Plugins", plugins])

        if ssl or self.target.startswith('https'):
            cmd_parts.append("-ssl")

        if additional_args:
            cmd_parts.extend(additional_args)

        command = " ".join(cmd_parts)
        result = self.executor.run(command, timeout=7200, live_output=True)  # Nikto can be slow

        web_result = WebEnumResult(target=self.target, raw_output=result.stdout)
        web_result.vulnerabilities = self._parse_nikto_output(result.stdout)

        print_success(f"Found {len(web_result.vulnerabilities)} potential issues")
        return web_result, result

    def _parse_nikto_output(self, output: str) -> List[Dict]:
        """Parse Nikto output for vulnerabilities."""
        vulns = []
        # Pattern: + OSVDB-XXXXX: Description
        pattern = r'\+\s+(OSVDB-\d+|CVE-[\d-]+)?:?\s*(.+)'

        for line in output.split('\n'):
            if line.startswith('+') and not line.startswith('+ Target'):
                match = re.match(pattern, line)
                if match:
                    vulns.append({
                        'id': match.group(1) or 'INFO',
                        'description': match.group(2).strip()
                    })

        return vulns

    def nuclei(
        self,
        templates: Optional[List[str]] = None,
        severity: Optional[str] = None,
        tags: Optional[List[str]] = None,
        rate_limit: int = 150,
        bulk_size: int = 25,
        additional_args: Optional[List[str]] = None
    ) -> Tuple[WebEnumResult, CommandResult]:
        """
        Run Nuclei vulnerability scanner.

        Args:
            templates: Specific templates to use
            severity: Filter by severity (info,low,medium,high,critical)
            tags: Filter by tags
            rate_limit: Rate limit for requests per second
            bulk_size: Number of targets to process in parallel
            additional_args: Additional Nuclei arguments
        """
        if not self.has_nuclei:
            print_error("Nuclei is not installed.")
            return WebEnumResult(self.target), CommandResult("", -1, "", "Nuclei not installed", 0, False)

        print_section("Nuclei Vulnerability Scan")

        output_file = self.output_manager.get_output_path('web', f"nuclei_{self.target_host}.txt")
        json_file = self.output_manager.get_output_path('web', f"nuclei_{self.target_host}.json")

        cmd_parts = [
            "nuclei",
            "-u", self.target,
            "-o", str(output_file),
            "-json-export", str(json_file),
            "-rate-limit", str(rate_limit),
            "-bulk-size", str(bulk_size),
            "-silent"
        ]

        if templates:
            for t in templates:
                cmd_parts.extend(["-t", t])

        if severity:
            cmd_parts.extend(["-s", severity])

        if tags:
            cmd_parts.extend(["-tags", ",".join(tags)])

        if additional_args:
            cmd_parts.extend(additional_args)

        command = " ".join(cmd_parts)
        result = self.executor.run(command, timeout=7200, live_output=True)

        web_result = WebEnumResult(target=self.target, raw_output=result.stdout)
        web_result.vulnerabilities = self._parse_nuclei_output(result.stdout)

        print_success(f"Found {len(web_result.vulnerabilities)} issues")
        return web_result, result

    def _parse_nuclei_output(self, output: str) -> List[Dict]:
        """Parse Nuclei output."""
        vulns = []
        # Pattern: [severity] [template-id] [protocol] URL
        pattern = r'\[(\w+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.+)'

        for line in output.split('\n'):
            match = re.match(pattern, line)
            if match:
                vulns.append({
                    'severity': match.group(1),
                    'template': match.group(2),
                    'protocol': match.group(3),
                    'url': match.group(4)
                })

        return vulns

    def full_enum(
        self,
        wordlist: str = "dirb_common",
        extensions: str = "php,html,txt,js,css,bak,old"
    ) -> Dict[str, WebEnumResult]:
        """Run full web enumeration suite."""
        print_section(f"Full Web Enumeration: {self.target}")

        results = {}

        # Directory brute-force
        if self.has_gobuster:
            print_info("Running Gobuster directory scan...")
            results['gobuster'], _ = self.gobuster_dir(
                wordlist=wordlist,
                extensions=extensions
            )

        # Vulnerability scanning
        if self.has_nikto:
            print_info("Running Nikto scan...")
            results['nikto'], _ = self.nikto()

        if self.has_nuclei:
            print_info("Running Nuclei scan...")
            results['nuclei'], _ = self.nuclei(severity="medium,high,critical")

        self._print_enum_summary(results)
        return results

    def _print_enum_summary(self, results: Dict[str, WebEnumResult]):
        """Print web enumeration summary."""
        print_section("Web Enumeration Summary")

        for tool, result in results.items():
            print(f"\n{Colors.BOLD}{tool.upper()}{Colors.RESET}")
            print("-" * 40)

            if result.discovered_paths:
                print(f"  Discovered Paths: {len(result.discovered_paths)}")
                for path in result.discovered_paths[:10]:
                    print(f"    [{path.get('status', '?')}] {path.get('path', '?')}")
                if len(result.discovered_paths) > 10:
                    print(f"    ... and {len(result.discovered_paths) - 10} more")

            if result.vulnerabilities:
                print(f"  Vulnerabilities: {len(result.vulnerabilities)}")
                for vuln in result.vulnerabilities[:5]:
                    if 'severity' in vuln:
                        print(f"    [{vuln['severity']}] {vuln.get('template', vuln.get('description', ''))}")
                    else:
                        print(f"    [{vuln.get('id', 'INFO')}] {vuln.get('description', '')[:60]}")
                if len(result.vulnerabilities) > 5:
                    print(f"    ... and {len(result.vulnerabilities) - 5} more")


def run_web_menu(target: str) -> Optional[Dict[str, WebEnumResult]]:
    """Interactive menu for web enumeration."""
    from modules.utils import print_banner

    print_banner()

    enumerator = WebEnumerator(target)

    print_section(f"Web Enumeration: {target}")

    options = [
        ("1", "Gobuster Directory Scan", lambda: enumerator.gobuster_dir()),
        ("2", "Gobuster with Extensions", lambda: enumerator.gobuster_dir(extensions="php,html,txt,js,bak")),
        ("3", "Gobuster VHost Discovery", lambda: enumerator.gobuster_vhost()),
        ("4", "ffuf Directory Fuzzing", lambda: enumerator.ffuf()),
        ("5", "ffuf with Filters", lambda: enumerator.ffuf(filter_size="0")),
        ("6", "Nikto Scan", lambda: enumerator.nikto()),
        ("7", "Nuclei Scan (all)", lambda: enumerator.nuclei()),
        ("8", "Nuclei Scan (high/critical)", lambda: enumerator.nuclei(severity="high,critical")),
        ("9", "Full Web Enumeration", lambda: enumerator.full_enum()),
        ("0", "Back to Main Menu", None),
    ]

    print("\nSelect enumeration type:")
    for key, name, _ in options:
        print(f"  [{key}] {name}")

    choice = input(f"\n{Colors.CYAN}Enter choice: {Colors.RESET}").strip()

    for key, name, func in options:
        if choice == key:
            if func is None:
                return None
            print_info(f"Starting {name}...")
            result = func()
            if isinstance(result, tuple):
                return {name: result[0]}
            return result

    print_error("Invalid choice")
    return None


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python web_enum.py <target_url>")
        sys.exit(1)

    target = sys.argv[1]
    run_web_menu(target)
