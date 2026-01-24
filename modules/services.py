#!/usr/bin/env python3
"""
Service enumeration module for the Pentest Toolkit.
Handles SMB, LDAP, and other service-specific enumeration.
"""

import re
from pathlib import Path
from typing import Optional, List, Dict, Tuple
from dataclasses import dataclass, field

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from configs.config import check_tool_installed, RESULTS_DIR
from modules.utils import (
    OutputManager, CommandExecutor, CommandResult,
    print_section, print_success, print_error, print_warning, print_info,
    Colors
)


@dataclass
class SMBEnumResult:
    """Result of SMB enumeration."""
    target: str
    shares: List[Dict] = field(default_factory=list)
    users: List[str] = field(default_factory=list)
    groups: List[str] = field(default_factory=list)
    password_policy: Dict = field(default_factory=dict)
    os_info: str = ""
    domain: str = ""
    raw_output: str = ""


@dataclass
class ServiceEnumResult:
    """Generic service enumeration result."""
    target: str
    service: str
    data: Dict = field(default_factory=dict)
    raw_output: str = ""


class ServiceEnumerator:
    """Handles service-specific enumeration."""

    def __init__(self, target: str, output_manager: Optional[OutputManager] = None):
        self.target = target
        self.output_manager = output_manager or OutputManager(RESULTS_DIR, target)
        self.executor = CommandExecutor(self.output_manager)

        # Check tool availability
        self.has_enum4linux = check_tool_installed("enum4linux")
        self.has_enum4linux_ng = check_tool_installed("enum4linux-ng")
        self.has_smbclient = check_tool_installed("smbclient")
        self.has_crackmapexec = check_tool_installed("crackmapexec")
        self.has_netexec = check_tool_installed("netexec")
        self.has_rpcclient = check_tool_installed("rpcclient")

    def enum4linux(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
        full_enum: bool = True,
        additional_args: Optional[List[str]] = None
    ) -> Tuple[SMBEnumResult, CommandResult]:
        """
        Run enum4linux for SMB/Windows enumeration.

        Args:
            username: Username for authenticated enumeration
            password: Password for authenticated enumeration
            full_enum: Run full enumeration (-a flag)
            additional_args: Additional enum4linux arguments
        """
        # Prefer enum4linux-ng if available
        if self.has_enum4linux_ng:
            return self._enum4linux_ng(username, password, full_enum, additional_args)

        if not self.has_enum4linux:
            print_error("enum4linux is not installed.")
            return SMBEnumResult(self.target), CommandResult("", -1, "", "enum4linux not installed", 0, False)

        print_section("enum4linux SMB Enumeration")

        output_file = self.output_manager.get_output_path('services', f"enum4linux_{self.target.replace('.', '_')}.txt")

        cmd_parts = ["enum4linux"]

        if full_enum:
            cmd_parts.append("-a")

        if username:
            cmd_parts.extend(["-u", username])
        if password:
            cmd_parts.extend(["-p", password])

        if additional_args:
            cmd_parts.extend(additional_args)

        cmd_parts.append(self.target)

        command = " ".join(cmd_parts)
        result = self.executor.run(command, timeout=600, live_output=True)

        # Save output
        self.output_manager.save_output(
            'services',
            f"enum4linux_{self.target.replace('.', '_')}.txt",
            result.stdout
        )

        smb_result = SMBEnumResult(target=self.target, raw_output=result.stdout)
        smb_result = self._parse_enum4linux_output(result.stdout, smb_result)

        self._print_smb_summary(smb_result)
        return smb_result, result

    def _enum4linux_ng(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
        full_enum: bool = True,
        additional_args: Optional[List[str]] = None
    ) -> Tuple[SMBEnumResult, CommandResult]:
        """Run enum4linux-ng (modern version)."""
        print_section("enum4linux-ng SMB Enumeration")

        output_file = self.output_manager.get_output_path('services', f"enum4linux_ng_{self.target.replace('.', '_')}")

        cmd_parts = ["enum4linux-ng", "-A"]

        if username:
            cmd_parts.extend(["-u", username])
        if password:
            cmd_parts.extend(["-p", password])

        cmd_parts.extend(["-oA", str(output_file)])

        if additional_args:
            cmd_parts.extend(additional_args)

        cmd_parts.append(self.target)

        command = " ".join(cmd_parts)
        result = self.executor.run(command, timeout=600, live_output=True)

        smb_result = SMBEnumResult(target=self.target, raw_output=result.stdout)
        smb_result = self._parse_enum4linux_output(result.stdout, smb_result)

        self._print_smb_summary(smb_result)
        return smb_result, result

    def _parse_enum4linux_output(self, output: str, result: SMBEnumResult) -> SMBEnumResult:
        """Parse enum4linux output."""
        # Parse OS info
        os_match = re.search(r'OS:\s*(.+)', output)
        if os_match:
            result.os_info = os_match.group(1).strip()

        # Parse domain
        domain_match = re.search(r'Domain:\s*(.+)', output)
        if domain_match:
            result.domain = domain_match.group(1).strip()

        # Parse shares
        share_pattern = r'//[\d\.]+/(\S+)\s+Mapping:\s*(\S+)\s+Listing:\s*(\S+)'
        for match in re.finditer(share_pattern, output):
            result.shares.append({
                'name': match.group(1),
                'mapping': match.group(2),
                'listing': match.group(3)
            })

        # Parse users (RID cycling)
        user_pattern = r'user:\[([^\]]+)\]\s+rid:\[([^\]]+)\]'
        for match in re.finditer(user_pattern, output):
            result.users.append(match.group(1))

        # Parse groups
        group_pattern = r'group:\[([^\]]+)\]\s+rid:\[([^\]]+)\]'
        for match in re.finditer(group_pattern, output):
            result.groups.append(match.group(1))

        return result

    def smbclient_list(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
        no_pass: bool = True
    ) -> Tuple[SMBEnumResult, CommandResult]:
        """List SMB shares using smbclient."""
        if not self.has_smbclient:
            print_error("smbclient is not installed.")
            return SMBEnumResult(self.target), CommandResult("", -1, "", "smbclient not installed", 0, False)

        print_section("smbclient Share Listing")

        cmd_parts = ["smbclient", "-L", f"//{self.target}"]

        if username:
            cmd_parts.extend(["-U", username if not password else f"{username}%{password}"])
        elif no_pass:
            cmd_parts.append("-N")

        command = " ".join(cmd_parts)
        result = self.executor.run(command, timeout=60, live_output=True)

        smb_result = SMBEnumResult(target=self.target, raw_output=result.stdout)

        # Parse shares
        share_pattern = r'^\s+(\S+)\s+(Disk|IPC|Printer)\s*(.*)$'
        for line in result.stdout.split('\n'):
            match = re.match(share_pattern, line)
            if match:
                smb_result.shares.append({
                    'name': match.group(1),
                    'type': match.group(2),
                    'comment': match.group(3).strip()
                })

        return smb_result, result

    def smbclient_connect(
        self,
        share: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        commands: Optional[List[str]] = None
    ) -> CommandResult:
        """Connect to an SMB share and run commands."""
        if not self.has_smbclient:
            print_error("smbclient is not installed.")
            return CommandResult("", -1, "", "smbclient not installed", 0, False)

        print_section(f"smbclient: //{self.target}/{share}")

        cmd_parts = ["smbclient", f"//{self.target}/{share}"]

        if username:
            cmd_parts.extend(["-U", username if not password else f"{username}%{password}"])
        else:
            cmd_parts.append("-N")

        if commands:
            cmd_str = "; ".join(commands)
            cmd_parts.extend(["-c", f'"{cmd_str}"'])

        command = " ".join(cmd_parts)
        return self.executor.run(command, timeout=120, live_output=True)

    def netexec_generate_hosts(
        self,
        hosts_file: str = "/etc/hosts",
        backup: bool = True
    ) -> CommandResult:
        """
        Generate /etc/hosts file from SMB enumeration using NetExec.
        Equivalent to: sudo nxc smb $RHOST --generate-hosts-file /etc/hosts

        Args:
            hosts_file: Path to hosts file (default: /etc/hosts)
            backup: Create backup of existing hosts file before modification

        Returns:
            CommandResult from the NetExec command
        """
        tool = "nxc" if self.has_netexec else None

        if not self.has_netexec:
            print_error("NetExec (nxc) is not installed. This feature requires NetExec.")
            print_info("Install with: pipx install git+https://github.com/Pennyw0rth/NetExec")
            return CommandResult("", -1, "", "NetExec not installed", 0, False)

        print_section("NetExec Hosts File Generation")
        print_warning(f"This will modify {hosts_file} - ensure you have proper authorization!")

        # Backup existing hosts file if requested
        if backup and hosts_file == "/etc/hosts":
            import datetime
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_cmd = f"sudo cp {hosts_file} {hosts_file}.backup.{timestamp}"
            print_info(f"Creating backup: {hosts_file}.backup.{timestamp}")
            self.executor.run(backup_cmd, timeout=10, sudo=True)

        # Run NetExec with --generate-hosts-file
        cmd_parts = ["nxc", "smb", self.target, "--generate-hosts-file", hosts_file]
        command = " ".join(cmd_parts)

        print_info(f"Running: sudo {command}")
        result = self.executor.run(command, timeout=120, live_output=True, sudo=True)

        # Save output
        self.output_manager.save_output(
            'services',
            f"netexec_hosts_{self.target.replace('.', '_')}.txt",
            result.stdout
        )

        if result.success:
            print_success(f"Successfully generated hosts file entries for {self.target}")
            print_info(f"Check {hosts_file} for the new entries")
        else:
            print_error(f"Failed to generate hosts file. Check permissions and ensure NetExec is installed.")

        return result

    def crackmapexec_smb(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
        hash_val: Optional[str] = None,
        enum_shares: bool = True,
        enum_users: bool = False,
        enum_sessions: bool = False,
        spider: bool = False,
        additional_args: Optional[List[str]] = None
    ) -> Tuple[SMBEnumResult, CommandResult]:
        """
        Run CrackMapExec/NetExec for SMB enumeration.

        Args:
            username: Username for authentication
            password: Password for authentication
            hash_val: NTLM hash for pass-the-hash
            enum_shares: Enumerate shares
            enum_users: Enumerate users (requires auth)
            enum_sessions: Enumerate sessions (requires auth)
            spider: Spider shares for sensitive files
            additional_args: Additional arguments
        """
        # Prefer netexec if available (cme successor)
        tool = "netexec" if self.has_netexec else "crackmapexec"

        if not self.has_netexec and not self.has_crackmapexec:
            print_error("Neither NetExec nor CrackMapExec is installed.")
            return SMBEnumResult(self.target), CommandResult("", -1, "", "Tool not installed", 0, False)

        print_section(f"{tool.upper()} SMB Enumeration")

        cmd_parts = [tool, "smb", self.target]

        if username:
            cmd_parts.extend(["-u", username])
            if password:
                cmd_parts.extend(["-p", password])
            elif hash_val:
                cmd_parts.extend(["-H", hash_val])
        else:
            cmd_parts.extend(["-u", "''", "-p", "''"])

        if enum_shares:
            cmd_parts.append("--shares")

        if enum_users:
            cmd_parts.append("--users")

        if enum_sessions:
            cmd_parts.append("--sessions")

        if spider:
            cmd_parts.append("--spider")

        if additional_args:
            cmd_parts.extend(additional_args)

        command = " ".join(cmd_parts)
        result = self.executor.run(command, timeout=300, live_output=True)

        # Save output
        self.output_manager.save_output(
            'services',
            f"{tool}_smb_{self.target.replace('.', '_')}.txt",
            result.stdout
        )

        smb_result = SMBEnumResult(target=self.target, raw_output=result.stdout)
        return smb_result, result

    def rpcclient_enum(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
        commands: Optional[List[str]] = None
    ) -> Tuple[ServiceEnumResult, CommandResult]:
        """
        Run rpcclient for RPC enumeration.

        Args:
            username: Username for authentication
            password: Password for authentication
            commands: RPC commands to execute
        """
        if not self.has_rpcclient:
            print_error("rpcclient is not installed.")
            return ServiceEnumResult(self.target, "rpc"), CommandResult("", -1, "", "rpcclient not installed", 0, False)

        print_section("rpcclient RPC Enumeration")

        # Default enumeration commands
        if commands is None:
            commands = [
                "srvinfo",
                "enumdomusers",
                "enumdomgroups",
                "getdompwinfo",
                "querydispinfo",
            ]

        results = []
        all_output = []

        for cmd in commands:
            cmd_parts = ["rpcclient", "-U", "''", "-N", self.target, "-c", f'"{cmd}"']

            if username:
                cmd_parts = ["rpcclient", "-U", f"{username}%{password or ''}", self.target, "-c", f'"{cmd}"']

            command = " ".join(cmd_parts)
            result = self.executor.run(command, timeout=30, live_output=True)
            results.append(result)
            all_output.append(f"=== {cmd} ===\n{result.stdout}\n")

        combined_output = "\n".join(all_output)
        self.output_manager.save_output(
            'services',
            f"rpcclient_{self.target.replace('.', '_')}.txt",
            combined_output
        )

        service_result = ServiceEnumResult(
            target=self.target,
            service="rpc",
            raw_output=combined_output
        )

        return service_result, results[-1] if results else CommandResult("", 0, "", "", 0, True)

    def smb_full_enum(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None
    ) -> Dict[str, any]:
        """Run comprehensive SMB enumeration."""
        print_section(f"Full SMB Enumeration: {self.target}")

        results = {}

        # enum4linux / enum4linux-ng
        if self.has_enum4linux or self.has_enum4linux_ng:
            print_info("Running enum4linux...")
            results['enum4linux'], _ = self.enum4linux(username, password)

        # smbclient share listing
        if self.has_smbclient:
            print_info("Listing shares with smbclient...")
            results['smbclient'], _ = self.smbclient_list(username, password)

        # CrackMapExec/NetExec
        if self.has_crackmapexec or self.has_netexec:
            print_info("Running CrackMapExec/NetExec...")
            results['cme'], _ = self.crackmapexec_smb(username, password, enum_shares=True)

        # rpcclient
        if self.has_rpcclient:
            print_info("Running rpcclient enumeration...")
            results['rpcclient'], _ = self.rpcclient_enum(username, password)

        return results

    def _print_smb_summary(self, result: SMBEnumResult):
        """Print SMB enumeration summary."""
        print_section("SMB Enumeration Summary")

        print_info(f"Target: {result.target}")

        if result.os_info:
            print_info(f"OS: {result.os_info}")

        if result.domain:
            print_info(f"Domain: {result.domain}")

        if result.shares:
            print(f"\n{Colors.BOLD}Shares ({len(result.shares)}):{Colors.RESET}")
            for share in result.shares:
                print(f"  - {share.get('name', '?')} ({share.get('type', share.get('mapping', '?'))})")

        if result.users:
            print(f"\n{Colors.BOLD}Users ({len(result.users)}):{Colors.RESET}")
            for user in result.users[:20]:
                print(f"  - {user}")
            if len(result.users) > 20:
                print(f"  ... and {len(result.users) - 20} more")

        if result.groups:
            print(f"\n{Colors.BOLD}Groups ({len(result.groups)}):{Colors.RESET}")
            for group in result.groups[:10]:
                print(f"  - {group}")
            if len(result.groups) > 10:
                print(f"  ... and {len(result.groups) - 10} more")


def run_services_menu(target: str) -> Optional[Dict]:
    """Interactive menu for service enumeration."""
    from modules.utils import print_banner

    print_banner()

    enumerator = ServiceEnumerator(target)

    print_section(f"Service Enumeration: {target}")

    # Ask for credentials
    print("\nCredentials (leave blank for anonymous):")
    username = input(f"  Username: ").strip() or None
    password = None
    if username:
        password = input(f"  Password: ").strip() or None

    options = [
        ("1", "enum4linux Full Enum", lambda: enumerator.enum4linux(username, password)),
        ("2", "smbclient List Shares", lambda: enumerator.smbclient_list(username, password)),
        ("3", "CrackMapExec/NetExec Shares", lambda: enumerator.crackmapexec_smb(username, password)),
        ("4", "rpcclient Enumeration", lambda: enumerator.rpcclient_enum(username, password)),
        ("5", "NetExec Generate Hosts File", lambda: enumerator.netexec_generate_hosts()),
        ("6", "Full SMB Enumeration", lambda: enumerator.smb_full_enum(username, password)),
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
        print("Usage: python services.py <target>")
        sys.exit(1)

    target = sys.argv[1]
    run_services_menu(target)
