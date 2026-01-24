#!/usr/bin/env python3
"""
Anonymous Login Testing Module for the Pentest Toolkit.
Tests anonymous/guest/null authentication across various services.
"""

import re
import socket
import ftplib
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
class AnonLoginResult:
    """Result of anonymous login testing."""
    target: str
    service: str
    port: int
    success: bool
    method: str = ""
    details: str = ""
    data: Dict = field(default_factory=dict)


@dataclass
class AnonTestSummary:
    """Summary of all anonymous login tests."""
    target: str
    results: List[AnonLoginResult] = field(default_factory=list)
    vulnerable_services: List[str] = field(default_factory=list)

    def add_result(self, result: AnonLoginResult):
        self.results.append(result)
        if result.success:
            self.vulnerable_services.append(f"{result.service}:{result.port}")


class AnonymousLoginTester:
    """Tests anonymous/null/guest authentication across services."""

    def __init__(self, target: str, output_manager: Optional[OutputManager] = None):
        self.target = target
        self.output_manager = output_manager or OutputManager(RESULTS_DIR, target)
        self.executor = CommandExecutor(self.output_manager)

        # Check tool availability
        self.has_smbclient = check_tool_installed("smbclient")
        self.has_rpcclient = check_tool_installed("rpcclient")
        self.has_crackmapexec = check_tool_installed("crackmapexec")
        self.has_netexec = check_tool_installed("netexec")
        self.has_ldapsearch = check_tool_installed("ldapsearch")
        self.has_mysql = check_tool_installed("mysql")
        self.has_psql = check_tool_installed("psql")
        self.has_mongo = check_tool_installed("mongo") or check_tool_installed("mongosh")
        self.has_redis_cli = check_tool_installed("redis-cli")
        self.has_snmpwalk = check_tool_installed("snmpwalk")
        self.has_rsync = check_tool_installed("rsync")
        self.has_nfs = check_tool_installed("showmount")
        self.has_telnet = check_tool_installed("telnet")
        self.has_hydra = check_tool_installed("hydra")

    def test_ftp_anonymous(self, port: int = 21, timeout: int = 10) -> AnonLoginResult:
        """
        Test FTP anonymous login.

        Tries: anonymous/anonymous, anonymous/<blank>, ftp/ftp
        """
        print_info(f"Testing FTP anonymous login on port {port}...")

        result = AnonLoginResult(
            target=self.target,
            service="FTP",
            port=port,
            success=False,
            method="anonymous"
        )

        credentials = [
            ("anonymous", "anonymous"),
            ("anonymous", ""),
            ("anonymous", "anonymous@"),
            ("ftp", "ftp"),
            ("ftp", ""),
        ]

        for username, password in credentials:
            try:
                ftp = ftplib.FTP(timeout=timeout)
                ftp.connect(self.target, port)
                ftp.login(username, password)

                # Try to list directory
                try:
                    files = ftp.nlst()
                    result.data['files'] = files[:20]  # First 20 files
                    result.data['file_count'] = len(files)
                except:
                    pass

                # Get welcome banner
                result.data['banner'] = ftp.getwelcome()

                ftp.quit()

                result.success = True
                result.method = f"{username}:{password if password else '<blank>'}"
                result.details = f"Anonymous login successful with {result.method}"

                print_success(f"FTP anonymous login SUCCESS: {result.method}")
                if result.data.get('files'):
                    print_info(f"  Found {result.data.get('file_count', 0)} files")

                break

            except ftplib.error_perm as e:
                continue
            except Exception as e:
                result.details = str(e)
                break

        if not result.success:
            print_warning(f"FTP anonymous login FAILED on port {port}")

        self._save_result(result)
        return result

    def test_smb_anonymous(self, port: int = 445) -> AnonLoginResult:
        """
        Test SMB anonymous/null session login.

        Tries: null session, guest account
        """
        print_info(f"Testing SMB anonymous login on port {port}...")

        result = AnonLoginResult(
            target=self.target,
            service="SMB",
            port=port,
            success=False,
            method="null_session"
        )

        # Method 1: smbclient null session
        if self.has_smbclient:
            cmd = f"smbclient -L //{self.target} -N 2>&1"
            cmd_result = self.executor.run(cmd, timeout=30, live_output=False)

            if cmd_result.return_code == 0 or "Sharename" in cmd_result.stdout:
                result.success = True
                result.method = "null_session (smbclient -N)"
                result.details = "SMB null session successful"

                # Parse shares
                shares = []
                for line in cmd_result.stdout.split('\n'):
                    if '\tDisk' in line or '\tIPC' in line or '\tPrinter' in line:
                        parts = line.strip().split()
                        if parts:
                            shares.append(parts[0])
                result.data['shares'] = shares

                print_success(f"SMB null session SUCCESS")
                if shares:
                    print_info(f"  Shares found: {', '.join(shares)}")

        # Method 2: Try guest account if null session failed
        if not result.success and self.has_smbclient:
            cmd = f"smbclient -L //{self.target} -U 'guest%' 2>&1"
            cmd_result = self.executor.run(cmd, timeout=30, live_output=False)

            if cmd_result.return_code == 0 or "Sharename" in cmd_result.stdout:
                result.success = True
                result.method = "guest_account"
                result.details = "SMB guest login successful"
                print_success(f"SMB guest login SUCCESS")

        # Method 3: CrackMapExec/NetExec
        if not result.success:
            tool = "netexec" if self.has_netexec else "crackmapexec" if self.has_crackmapexec else None
            if tool:
                cmd = f"{tool} smb {self.target} -u '' -p '' 2>&1"
                cmd_result = self.executor.run(cmd, timeout=30, live_output=False)

                if "[+]" in cmd_result.stdout or "STATUS_SUCCESS" in cmd_result.stdout:
                    result.success = True
                    result.method = f"null_session ({tool})"
                    result.details = "SMB null session successful"
                    print_success(f"SMB null session SUCCESS (via {tool})")

        if not result.success:
            print_warning(f"SMB anonymous login FAILED on port {port}")

        self._save_result(result)
        return result

    def test_smb_share_access(self, shares: List[str] = None) -> List[AnonLoginResult]:
        """Test anonymous read/write access to SMB shares."""
        print_info("Testing anonymous access to SMB shares...")

        results = []

        # Get share list if not provided
        if not shares and self.has_smbclient:
            cmd = f"smbclient -L //{self.target} -N 2>&1"
            cmd_result = self.executor.run(cmd, timeout=30, live_output=False)

            shares = []
            for line in cmd_result.stdout.split('\n'):
                if '\tDisk' in line:
                    parts = line.strip().split()
                    if parts and not parts[0].endswith('$'):
                        shares.append(parts[0])

        for share in shares or []:
            result = AnonLoginResult(
                target=self.target,
                service=f"SMB_SHARE",
                port=445,
                success=False,
                method=f"share:{share}"
            )

            # Test read access
            cmd = f"smbclient //{self.target}/{share} -N -c 'dir' 2>&1"
            cmd_result = self.executor.run(cmd, timeout=30, live_output=False)

            if cmd_result.return_code == 0 and "NT_STATUS_ACCESS_DENIED" not in cmd_result.stdout:
                result.success = True
                result.details = f"Anonymous READ access to {share}"
                result.data['access'] = 'read'

                # Count files
                file_count = len([l for l in cmd_result.stdout.split('\n') if '  D  ' in l or '  A  ' in l])
                result.data['file_count'] = file_count

                print_success(f"  Share '{share}': READ access ({file_count} items)")

                # Test write access (create and delete test file)
                test_cmd = f"smbclient //{self.target}/{share} -N -c 'put /dev/null .anon_test_delete_me' 2>&1"
                write_result = self.executor.run(test_cmd, timeout=15, live_output=False)

                if "NT_STATUS" not in write_result.stdout and write_result.return_code == 0:
                    result.data['access'] = 'read+write'
                    result.details = f"Anonymous READ+WRITE access to {share}"
                    print_success(f"  Share '{share}': WRITE access confirmed!")

                    # Clean up test file
                    cleanup_cmd = f"smbclient //{self.target}/{share} -N -c 'del .anon_test_delete_me' 2>&1"
                    self.executor.run(cleanup_cmd, timeout=10, live_output=False)
            else:
                print_warning(f"  Share '{share}': No anonymous access")

            results.append(result)

        return results

    def test_ldap_anonymous(self, port: int = 389) -> AnonLoginResult:
        """Test LDAP anonymous bind."""
        print_info(f"Testing LDAP anonymous bind on port {port}...")

        result = AnonLoginResult(
            target=self.target,
            service="LDAP",
            port=port,
            success=False,
            method="anonymous_bind"
        )

        if not self.has_ldapsearch:
            print_warning("ldapsearch not installed, skipping LDAP test")
            return result

        # Try anonymous bind and retrieve naming contexts
        cmd = f"ldapsearch -x -H ldap://{self.target}:{port} -s base namingContexts 2>&1"
        cmd_result = self.executor.run(cmd, timeout=30, live_output=False)

        if "namingContexts:" in cmd_result.stdout:
            result.success = True
            result.details = "LDAP anonymous bind successful"

            # Extract naming contexts (base DNs)
            contexts = re.findall(r'namingContexts:\s*(.+)', cmd_result.stdout)
            result.data['naming_contexts'] = contexts

            print_success(f"LDAP anonymous bind SUCCESS")
            for ctx in contexts:
                print_info(f"  Base DN: {ctx}")

            # Try to enumerate users
            if contexts:
                base_dn = contexts[0]
                user_cmd = f"ldapsearch -x -H ldap://{self.target}:{port} -b '{base_dn}' '(objectClass=user)' sAMAccountName 2>&1 | head -100"
                user_result = self.executor.run(user_cmd, timeout=60, live_output=False)

                users = re.findall(r'sAMAccountName:\s*(\S+)', user_result.stdout)
                if users:
                    result.data['users'] = users[:20]
                    print_info(f"  Found {len(users)} users")
        else:
            print_warning(f"LDAP anonymous bind FAILED on port {port}")

        self._save_result(result)
        return result

    def test_mysql_anonymous(self, port: int = 3306) -> AnonLoginResult:
        """Test MySQL anonymous/root without password login."""
        print_info(f"Testing MySQL anonymous login on port {port}...")

        result = AnonLoginResult(
            target=self.target,
            service="MySQL",
            port=port,
            success=False,
            method="anonymous"
        )

        if not self.has_mysql:
            print_warning("mysql client not installed, skipping MySQL test")
            return result

        # Try various anonymous/weak credentials
        credentials = [
            ("root", ""),
            ("mysql", ""),
            ("anonymous", ""),
            ("", ""),
            ("root", "root"),
            ("root", "toor"),
            ("admin", ""),
            ("admin", "admin"),
        ]

        for username, password in credentials:
            if password:
                cmd = f"mysql -h {self.target} -P {port} -u '{username}' -p'{password}' -e 'SELECT VERSION();' 2>&1"
            else:
                cmd = f"mysql -h {self.target} -P {port} -u '{username}' --skip-password -e 'SELECT VERSION();' 2>&1"

            cmd_result = self.executor.run(cmd, timeout=15, live_output=False)

            if "VERSION()" in cmd_result.stdout or re.search(r'\d+\.\d+\.\d+', cmd_result.stdout):
                result.success = True
                result.method = f"{username}:{password if password else '<blank>'}"
                result.details = f"MySQL login successful with {result.method}"

                # Extract version
                version_match = re.search(r'(\d+\.\d+\.\d+[^\s]*)', cmd_result.stdout)
                if version_match:
                    result.data['version'] = version_match.group(1)

                print_success(f"MySQL anonymous login SUCCESS: {result.method}")
                break

        if not result.success:
            print_warning(f"MySQL anonymous login FAILED on port {port}")

        self._save_result(result)
        return result

    def test_postgresql_anonymous(self, port: int = 5432) -> AnonLoginResult:
        """Test PostgreSQL anonymous/default login."""
        print_info(f"Testing PostgreSQL anonymous login on port {port}...")

        result = AnonLoginResult(
            target=self.target,
            service="PostgreSQL",
            port=port,
            success=False,
            method="anonymous"
        )

        if not self.has_psql:
            print_warning("psql not installed, skipping PostgreSQL test")
            return result

        credentials = [
            ("postgres", ""),
            ("postgres", "postgres"),
            ("admin", ""),
            ("admin", "admin"),
        ]

        for username, password in credentials:
            # Set PGPASSWORD environment variable
            env_prefix = f"PGPASSWORD='{password}'" if password else ""
            cmd = f"{env_prefix} psql -h {self.target} -p {port} -U {username} -c 'SELECT version();' 2>&1"

            cmd_result = self.executor.run(cmd, timeout=15, live_output=False)

            if "PostgreSQL" in cmd_result.stdout and "version" in cmd_result.stdout.lower():
                result.success = True
                result.method = f"{username}:{password if password else '<blank>'}"
                result.details = f"PostgreSQL login successful with {result.method}"

                # Extract version
                version_match = re.search(r'PostgreSQL\s+(\d+\.\d+)', cmd_result.stdout)
                if version_match:
                    result.data['version'] = version_match.group(1)

                print_success(f"PostgreSQL anonymous login SUCCESS: {result.method}")
                break

        if not result.success:
            print_warning(f"PostgreSQL anonymous login FAILED on port {port}")

        self._save_result(result)
        return result

    def test_redis_anonymous(self, port: int = 6379) -> AnonLoginResult:
        """Test Redis unauthenticated access."""
        print_info(f"Testing Redis anonymous access on port {port}...")

        result = AnonLoginResult(
            target=self.target,
            service="Redis",
            port=port,
            success=False,
            method="no_auth"
        )

        if not self.has_redis_cli:
            # Try raw socket connection
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((self.target, port))
                sock.send(b"INFO\r\n")
                response = sock.recv(4096).decode('utf-8', errors='ignore')
                sock.close()

                if "redis_version" in response:
                    result.success = True
                    result.method = "no_auth (socket)"
                    result.details = "Redis unauthenticated access confirmed"

                    version_match = re.search(r'redis_version:(\S+)', response)
                    if version_match:
                        result.data['version'] = version_match.group(1)

                    print_success(f"Redis anonymous access SUCCESS")
            except Exception as e:
                result.details = str(e)
        else:
            cmd = f"redis-cli -h {self.target} -p {port} INFO 2>&1"
            cmd_result = self.executor.run(cmd, timeout=15, live_output=False)

            if "redis_version" in cmd_result.stdout:
                result.success = True
                result.method = "no_auth"
                result.details = "Redis unauthenticated access confirmed"

                version_match = re.search(r'redis_version:(\S+)', cmd_result.stdout)
                if version_match:
                    result.data['version'] = version_match.group(1)

                print_success(f"Redis anonymous access SUCCESS (v{result.data.get('version', '?')})")

        if not result.success:
            print_warning(f"Redis anonymous access FAILED on port {port}")

        self._save_result(result)
        return result

    def test_mongodb_anonymous(self, port: int = 27017) -> AnonLoginResult:
        """Test MongoDB unauthenticated access."""
        print_info(f"Testing MongoDB anonymous access on port {port}...")

        result = AnonLoginResult(
            target=self.target,
            service="MongoDB",
            port=port,
            success=False,
            method="no_auth"
        )

        mongo_cmd = "mongosh" if check_tool_installed("mongosh") else "mongo"

        if not check_tool_installed(mongo_cmd):
            print_warning(f"{mongo_cmd} not installed, skipping MongoDB test")
            return result

        cmd = f"{mongo_cmd} --host {self.target} --port {port} --eval 'db.adminCommand({{listDatabases: 1}})' 2>&1"
        cmd_result = self.executor.run(cmd, timeout=15, live_output=False)

        if "databases" in cmd_result.stdout and "name" in cmd_result.stdout:
            result.success = True
            result.method = "no_auth"
            result.details = "MongoDB unauthenticated access confirmed"

            # Extract database names
            db_names = re.findall(r'"name"\s*:\s*"([^"]+)"', cmd_result.stdout)
            result.data['databases'] = db_names

            print_success(f"MongoDB anonymous access SUCCESS")
            print_info(f"  Databases: {', '.join(db_names)}")
        else:
            print_warning(f"MongoDB anonymous access FAILED on port {port}")

        self._save_result(result)
        return result

    def test_snmp_public(self, port: int = 161) -> AnonLoginResult:
        """Test SNMP with public community string."""
        print_info(f"Testing SNMP public community on port {port}...")

        result = AnonLoginResult(
            target=self.target,
            service="SNMP",
            port=port,
            success=False,
            method="public_community"
        )

        if not self.has_snmpwalk:
            print_warning("snmpwalk not installed, skipping SNMP test")
            return result

        community_strings = ["public", "private", "community", "snmp"]

        for community in community_strings:
            cmd = f"snmpwalk -v2c -c {community} {self.target}:{port} 1.3.6.1.2.1.1.1 2>&1"
            cmd_result = self.executor.run(cmd, timeout=15, live_output=False)

            if "STRING:" in cmd_result.stdout or "OID" in cmd_result.stdout:
                result.success = True
                result.method = f"community:{community}"
                result.details = f"SNMP accessible with community string '{community}'"

                # Extract system description
                desc_match = re.search(r'STRING:\s*"?([^"]+)"?', cmd_result.stdout)
                if desc_match:
                    result.data['system_description'] = desc_match.group(1)

                print_success(f"SNMP public community SUCCESS: '{community}'")
                break

        if not result.success:
            print_warning(f"SNMP public community FAILED on port {port}")

        self._save_result(result)
        return result

    def test_nfs_exports(self, port: int = 2049) -> AnonLoginResult:
        """Test NFS for world-accessible exports."""
        print_info(f"Testing NFS exports on port {port}...")

        result = AnonLoginResult(
            target=self.target,
            service="NFS",
            port=port,
            success=False,
            method="showmount"
        )

        if not self.has_nfs:
            print_warning("showmount not installed, skipping NFS test")
            return result

        cmd = f"showmount -e {self.target} 2>&1"
        cmd_result = self.executor.run(cmd, timeout=30, live_output=False)

        if "Export list" in cmd_result.stdout:
            # Parse exports
            exports = []
            for line in cmd_result.stdout.split('\n')[1:]:
                if line.strip():
                    parts = line.strip().split()
                    if parts:
                        export_path = parts[0]
                        allowed = parts[1] if len(parts) > 1 else "*"
                        exports.append({'path': export_path, 'allowed': allowed})

                        # Check if world-accessible
                        if '*' in allowed or '0.0.0.0' in allowed or 'everyone' in allowed.lower():
                            result.success = True

            result.data['exports'] = exports

            if result.success:
                result.details = "NFS has world-accessible exports"
                print_success(f"NFS world-accessible exports found:")
                for exp in exports:
                    print_info(f"  {exp['path']} -> {exp['allowed']}")
            else:
                print_warning(f"NFS exports found but restricted")
                for exp in exports:
                    print_info(f"  {exp['path']} -> {exp['allowed']}")
        else:
            print_warning(f"NFS no exports or access denied")

        self._save_result(result)
        return result

    def test_rsync_anonymous(self, port: int = 873) -> AnonLoginResult:
        """Test rsync for anonymous module access."""
        print_info(f"Testing rsync anonymous access on port {port}...")

        result = AnonLoginResult(
            target=self.target,
            service="rsync",
            port=port,
            success=False,
            method="anonymous"
        )

        if not self.has_rsync:
            print_warning("rsync not installed, skipping rsync test")
            return result

        cmd = f"rsync --list-only rsync://{self.target}:{port}/ 2>&1"
        cmd_result = self.executor.run(cmd, timeout=30, live_output=False)

        if cmd_result.return_code == 0 and cmd_result.stdout.strip():
            modules = [line.strip().split()[0] for line in cmd_result.stdout.split('\n') if line.strip()]
            modules = [m for m in modules if m and not m.startswith('@')]

            if modules:
                result.success = True
                result.method = "anonymous"
                result.details = f"rsync anonymous modules found: {', '.join(modules)}"
                result.data['modules'] = modules

                print_success(f"rsync anonymous access SUCCESS")
                print_info(f"  Modules: {', '.join(modules)}")
            else:
                print_warning(f"rsync accessible but no modules listed")
        else:
            print_warning(f"rsync anonymous access FAILED on port {port}")

        self._save_result(result)
        return result

    def test_telnet_banner(self, port: int = 23) -> AnonLoginResult:
        """Test Telnet for open access or information disclosure."""
        print_info(f"Testing Telnet on port {port}...")

        result = AnonLoginResult(
            target=self.target,
            service="Telnet",
            port=port,
            success=False,
            method="banner_grab"
        )

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.target, port))

            # Receive banner
            banner = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()

            if banner:
                result.success = True
                result.details = "Telnet accessible, banner received"
                result.data['banner'] = banner[:500]

                print_success(f"Telnet accessible on port {port}")
                print_info(f"  Banner: {banner[:100]}...")
        except Exception as e:
            result.details = str(e)
            print_warning(f"Telnet connection failed on port {port}")

        self._save_result(result)
        return result

    def test_rpc_anonymous(self, port: int = 111) -> AnonLoginResult:
        """Test RPC/rpcbind for service enumeration."""
        print_info(f"Testing RPC on port {port}...")

        result = AnonLoginResult(
            target=self.target,
            service="RPC",
            port=port,
            success=False,
            method="rpcinfo"
        )

        if check_tool_installed("rpcinfo"):
            cmd = f"rpcinfo -p {self.target} 2>&1"
            cmd_result = self.executor.run(cmd, timeout=30, live_output=False)

            if "program" in cmd_result.stdout.lower() and cmd_result.return_code == 0:
                result.success = True
                result.details = "RPC services enumerable"

                # Parse services
                services = []
                for line in cmd_result.stdout.split('\n')[1:]:
                    parts = line.split()
                    if len(parts) >= 4:
                        services.append({
                            'program': parts[0],
                            'version': parts[1],
                            'protocol': parts[2],
                            'port': parts[3]
                        })

                result.data['services'] = services[:20]
                print_success(f"RPC enumeration SUCCESS ({len(services)} services)")
        else:
            print_warning("rpcinfo not installed, skipping RPC test")

        self._save_result(result)
        return result

    def test_all_services(self, ports: Dict[str, List[int]] = None) -> AnonTestSummary:
        """
        Test anonymous login across all detected services.

        Args:
            ports: Dictionary mapping service names to port lists
                   e.g., {'ftp': [21], 'smb': [445], 'mysql': [3306]}
        """
        print_section(f"Anonymous Login Testing: {self.target}")

        summary = AnonTestSummary(target=self.target)

        # Default common ports if not specified
        if ports is None:
            ports = {
                'ftp': [21],
                'smb': [445, 139],
                'ldap': [389, 636],
                'mysql': [3306],
                'postgresql': [5432],
                'redis': [6379],
                'mongodb': [27017],
                'snmp': [161],
                'nfs': [2049],
                'rsync': [873],
                'telnet': [23],
                'rpc': [111]
            }

        # Test each service
        service_tests = {
            'ftp': self.test_ftp_anonymous,
            'smb': self.test_smb_anonymous,
            'ldap': self.test_ldap_anonymous,
            'mysql': self.test_mysql_anonymous,
            'postgresql': self.test_postgresql_anonymous,
            'redis': self.test_redis_anonymous,
            'mongodb': self.test_mongodb_anonymous,
            'snmp': self.test_snmp_public,
            'nfs': self.test_nfs_exports,
            'rsync': self.test_rsync_anonymous,
            'telnet': self.test_telnet_banner,
            'rpc': self.test_rpc_anonymous
        }

        for service, port_list in ports.items():
            if service in service_tests:
                for port in port_list:
                    # Check if port is open first
                    if self._is_port_open(port):
                        result = service_tests[service](port)
                        summary.add_result(result)
                    else:
                        print_info(f"Port {port} ({service}) is closed, skipping")

        # Test SMB share access if SMB was successful
        smb_success = any(r.success and r.service == "SMB" for r in summary.results)
        if smb_success:
            share_results = self.test_smb_share_access()
            for r in share_results:
                summary.add_result(r)

        self._print_summary(summary)
        return summary

    def _is_port_open(self, port: int, timeout: int = 3) -> bool:
        """Quick check if a port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            return result == 0
        except:
            return False

    def _save_result(self, result: AnonLoginResult):
        """Save individual result to output file."""
        if self.output_manager:
            output = f"""
{'='*60}
Service: {result.service}
Port: {result.port}
Success: {result.success}
Method: {result.method}
Details: {result.details}
Data: {result.data}
{'='*60}
"""
            filename = f"anon_login_{self.target.replace('.', '_')}.txt"
            filepath = self.output_manager.get_output_path('services', filename)

            with open(filepath, 'a') as f:
                f.write(output)

    def _print_summary(self, summary: AnonTestSummary):
        """Print summary of anonymous login tests."""
        print_section("Anonymous Login Summary")

        print_info(f"Target: {summary.target}")
        print_info(f"Total tests: {len(summary.results)}")

        successful = [r for r in summary.results if r.success]
        failed = [r for r in summary.results if not r.success]

        if successful:
            print(f"\n{Colors.GREEN}{Colors.BOLD}VULNERABLE SERVICES ({len(successful)}):{Colors.RESET}")
            for r in successful:
                print(f"  {Colors.GREEN}[✓]{Colors.RESET} {r.service}:{r.port} - {r.method}")
                if r.data:
                    for key, value in r.data.items():
                        if isinstance(value, list):
                            print(f"      {key}: {', '.join(str(v) for v in value[:5])}")
                        else:
                            print(f"      {key}: {value}")

        if failed:
            print(f"\n{Colors.YELLOW}Secure/Failed ({len(failed)}):{Colors.RESET}")
            for r in failed:
                print(f"  {Colors.YELLOW}[✗]{Colors.RESET} {r.service}:{r.port}")


def run_anon_menu(target: str) -> Optional[AnonTestSummary]:
    """Interactive menu for anonymous login testing."""
    from modules.utils import print_banner

    print_banner()

    tester = AnonymousLoginTester(target)

    print_section(f"Anonymous Login Testing: {target}")

    options = [
        ("1", "Test All Services (auto-detect)", lambda: tester.test_all_services()),
        ("2", "Test FTP Anonymous", lambda: tester.test_ftp_anonymous()),
        ("3", "Test SMB Null Session", lambda: tester.test_smb_anonymous()),
        ("4", "Test SMB Share Access", lambda: tester.test_smb_share_access()),
        ("5", "Test LDAP Anonymous", lambda: tester.test_ldap_anonymous()),
        ("6", "Test MySQL Anonymous", lambda: tester.test_mysql_anonymous()),
        ("7", "Test PostgreSQL Anonymous", lambda: tester.test_postgresql_anonymous()),
        ("8", "Test Redis No-Auth", lambda: tester.test_redis_anonymous()),
        ("9", "Test MongoDB No-Auth", lambda: tester.test_mongodb_anonymous()),
        ("a", "Test SNMP Public Community", lambda: tester.test_snmp_public()),
        ("b", "Test NFS Exports", lambda: tester.test_nfs_exports()),
        ("c", "Test rsync Anonymous", lambda: tester.test_rsync_anonymous()),
        ("0", "Back to Main Menu", None),
    ]

    print("\nSelect test:")
    for key, name, _ in options:
        print(f"  [{key}] {name}")

    choice = input(f"\n{Colors.CYAN}Enter choice: {Colors.RESET}").strip().lower()

    for key, name, func in options:
        if choice == key:
            if func is None:
                return None
            print_info(f"Starting {name}...")
            result = func()
            return result

    print_error("Invalid choice")
    return None


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python anon_login.py <target>")
        sys.exit(1)

    target = sys.argv[1]
    run_anon_menu(target)
