#!/usr/bin/env python3
"""
Configuration management for the Pentest Toolkit.
Handles target settings, tool paths, and scan profiles.
"""

import os
import json
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict

# Base directories
TOOLKIT_ROOT = Path(__file__).parent.parent
RESULTS_DIR = TOOLKIT_ROOT / "results"
CONFIGS_DIR = TOOLKIT_ROOT / "configs"
WORDLISTS_DIR = Path("/usr/share/wordlists")

# Default wordlists (common locations)
DEFAULT_WORDLISTS = {
    "dirb_common": "/usr/share/wordlists/dirb/common.txt",
    "dirb_big": "/usr/share/wordlists/dirb/big.txt",
    "dirbuster_medium": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "rockyou": "/usr/share/wordlists/rockyou.txt",
    "seclists_common": "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "seclists_raft_dirs": "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
}


@dataclass
class TargetConfig:
    """Configuration for a specific target."""
    ip: str
    hostname: Optional[str] = None
    domain: Optional[str] = None
    ports: List[int] = field(default_factory=list)
    discovered_services: Dict[int, str] = field(default_factory=dict)
    notes: str = ""

    def __post_init__(self):
        """Validate IP address format."""
        import ipaddress
        try:
            ipaddress.ip_address(self.ip)
        except ValueError:
            # Could be a hostname or CIDR, allow it
            pass

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> 'TargetConfig':
        return cls(**data)

    def save(self, results_dir: Path) -> Path:
        """Save target config to JSON file."""
        target_dir = results_dir / self.ip.replace('/', '_')
        target_dir.mkdir(parents=True, exist_ok=True)
        config_file = target_dir / "target_config.json"
        with open(config_file, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
        return config_file

    @classmethod
    def load(cls, config_file: Path) -> 'TargetConfig':
        """Load target config from JSON file."""
        with open(config_file, 'r') as f:
            return cls.from_dict(json.load(f))


@dataclass
class ScanProfile:
    """Predefined scan profiles for common scenarios."""
    name: str
    description: str
    rustscan_args: List[str] = field(default_factory=list)
    nmap_args: List[str] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)


# Predefined scan profiles
SCAN_PROFILES = {
    "quick": ScanProfile(
        name="Quick Scan",
        description="Fast port discovery with basic service detection",
        rustscan_args=["--ulimit", "5000", "-b", "1500"],
        nmap_args=["-sV", "-sC", "--open"],
        scripts=[]
    ),
    "full": ScanProfile(
        name="Full Enumeration",
        description="Complete port scan with version detection and default scripts",
        rustscan_args=["--ulimit", "5000", "-b", "1500", "--range", "1-65535"],
        nmap_args=["-sV", "-sC", "-O", "--open"],
        scripts=[]
    ),
    "full_scripts": ScanProfile(
        name="Full Enumeration with Scripts",
        description="Complete scan with vulnerability scripts",
        rustscan_args=["--ulimit", "5000", "-b", "1500", "--range", "1-65535"],
        nmap_args=["-sV", "-sC", "-O", "--open", "--script", "vuln"],
        scripts=["vuln"]
    ),
    "stealth": ScanProfile(
        name="Stealth Scan",
        description="Slow, stealthy scan to avoid detection",
        rustscan_args=["--ulimit", "1000", "-b", "100"],
        nmap_args=["-sS", "-sV", "-T2", "--open"],
        scripts=[]
    ),
    "udp": ScanProfile(
        name="UDP Scan",
        description="Top UDP ports scan (requires sudo)",
        rustscan_args=[],  # RustScan doesn't do UDP, use Nmap directly
        nmap_args=["-sU", "-sV", "--top-ports", "100", "--open"],
        scripts=[]
    ),
    "smb": ScanProfile(
        name="SMB Enumeration",
        description="Focused SMB/Windows enumeration",
        rustscan_args=["--ulimit", "5000", "-p", "139,445"],
        nmap_args=["-sV", "-sC", "--script", "smb-enum-shares,smb-enum-users,smb-os-discovery,smb-security-mode,smb-protocols,smb2-security-mode"],
        scripts=["smb-*"]
    ),
    "http": ScanProfile(
        name="HTTP Enumeration",
        description="Web server enumeration with HTTP scripts",
        rustscan_args=["--ulimit", "5000", "-p", "80,443,8080,8443,8000,8888"],
        nmap_args=["-sV", "-sC", "--script", "http-enum,http-headers,http-methods,http-title,http-robots.txt,http-sitemap-generator"],
        scripts=["http-*"]
    ),
    "vuln": ScanProfile(
        name="Vulnerability Scan",
        description="Vulnerability assessment scan",
        rustscan_args=["--ulimit", "5000", "-b", "1500"],
        nmap_args=["-sV", "--script", "vuln", "--open"],
        scripts=["vuln"]
    ),
}


# Tool paths (auto-detect or configure)
TOOL_PATHS = {
    "rustscan": "rustscan",
    "nmap": "nmap",
    "gobuster": "gobuster",
    "ffuf": "ffuf",
    "nikto": "nikto",
    "nuclei": "nuclei",
    "enum4linux": "enum4linux",
    "enum4linux-ng": "enum4linux-ng",
    "smbclient": "smbclient",
    "crackmapexec": "crackmapexec",
    "netexec": "netexec",
    "impacket-GetNPUsers": "impacket-GetNPUsers",
    "impacket-GetUserSPNs": "impacket-GetUserSPNs",
    "impacket-secretsdump": "impacket-secretsdump",
    "impacket-psexec": "impacket-psexec",
    "impacket-wmiexec": "impacket-wmiexec",
    "impacket-smbexec": "impacket-smbexec",
}


def check_tool_installed(tool_name: str) -> bool:
    """Check if a tool is installed and accessible."""
    import shutil
    tool_path = TOOL_PATHS.get(tool_name, tool_name)
    return shutil.which(tool_path) is not None


def get_installed_tools() -> Dict[str, bool]:
    """Get a dictionary of all tools and their installation status."""
    return {tool: check_tool_installed(tool) for tool in TOOL_PATHS}


def find_wordlist(name: str) -> Optional[Path]:
    """Find a wordlist by name or path."""
    # Check if it's a direct path
    if os.path.exists(name):
        return Path(name)

    # Check predefined wordlists
    if name in DEFAULT_WORDLISTS:
        path = Path(DEFAULT_WORDLISTS[name])
        if path.exists():
            return path

    # Search common locations
    search_paths = [
        Path("/usr/share/wordlists"),
        Path("/usr/share/seclists"),
        Path("/opt/wordlists"),
        Path.home() / "wordlists",
    ]

    for base_path in search_paths:
        if base_path.exists():
            matches = list(base_path.rglob(f"*{name}*"))
            if matches:
                return matches[0]

    return None
