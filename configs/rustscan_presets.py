#!/usr/bin/env python3
"""
RustScan Preset Configurations for NETSTALKER
Provides multiple scanning modes optimized for different scenarios.
"""

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class RustScanPreset:
    """RustScan preset configuration."""
    name: str
    description: str
    ulimit: int
    batch_size: int
    timeout: int
    port_range: Optional[str]
    nmap_args: List[str]
    use_case: str
    estimated_time: str


# Preset definitions
RUSTSCAN_FAST = RustScanPreset(
    name="fast",
    description="Fast reconnaissance scan (top 1000 ports)",
    ulimit=5000,
    batch_size=2000,
    timeout=2000,
    port_range=None,  # Will use --top-ports 1000
    nmap_args=["-sV", "-sC", "-Pn"],
    use_case="Initial reconnaissance, CTF time limits, quick checks",
    estimated_time="~30 seconds"
)

RUSTSCAN_FULL = RustScanPreset(
    name="full",
    description="Comprehensive scan (all 65535 ports)",
    ulimit=5000,
    batch_size=1500,
    timeout=3000,
    port_range="1-65535",
    nmap_args=["-A", "-Pn"],
    use_case="Comprehensive enumeration, professional pentests, HTB boxes",
    estimated_time="~5-10 minutes"
)

RUSTSCAN_STEALTH = RustScanPreset(
    name="stealth",
    description="Slow, evasive scan (IDS/IPS evasion)",
    ulimit=1000,
    batch_size=500,
    timeout=5000,
    port_range="1-65535",
    nmap_args=["-sV", "-T2", "-Pn", "--max-retries", "1"],
    use_case="IDS/IPS evasion, production environments, stealthy enumeration",
    estimated_time="~30-60 minutes"
)

RUSTSCAN_CUSTOM = RustScanPreset(
    name="custom",
    description="Custom scan with user-defined Nmap arguments",
    ulimit=5000,
    batch_size=1500,
    timeout=3000,
    port_range="1-65535",
    nmap_args=[],  # User provides via CLI
    use_case="Maximum flexibility, specific enumeration needs",
    estimated_time="Variable"
)

# Preset registry
RUSTSCAN_PRESETS = {
    "fast": RUSTSCAN_FAST,
    "full": RUSTSCAN_FULL,
    "stealth": RUSTSCAN_STEALTH,
    "custom": RUSTSCAN_CUSTOM,
}


def get_preset(name: str) -> Optional[RustScanPreset]:
    """Get a RustScan preset by name."""
    return RUSTSCAN_PRESETS.get(name.lower())


def list_presets() -> List[RustScanPreset]:
    """Get all available presets."""
    return list(RUSTSCAN_PRESETS.values())
