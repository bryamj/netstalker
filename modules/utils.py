#!/usr/bin/env python3
"""
Core utilities for the Pentest Toolkit.
Handles logging, command execution, and output management.
"""

import os
import sys
import subprocess
import shlex
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Tuple, Callable
from dataclasses import dataclass
import threading
import queue

# Import Rose Pine theme
try:
    from modules.theme import RosePine as Colors, CyberSymbols, CyberArt
except ImportError:
    # Fallback to basic colors if theme module not available
    class Colors:
        RED = '\033[91m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        BLUE = '\033[94m'
        MAGENTA = '\033[95m'
        CYAN = '\033[96m'
        WHITE = '\033[97m'
        BOLD = '\033[1m'
        UNDERLINE = '\033[4m'
        RESET = '\033[0m'
        # Rose Pine aliases
        FOAM = CYAN
        IRIS = MAGENTA
        PINE = GREEN
        LOVE = RED
        GOLD = YELLOW
        TEXT = WHITE
        MUTED = '\033[90m'

        @classmethod
        def disable(cls):
            """Disable colors for non-TTY output."""
            for attr in dir(cls):
                if not attr.startswith('_') and attr.isupper():
                    setattr(cls, attr, '')

    class CyberSymbols:
        CHECK = "✓"
        CROSS = "✗"
        ARROW_RIGHT = "►"
        WARNING = "⚠"

    class CyberArt:
        @staticmethod
        def status_ok(msg): return f"[{Colors.GREEN}✓{Colors.RESET}] {msg}"
        @staticmethod
        def status_fail(msg): return f"[{Colors.RED}✗{Colors.RESET}] {msg}"
        @staticmethod
        def status_warn(msg): return f"[{Colors.YELLOW}⚠{Colors.RESET}] {msg}"
        @staticmethod
        def status_info(msg): return f"[{Colors.CYAN}►{Colors.RESET}] {msg}"


def colorize(text: str, color: str) -> str:
    """Apply color to text."""
    return f"{color}{text}{Colors.RESET}"


def print_banner():
    """Print the NETSTALKER cyberpunk banner."""
    try:
        from modules.theme import print_banner as cyber_banner
        cyber_banner()
        return
    except:
        pass

    # Fallback banner
    banner = f"""
{Colors.FOAM}███╗   ██╗███████╗████████╗{Colors.IRIS}███████╗████████╗ █████╗ ██╗     ██╗  ██╗███████╗██████╗
{Colors.FOAM}████╗  ██║██╔════╝╚══██╔══╝{Colors.IRIS}██╔════╝╚══██╔══╝██╔══██╗██║     ██║ ██╔╝██╔════╝██╔══██╗
{Colors.FOAM}██╔██╗ ██║█████╗     ██║   {Colors.IRIS}███████╗   ██║   ███████║██║     █████╔╝ █████╗  ██████╔╝
{Colors.FOAM}██║╚██╗██║██╔══╝     ██║   {Colors.IRIS}╚════██║   ██║   ██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
{Colors.FOAM}██║ ╚████║███████╗   ██║   {Colors.IRIS}███████║   ██║   ██║  ██║███████╗██║  ██╗███████╗██║  ██║
{Colors.FOAM}╚═╝  ╚═══╝╚══════╝   ╚═╝   {Colors.IRIS}╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝{Colors.RESET}

{Colors.FOAM}{'═' * 20} {Colors.PINE}⚡ Cyberpunk Penetration Testing Arsenal ⚡{Colors.FOAM} {'═' * 20}{Colors.RESET}
{Colors.MUTED}[ {Colors.IRIS}Ethical Hacking Framework {Colors.MUTED}• {Colors.FOAM}Rose Pine Themed {Colors.MUTED}• {Colors.GOLD}v2.0 CYBER {Colors.MUTED}]{Colors.RESET}
"""
    print(banner)


def print_section(title: str, char: str = "═"):
    """Print a cyberpunk section header."""
    try:
        from modules.theme import CyberArt
        print(f"\n{CyberArt.section_divider(title, 80)}\n")
    except:
        width = 80
        padding = (width - len(title) - 4) // 2
        line = f"{Colors.FOAM}{char * padding}{Colors.RESET} "
        line += f"{Colors.IRIS}►{Colors.RESET} "
        line += f"{Colors.BOLD}{Colors.GOLD}{title}{Colors.RESET} "
        line += f"{Colors.IRIS}◄{Colors.RESET} "
        line += f"{Colors.FOAM}{char * padding}{Colors.RESET}"
        print(f"\n{line}\n")


def print_success(message: str):
    """Print a success message."""
    try:
        from modules.theme import CyberArt
        print(CyberArt.status_ok(message))
    except:
        print(f"{Colors.PINE}[✓]{Colors.RESET} {Colors.FOAM}{message}{Colors.RESET}")


def print_error(message: str):
    """Print an error message."""
    try:
        from modules.theme import CyberArt
        print(CyberArt.status_fail(message))
    except:
        print(f"{Colors.LOVE}[✗]{Colors.RESET} {Colors.MUTED}{message}{Colors.RESET}")


def print_warning(message: str):
    """Print a warning message."""
    try:
        from modules.theme import CyberArt
        print(CyberArt.status_warn(message))
    except:
        print(f"{Colors.GOLD}[!]{Colors.RESET} {Colors.GOLD}{message}{Colors.RESET}")


def print_info(message: str):
    """Print an info message."""
    try:
        from modules.theme import CyberArt
        print(CyberArt.status_info(message))
    except:
        print(f"{Colors.IRIS}[*]{Colors.RESET} {Colors.TEXT}{message}{Colors.RESET}")


def print_progress(message: str):
    """Print a progress message."""
    print(f"{Colors.IRIS}[→]{Colors.RESET} {Colors.TEXT}{message}{Colors.RESET}")


@dataclass
class CommandResult:
    """Result of a command execution."""
    command: str
    return_code: int
    stdout: str
    stderr: str
    duration: float
    success: bool

    def __str__(self):
        status = "SUCCESS" if self.success else "FAILED"
        return f"[{status}] {self.command} (exit: {self.return_code}, duration: {self.duration:.2f}s)"


class OutputManager:
    """Manages output directories and logging for pentest results."""

    def __init__(self, base_dir: Path, target_ip: str):
        self.base_dir = Path(base_dir)
        self.target_ip = target_ip.replace('/', '_').replace(':', '_')
        self.target_dir = self.base_dir / self.target_ip
        self.session_time = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Create directory structure
        self.dirs = {
            'root': self.target_dir,
            'scans': self.target_dir / 'scans',
            'web': self.target_dir / 'web',
            'services': self.target_dir / 'services',
            'ad': self.target_dir / 'ad',
            'loot': self.target_dir / 'loot',
            'notes': self.target_dir / 'notes',
        }

        for dir_path in self.dirs.values():
            dir_path.mkdir(parents=True, exist_ok=True)

        # Setup logging
        self.master_log = self.base_dir / "master_log.txt"
        self.session_log = self.target_dir / f"session_{self.session_time}.log"
        self.command_log = self.target_dir / "commands.log"

        self._setup_logging()

    def _setup_logging(self):
        """Setup logging configuration."""
        self.logger = logging.getLogger(f"pentest_{self.target_ip}")
        self.logger.setLevel(logging.DEBUG)

        # File handler for session log
        fh = logging.FileHandler(self.session_log)
        fh.setLevel(logging.DEBUG)

        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)

        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)

        self.logger.addHandler(fh)
        self.logger.addHandler(ch)

    def log_command(self, command: str, result: CommandResult):
        """Log a command execution to both session and master logs."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Log to session log
        self.logger.info(f"Command: {command}")
        self.logger.info(f"Exit Code: {result.return_code}")
        self.logger.info(f"Duration: {result.duration:.2f}s")

        # Append to master log
        with open(self.master_log, 'a') as f:
            f.write(f"\n{'='*60}\n")
            f.write(f"Timestamp: {timestamp}\n")
            f.write(f"Target: {self.target_ip}\n")
            f.write(f"Command: {command}\n")
            f.write(f"Exit Code: {result.return_code}\n")
            f.write(f"Duration: {result.duration:.2f}s\n")
            f.write(f"{'='*60}\n")

        # Append to command log
        with open(self.command_log, 'a') as f:
            f.write(f"[{timestamp}] {command}\n")

    def save_output(self, category: str, filename: str, content: str) -> Path:
        """Save output to a file in the appropriate category directory."""
        output_dir = self.dirs.get(category, self.target_dir)
        output_file = output_dir / filename
        with open(output_file, 'w') as f:
            f.write(content)
        return output_file

    def get_output_path(self, category: str, filename: str) -> Path:
        """Get the path for an output file."""
        output_dir = self.dirs.get(category, self.target_dir)
        return output_dir / filename


class CommandExecutor:
    """Executes shell commands with logging and output capture."""

    def __init__(self, output_manager: Optional[OutputManager] = None):
        self.output_manager = output_manager

    def run(
        self,
        command: str,
        timeout: Optional[int] = None,
        capture_output: bool = True,
        live_output: bool = True,
        sudo: bool = False,
        env: Optional[dict] = None
    ) -> CommandResult:
        """
        Execute a command and return the result.

        Args:
            command: The command to execute
            timeout: Timeout in seconds (None for no timeout)
            capture_output: Whether to capture stdout/stderr
            live_output: Whether to print output in real-time
            sudo: Whether to prepend sudo to the command
            env: Additional environment variables
        """
        if sudo and os.geteuid() != 0:
            command = f"sudo {command}"

        print_progress(f"Executing: {command}")

        start_time = datetime.now()
        stdout_data = []
        stderr_data = []

        try:
            # Prepare environment
            run_env = os.environ.copy()
            if env:
                run_env.update(env)

            # Execute command
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=run_env
            )

            if live_output and capture_output:
                # Read output in real-time
                def read_stream(stream, buffer, prefix=""):
                    for line in iter(stream.readline, ''):
                        buffer.append(line)
                        if live_output:
                            print(f"{prefix}{line}", end='')
                    stream.close()

                stdout_thread = threading.Thread(
                    target=read_stream,
                    args=(process.stdout, stdout_data, "")
                )
                stderr_thread = threading.Thread(
                    target=read_stream,
                    args=(process.stderr, stderr_data, f"{Colors.RED}")
                )

                stdout_thread.start()
                stderr_thread.start()

                # Wait for completion
                process.wait(timeout=timeout)
                stdout_thread.join()
                stderr_thread.join()

                stdout = ''.join(stdout_data)
                stderr = ''.join(stderr_data)
            else:
                stdout, stderr = process.communicate(timeout=timeout)

            return_code = process.returncode

        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            return_code = -1
            print_error(f"Command timed out after {timeout} seconds")

        except Exception as e:
            stdout = ""
            stderr = str(e)
            return_code = -1
            print_error(f"Command execution failed: {e}")

        duration = (datetime.now() - start_time).total_seconds()
        success = return_code == 0

        result = CommandResult(
            command=command,
            return_code=return_code,
            stdout=stdout if isinstance(stdout, str) else ''.join(stdout),
            stderr=stderr if isinstance(stderr, str) else ''.join(stderr),
            duration=duration,
            success=success
        )

        # Log the command
        if self.output_manager:
            self.output_manager.log_command(command, result)

        if success:
            print_success(f"Command completed in {duration:.2f}s")
        else:
            print_error(f"Command failed with exit code {return_code}")

        return result

    def run_chain(
        self,
        commands: List[str],
        stop_on_error: bool = True,
        **kwargs
    ) -> List[CommandResult]:
        """Execute a chain of commands."""
        results = []
        for cmd in commands:
            result = self.run(cmd, **kwargs)
            results.append(result)
            if stop_on_error and not result.success:
                print_error(f"Chain stopped due to failed command: {cmd}")
                break
        return results


def validate_ip(ip: str) -> bool:
    """Validate an IP address or hostname."""
    import ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        # Could be a hostname or CIDR
        if '/' in ip:
            try:
                ipaddress.ip_network(ip, strict=False)
                return True
            except ValueError:
                pass
        # Allow hostnames
        import re
        hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(hostname_pattern, ip))


def parse_ports(ports_str: str) -> List[int]:
    """Parse a port specification string into a list of ports."""
    ports = []
    for part in ports_str.split(','):
        part = part.strip()
        if '-' in part:
            start, end = part.split('-')
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def format_ports(ports: List[int]) -> str:
    """Format a list of ports into a compact string."""
    if not ports:
        return ""

    ports = sorted(set(ports))
    ranges = []
    start = ports[0]
    end = ports[0]

    for port in ports[1:]:
        if port == end + 1:
            end = port
        else:
            if start == end:
                ranges.append(str(start))
            else:
                ranges.append(f"{start}-{end}")
            start = end = port

    if start == end:
        ranges.append(str(start))
    else:
        ranges.append(f"{start}-{end}")

    return ','.join(ranges)
