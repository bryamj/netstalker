#!/usr/bin/env python3
"""
Rose Pine themed colors and ASCII art for NETSTALKER
Cyberpunk-inspired visual theme for penetration testing
"""

import random
import sys
import time
from typing import List


class RosePine:
    """Rose Pine Dawn color palette for terminal output."""

    # Primary colors
    FOAM = "\033[38;2;86;148;159m"       # Cyan/Teal #56949f
    IRIS = "\033[38;2;144;122;169m"      # Purple/Magenta #907aa9
    PINE = "\033[38;2;40;105;131m"       # Deep teal #286983
    LOVE = "\033[38;2;180;99;122m"       # Red/Rose #b4637a
    GOLD = "\033[38;2;234;157;52m"       # Orange/Yellow #ea9d34
    ROSE = "\033[38;2;215;130;126m"      # Light rose #d7827e

    # Text colors
    TEXT = "\033[38;2;87;82;121m"        # Main text #575279
    SUBTLE = "\033[38;2;121;117;147m"    # Subtle text #797593
    MUTED = "\033[38;2;152;147;165m"     # Muted text #9893a5

    # Background/surface colors
    BASE = "\033[38;2;250;244;237m"      # Base background #faf4ed
    SURFACE = "\033[38;2;255;250;243m"   # Surface #fffaf3
    OVERLAY = "\033[38;2;242;233;225m"   # Overlay #f2e9e1

    # Semantic aliases for common uses
    NEON_CYAN = FOAM
    NEON_MAGENTA = IRIS
    NEON_GREEN = PINE
    ELECTRIC_BLUE = FOAM
    DEEP_PURPLE = IRIS
    BRIGHT_RED = LOVE
    ORANGE = GOLD
    YELLOW = GOLD
    WHITE = TEXT
    GRAY = MUTED
    DARK_CYAN = PINE

    # Control codes
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    REVERSE = "\033[7m"

    @classmethod
    def gradient(cls, text: str, color1: str, color2: str) -> str:
        """Create a gradient effect between two colors."""
        # Simple two-color gradient for text
        mid = len(text) // 2
        return f"{color1}{text[:mid]}{color2}{text[mid:]}{cls.RESET}"


class CyberSymbols:
    """Cyberpunk and terminal symbols."""

    # Block characters
    BLOCK_FULL = "█"
    BLOCK_DARK = "▓"
    BLOCK_MED = "▒"
    BLOCK_LIGHT = "░"

    # Arrows and pointers
    ARROW_RIGHT = "►"
    ARROW_LEFT = "◄"
    ARROW_UP = "▲"
    ARROW_DOWN = "▼"
    POINTER = "➤"

    # Shapes
    DIAMOND = "◆"
    CIRCLE = "●"
    CIRCLE_EMPTY = "○"
    SQUARE = "■"
    SQUARE_EMPTY = "□"
    TRIANGLE = "▲"
    STAR = "★"
    STAR_EMPTY = "☆"

    # Status indicators
    CHECK = "✓"
    CROSS = "✗"
    PLUS = "+"
    MINUS = "-"
    WARNING = "⚠"
    INFO = "ℹ"
    QUESTION = "?"

    # Tech symbols
    LIGHTNING = "⚡"
    GEAR = "⚙"
    SHIELD = "🛡"
    ROCKET = "🚀"
    SKULL = "☠"
    TARGET = "🎯"
    KEY = "🔑"
    LOCK = "🔒"
    UNLOCK = "🔓"

    # Box drawing
    BOX_TL = "╔"
    BOX_TR = "╗"
    BOX_BL = "╚"
    BOX_BR = "╝"
    BOX_H = "═"
    BOX_V = "║"
    BOX_VR = "╠"
    BOX_VL = "╣"
    BOX_HU = "╩"
    BOX_HD = "╦"
    BOX_CROSS = "╬"

    # Matrix/Cyber characters
    CYBER_CHARS = "ヲアイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワン"
    BINARY = "01"
    HEX = "0123456789ABCDEF"

    # Glitch characters
    GLITCH = "░▒▓█▀▄│─┌┐└┘├┤┬┴┼"


class CyberArt:
    """Cyberpunk ASCII art for NETSTALKER."""

    @staticmethod
    def main_banner() -> str:
        """Main NETSTALKER banner."""
        r = RosePine
        return f"""
{r.FOAM}███╗   ██╗███████╗████████╗{r.IRIS}███████╗████████╗ █████╗ ██╗     ██╗  ██╗███████╗██████╗
{r.FOAM}████╗  ██║██╔════╝╚══██╔══╝{r.IRIS}██╔════╝╚══██╔══╝██╔══██╗██║     ██║ ██╔╝██╔════╝██╔══██╗
{r.FOAM}██╔██╗ ██║█████╗     ██║   {r.IRIS}███████╗   ██║   ███████║██║     █████╔╝ █████╗  ██████╔╝
{r.FOAM}██║╚██╗██║██╔══╝     ██║   {r.IRIS}╚════██║   ██║   ██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
{r.FOAM}██║ ╚████║███████╗   ██║   {r.IRIS}███████║   ██║   ██║  ██║███████╗██║  ██╗███████╗██║  ██║
{r.FOAM}╚═╝  ╚═══╝╚══════╝   ╚═╝   {r.IRIS}╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
{r.RESET}"""

    @staticmethod
    def skull_small() -> str:
        """Small skull art for warnings/critical sections."""
        r = RosePine
        return f"""
{r.LOVE}      ▄▄▄▄▄▄▄
{r.LOVE}    ▄█{r.OVERLAY}░░░░░{r.LOVE}█▄
{r.LOVE}   █{r.OVERLAY}░{r.FOAM}█{r.OVERLAY}░░░{r.FOAM}█{r.OVERLAY}░{r.LOVE}█
{r.LOVE}   █{r.OVERLAY}░░░{r.IRIS}▀{r.OVERLAY}░░░{r.LOVE}█
{r.LOVE}    █{r.OVERLAY}░{r.PINE}███{r.OVERLAY}░{r.LOVE}█
{r.LOVE}     ▀▀▀▀▀▀
{r.RESET}"""

    @staticmethod
    def cyber_eye() -> str:
        """Cybernetic eye art."""
        r = RosePine
        return f"""
{r.FOAM}    ▄▄▄▄▄▄▄▄▄
{r.FOAM}  ▄█{r.OVERLAY}░░░░░░░{r.FOAM}█▄
{r.FOAM} █{r.OVERLAY}░░░{r.IRIS}▄▄▄{r.OVERLAY}░░░{r.FOAM}█
{r.FOAM} █{r.OVERLAY}░░{r.IRIS}█{r.GOLD}█{r.IRIS}█{r.OVERLAY}░░{r.FOAM}█
{r.FOAM}  ▀█{r.OVERLAY}░░{r.IRIS}▀{r.OVERLAY}░░{r.FOAM}█▀
{r.FOAM}    ▀▀▀▀▀▀▀
{r.RESET}"""

    @staticmethod
    def terminal_glitch() -> str:
        """Glitch effect terminal."""
        r = RosePine
        return f"""
{r.FOAM}┌─[{r.IRIS}NETSTALKER{r.FOAM}@{r.PINE}VOID{r.FOAM}]─[{r.GOLD}~{r.FOAM}]{r.RESET}
{r.FOAM}└──╼{r.IRIS}${r.RESET} """

    @staticmethod
    def section_divider(title: str, width: int = 80) -> str:
        """Create a cyberpunk section divider."""
        r = RosePine
        s = CyberSymbols

        # Calculate padding
        title_len = len(title)
        padding = (width - title_len - 4) // 2

        line = f"{r.FOAM}{s.BOX_H * padding}{r.RESET} "
        line += f"{r.IRIS}{s.ARROW_RIGHT}{r.RESET} "
        line += f"{r.BOLD}{r.GOLD}{title}{r.RESET} "
        line += f"{r.IRIS}{s.ARROW_LEFT}{r.RESET} "
        line += f"{r.FOAM}{s.BOX_H * padding}{r.RESET}"

        return line

    @staticmethod
    def status_ok(msg: str) -> str:
        """Format success message."""
        r = RosePine
        s = CyberSymbols
        return f"{r.PINE}[{r.BOLD}{s.CHECK}{r.RESET}{r.PINE}]{r.RESET} {r.FOAM}{msg}{r.RESET}"

    @staticmethod
    def status_fail(msg: str) -> str:
        """Format failure message."""
        r = RosePine
        s = CyberSymbols
        return f"{r.LOVE}[{r.BOLD}{s.CROSS}{r.RESET}{r.LOVE}]{r.RESET} {r.MUTED}{msg}{r.RESET}"

    @staticmethod
    def status_warn(msg: str) -> str:
        """Format warning message."""
        r = RosePine
        s = CyberSymbols
        return f"{r.GOLD}[{r.BOLD}{s.WARNING}{r.RESET}{r.GOLD}]{r.RESET} {r.GOLD}{msg}{r.RESET}"

    @staticmethod
    def status_info(msg: str) -> str:
        """Format info message."""
        r = RosePine
        s = CyberSymbols
        return f"{r.IRIS}[{r.BOLD}{s.ARROW_RIGHT}{r.RESET}{r.IRIS}]{r.RESET} {r.TEXT}{msg}{r.RESET}"

    @staticmethod
    def matrix_line(width: int = 80, density: float = 0.3) -> str:
        """Generate a single line of matrix-style characters."""
        r = RosePine
        s = CyberSymbols

        line = ""
        for _ in range(width):
            if random.random() < density:
                char = random.choice(s.CYBER_CHARS + s.BINARY)
                color = random.choice([r.FOAM, r.IRIS, r.PINE, r.MUTED])
                line += f"{color}{char}{r.RESET}"
            else:
                line += " "
        return line

    @staticmethod
    def loading_bar(percent: int, width: int = 40, label: str = "") -> str:
        """Create a cyberpunk loading bar."""
        r = RosePine
        s = CyberSymbols

        filled = int(width * percent / 100)
        empty = width - filled

        bar = f"{r.FOAM}[{r.RESET}"
        bar += f"{r.IRIS}{s.BLOCK_FULL * filled}{r.RESET}"
        bar += f"{r.MUTED}{s.BLOCK_LIGHT * empty}{r.RESET}"
        bar += f"{r.FOAM}]{r.RESET} "
        bar += f"{r.GOLD}{percent:3d}%{r.RESET}"

        if label:
            bar += f" {r.TEXT}{label}{r.RESET}"

        return bar

    @staticmethod
    def box_message(title: str, lines: List[str], width: int = 60) -> str:
        """Create a boxed message with cyberpunk styling."""
        r = RosePine
        s = CyberSymbols

        output = []

        # Top border
        output.append(f"{r.FOAM}{s.BOX_TL}{s.BOX_H * (width - 2)}{s.BOX_TR}{r.RESET}")

        # Title
        title_padding = (width - len(title) - 4) // 2
        title_line = f"{r.FOAM}{s.BOX_V}{r.RESET} "
        title_line += " " * title_padding
        title_line += f"{r.BOLD}{r.IRIS}{title}{r.RESET}"
        title_line += " " * (width - len(title) - title_padding - 4)
        title_line += f" {r.FOAM}{s.BOX_V}{r.RESET}"
        output.append(title_line)

        # Separator
        output.append(f"{r.FOAM}{s.BOX_VR}{s.BOX_H * (width - 2)}{s.BOX_VL}{r.RESET}")

        # Content lines
        for line in lines:
            content_padding = width - len(line) - 4
            content_line = f"{r.FOAM}{s.BOX_V}{r.RESET} {r.TEXT}{line}{r.RESET}"
            content_line += " " * content_padding
            content_line += f" {r.FOAM}{s.BOX_V}{r.RESET}"
            output.append(content_line)

        # Bottom border
        output.append(f"{r.FOAM}{s.BOX_BL}{s.BOX_H * (width - 2)}{s.BOX_BR}{r.RESET}")

        return "\n".join(output)


class CyberEffects:
    """Terminal effects and animations."""

    @staticmethod
    def matrix_rain(duration: float = 2.0, width: int = 80):
        """Display matrix rain effect."""
        import shutil
        try:
            term_width = shutil.get_terminal_size().columns
            width = min(width, term_width)
        except:
            pass

        start_time = time.time()
        while time.time() - start_time < duration:
            sys.stdout.write("\r" + CyberArt.matrix_line(width, 0.2))
            sys.stdout.flush()
            time.sleep(0.05)
        sys.stdout.write("\r" + " " * width + "\r")
        sys.stdout.flush()

    @staticmethod
    def glitch_text(text: str, intensity: int = 3) -> str:
        """Add glitch effect to text."""
        r = RosePine
        s = CyberSymbols

        result = ""
        for char in text:
            if random.random() < (intensity * 0.1):
                # Add glitch
                glitch_char = random.choice(s.GLITCH)
                glitch_color = random.choice([r.FOAM, r.IRIS, r.LOVE, r.GOLD])
                result += f"{glitch_color}{glitch_char}{r.RESET}"
            else:
                result += char
        return result

    @staticmethod
    def cyber_spinner(text: str = "Loading", delay: float = 0.1):
        """Return a cyberpunk spinner frame generator."""
        r = RosePine
        frames = [
            f"{r.FOAM}[{r.IRIS}◐{r.FOAM}]{r.RESET}",
            f"{r.FOAM}[{r.IRIS}◓{r.FOAM}]{r.RESET}",
            f"{r.FOAM}[{r.IRIS}◑{r.FOAM}]{r.RESET}",
            f"{r.FOAM}[{r.IRIS}◒{r.FOAM}]{r.RESET}",
        ]
        i = 0
        while True:
            yield f"{frames[i % len(frames)]} {r.TEXT}{text}{r.RESET}"
            i += 1
            time.sleep(delay)


def print_banner():
    """Print the main NETSTALKER banner."""
    r = RosePine
    s = CyberSymbols

    print(CyberArt.main_banner())

    subtitle = f"{r.FOAM}{'═' * 20} {r.PINE}{s.LIGHTNING} Cyberpunk Penetration Testing Arsenal {s.LIGHTNING} {r.FOAM}{'═' * 20}{r.RESET}"
    print(subtitle.center(100))
    print()

    tagline = f"{r.MUTED}[ {r.IRIS}Ethical Hacking Framework {r.MUTED}• {r.FOAM}Rose Pine Themed {r.MUTED}• {r.GOLD}v2.0 CYBER {r.MUTED}]{r.RESET}"
    print(tagline.center(100))
    print()


if __name__ == "__main__":
    # Demo the theme
    print_banner()
    print()

    print(CyberArt.section_divider("STATUS INDICATORS"))
    print(CyberArt.status_ok("Connection established"))
    print(CyberArt.status_fail("Authentication failed"))
    print(CyberArt.status_warn("High latency detected"))
    print(CyberArt.status_info("Scanning in progress..."))
    print()

    print(CyberArt.section_divider("LOADING BAR"))
    for i in range(0, 101, 20):
        print(CyberArt.loading_bar(i, label=f"Scan progress"))
        time.sleep(0.3)
    print()

    print(CyberArt.section_divider("BOXED MESSAGE"))
    print(CyberArt.box_message("ALERT", [
        "Target acquired: 10.10.10.10",
        "Ports open: 80, 443, 445",
        "OS detected: Windows Server 2019"
    ]))
    print()

    print(CyberArt.section_divider("MATRIX EFFECT"))
    CyberEffects.matrix_rain(1.5)
    print()

    print(CyberArt.skull_small())
    print(CyberArt.cyber_eye())
