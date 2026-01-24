#!/usr/bin/env python3
"""
VOIDWALKER v3.9.2 - Elite Penetration Testing Arsenal Builder
A colorful, animated terminal-based installation script for Ubuntu/Debian systems
Features binary downloads, parallel installs, and cyberpunk aesthetics.

Designed for HTB Pro Labs and professional penetration testing engagements.
Downloads 250+ security tools including Windows binaries, PowerShell scripts,
C2 frameworks, and more.
"""

import argparse
import gzip
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import random
import urllib.parse
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError

__version__ = "3.9.2"

class Colors:
    # Rosé Pine Dawn Color Palette
    NEON_CYAN = "\033[38;2;86;148;159m"      # Foam #56949f
    NEON_MAGENTA = "\033[38;2;144;122;169m"  # Iris #907aa9
    NEON_GREEN = "\033[38;2;40;105;131m"     # Pine #286983
    ELECTRIC_BLUE = "\033[38;2;86;148;159m"  # Foam #56949f
    DEEP_PURPLE = "\033[38;2;144;122;169m"   # Iris #907aa9
    BRIGHT_RED = "\033[38;2;180;99;122m"     # Love #b4637a
    ORANGE = "\033[38;2;234;157;52m"         # Gold #ea9d34
    YELLOW = "\033[38;2;234;157;52m"         # Gold #ea9d34
    WHITE = "\033[38;2;87;82;121m"           # Text #575279
    GRAY = "\033[38;2;152;147;165m"          # Muted #9893a5
    DARK_CYAN = "\033[38;2;40;105;131m"      # Pine #286983
    ROSE = "\033[38;2;215;130;126m"          # Rose #d7827e
    SUBTLE = "\033[38;2;121;117;147m"        # Subtle #797593
    BASE = "\033[38;2;250;244;237m"          # Base #faf4ed
    SURFACE = "\033[38;2;255;250;243m"       # Surface #fffaf3
    OVERLAY = "\033[38;2;242;233;225m"       # Overlay #f2e9e1
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

class Symbols:
    BLOCK_FULL = "█"
    BLOCK_LIGHT = "░"
    BLOCK_MED = "▒"
    BLOCK_DARK = "▓"
    ARROW_RIGHT = "►"
    DIAMOND = "◆"
    CIRCLE = "●"
    STAR = "★"
    CHECK = "✓"
    CROSS = "✗"
    LIGHTNING = "⚡"
    GEAR = "⚙"
    SHIELD = "🛡"
    ROCKET = "🚀"
    BOX_TL = "╔"
    BOX_TR = "╗"
    BOX_BL = "╚"
    BOX_BR = "╝"
    BOX_H = "═"
    BOX_V = "║"
    CYBER_CHARS = "ヲアイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワン"

WORKSPACE_DIRS = [
    "engagements/_template/notes",
    "engagements/_template/scans/nmap",
    "engagements/_template/scans/web",
    "engagements/_template/scans/ad",
    "engagements/_template/loot/creds",
    "engagements/_template/loot/hashes",
    "engagements/_template/loot/tickets",
    "engagements/_template/loot/screenshots",
    "engagements/_template/exploits",
    "engagements/_template/reports",
    "tools/windows/enum",
    "tools/windows/privesc",
    "tools/windows/creds",
    "tools/windows/kerberos",
    "tools/windows/lateral",
    "tools/windows/adcs",
    "tools/windows/coercion",
    "tools/windows/persistence",
    "tools/windows/evasion",
    "tools/windows/inveigh",
    "tools/windows/misc",
    "tools/windows/precompiled",
    "tools/windows/sql",
    "tools/windows/exchange",
    "tools/windows/delegation",
    "tools/windows/relay",
    "tools/windows/sysinternals",
    "tools/powershell/recon",
    "tools/powershell/privesc",
    "tools/powershell/creds",
    "tools/powershell/lateral",
    "tools/powershell/persistence",
    "tools/powershell/evasion",
    "tools/powershell/ad",
    "tools/linux/enum",
    "tools/linux/privesc",
    "tools/linux/static",
    "tools/pivoting/chisel",
    "tools/pivoting/ligolo-ng",
    "tools/pivoting/misc",
    "tools/maldev/loaders",
    "tools/maldev/injection",
    "tools/maldev/evasion",
    "tools/maldev/crypters",
    "tools/maldev/shellcode",
    "tools/maldev/persistence",
    "tools/maldev/misc",
    "tools/c2",
    "tools/c2/implants",
    "tools/web/scanners",
    "tools/web/sqli",
    "tools/web/xss_ssrf",
    "tools/web/cms",
    "tools/web/api",
    "tools/cloud/aws",
    "tools/cloud/azure",
    "tools/cloud/gcp",
    "tools/cloud/kubernetes",
    "tools/container/kubernetes",
    "tools/container/escape",
    "tools/container/scanners",
    "tools/phishing/frameworks",
    "tools/phishing/email",
    "tools/phishing/payloads",
    "tools/wireless/wifi",
    "tools/wireless/bluetooth",
    "tools/wireless/rf",
    "payloads/webshells/php",
    "payloads/webshells/aspx",
    "payloads/webshells/jsp",
    "payloads/reverse-shells",
    "payloads/shellcode",
    "wordlists/passwords",
    "wordlists/usernames",
    "wordlists/directories",
    "wordlists/subdomains",
    "wordlists/kerberos",
    "wordlists/custom",
    "notes/cheatsheets",
    "notes/methodology",
    "loot",
    "scans",
    "reports/templates",
]

TOOL_CATEGORIES = {
    "Windows Binaries": {
        "description": "Mimikatz, Rubeus, SharpHound, Inveigh, GhostPack tools, and more",
        "function": "setup_windows_arsenal",
        "tools": [
            ("SharpCollection", "git", "https://github.com/Flangvik/SharpCollection.git", "Pre-compiled .NET arsenal (Rubeus, Seatbelt, etc.)"),
            ("Mimikatz", "zip", "https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip", "Credential dumping tool"),
            ("LaZagne", "file", "https://github.com/AlessandroZ/LaZagne/releases/latest/download/LaZagne.exe", "Multi-platform credential recovery"),
            ("PrintSpoofer64", "file", "https://github.com/itm4n/PrintSpoofer/releases/latest/download/PrintSpoofer64.exe", "Privilege escalation"),
            ("GodPotato-NET4", "file", "https://github.com/BeichenDream/GodPotato/releases/latest/download/GodPotato-NET4.exe", "Potato privilege escalation"),
            ("JuicyPotatoNG", "zip", "https://github.com/antonioCoco/JuicyPotatoNG/releases/latest/download/JuicyPotatoNG.zip", "Potato privilege escalation"),
            ("RunasCs", "zip", "https://github.com/antonioCoco/RunasCs/releases/latest/download/RunasCs.zip", "RunAs alternative"),
            ("winPEASx64", "file", "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe", "Windows privilege escalation"),
            ("winPEASx86", "file", "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx86.exe", "Windows privilege escalation (32-bit)"),
            ("Rubeus", "file", "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe", "Kerberos abuse toolkit"),
            ("Seatbelt", "file", "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Seatbelt.exe", "Security enumeration"),
            ("SharpUp", "file", "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/SharpUp.exe", "Privilege escalation checks"),
            ("SharpDPAPI", "file", "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/SharpDPAPI.exe", "DPAPI secrets extraction"),
            ("SafetyKatz", "file", "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/SafetyKatz.exe", "Safe Mimikatz"),
            ("SharpHound", "file", "https://github.com/BloodHoundAD/SharpHound/releases/latest/download/SharpHound.exe", "BloodHound collector"),
            ("Inveigh", "file", "https://github.com/Kevin-Robertson/Inveigh/releases/latest/download/Inveigh.exe", "LLMNR/NBNS poisoning"),
            ("Snaffler", "file", "https://github.com/SnaffCon/Snaffler/releases/latest/download/Snaffler.exe", "Credential hunting"),
            ("KrbRelayUp", "file", "https://github.com/Dec0ne/KrbRelayUp/releases/latest/download/KrbRelayUp.exe", "Kerberos relay"),
            ("Certify", "file", "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Certify.exe", "ADCS abuse"),
            ("SharpGPOAbuse", "file", "https://github.com/FSecureLABS/SharpGPOAbuse/releases/download/1.0/SharpGPOAbuse.exe", "GPO abuse"),
            ("nanodump", "file", "https://github.com/fortra/nanodump/releases/latest/download/nanodump.x64.exe", "LSASS dumper"),
            ("nc64", "file", "https://github.com/int0x33/nc.exe/raw/master/nc64.exe", "Netcat for Windows"),
            ("accesschk64", "file", "https://live.sysinternals.com/accesschk64.exe", "Access check utility"),
            ("PsExec64", "file", "https://live.sysinternals.com/PsExec64.exe", "Remote execution"),
            ("procdump64", "file", "https://live.sysinternals.com/procdump64.exe", "Process dump utility"),
        ],
        "repos": [
            ("GhostPack-Compiled", "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries.git"),
            ("Inveigh-Repo", "https://github.com/Kevin-Robertson/Inveigh.git"),
            ("KrbRelay", "https://github.com/cube0x0/KrbRelay.git"),
            ("KrbRelayUp", "https://github.com/Dec0ne/KrbRelayUp.git"),
            ("Certify", "https://github.com/GhostPack/Certify.git"),
            ("ForgeCert", "https://github.com/GhostPack/ForgeCert.git"),
            ("PassTheCert", "https://github.com/AlmondOffSec/PassTheCert.git"),
            ("PKINITtools", "https://github.com/dirkjanm/PKINITtools.git"),
            ("PetitPotam", "https://github.com/topotam/PetitPotam.git"),
            ("DFSCoerce", "https://github.com/Wh04m1001/DFSCoerce.git"),
            ("Coercer", "https://github.com/p0dalirius/Coercer.git"),
            ("ShadowCoerce", "https://github.com/ShutdownRepo/ShadowCoerce.git"),
            ("SharpWMI", "https://github.com/GhostPack/SharpWMI.git"),
            ("SharpRDP", "https://github.com/0xthirteen/SharpRDP.git"),
            ("SharpMove", "https://github.com/0xthirteen/SharpMove.git"),
            ("SCShell", "https://github.com/Mr-Un1k0d3r/SCShell.git"),
            ("SharpView", "https://github.com/tevora-threat/SharpView.git"),
            ("ADSearch", "https://github.com/tomcarver16/ADSearch.git"),
            ("ADRecon", "https://github.com/adrecon/ADRecon.git"),
            ("Snaffler", "https://github.com/SnaffCon/Snaffler.git"),
            ("StandIn", "https://github.com/FuzzySecurity/StandIn.git"),
            ("SharpGPOAbuse", "https://github.com/FSecureLABS/SharpGPOAbuse.git"),
            ("SharPersist", "https://github.com/mandiant/SharPersist.git"),
            ("AMSI-Bypass", "https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell.git"),
            ("Invisi-Shell", "https://github.com/OmerYa/Invisi-Shell.git"),
            ("Donut", "https://github.com/TheWover/donut.git"),
            ("Whisker", "https://github.com/eladshamir/Whisker.git"),
            ("SharpChromium", "https://github.com/djhohnstein/SharpChromium.git"),
            ("SharpSecDump", "https://github.com/G0ldenGunSec/SharpSecDump.git"),
            ("SharpLAPS", "https://github.com/swisskyrepo/SharpLAPS.git"),
            ("noPac", "https://github.com/Ridter/noPac.git"),
            ("SharpSCCM", "https://github.com/Mayyhem/SharpSCCM.git"),
            ("InternalMonologue", "https://github.com/eladshamir/Internal-Monologue.git"),
            ("SpoolSample", "https://github.com/leechristensen/SpoolSample.git"),
            ("SQLRecon", "https://github.com/skahwah/SQLRecon.git"),
            ("DAFT", "https://github.com/NetSPI/DAFT.git"),
            ("MailSniper", "https://github.com/dafthack/MailSniper.git"),
            ("ruler", "https://github.com/sensepost/ruler.git"),
            ("PrivExchange", "https://github.com/dirkjanm/PrivExchange.git"),
            ("krbrelayx", "https://github.com/dirkjanm/krbrelayx.git"),
            ("mitm6", "https://github.com/dirkjanm/mitm6.git"),
            ("RemotePotato0", "https://github.com/antonioCoco/RemotePotato0.git"),
        ]
    },
    "PowerShell Scripts": {
        "description": "PowerSploit, Nishang, PowerView, PrivescCheck, AMSI bypasses",
        "function": "setup_powershell_arsenal",
        "repos": [
            ("PowerSploit", "https://github.com/PowerShellMafia/PowerSploit.git"),
            ("nishang", "https://github.com/samratashok/nishang.git"),
            ("Powermad", "https://github.com/Kevin-Robertson/Powermad.git"),
            ("ADModule", "https://github.com/samratashok/ADModule.git"),
            ("PowerUpSQL", "https://github.com/NetSPI/PowerUpSQL.git"),
            ("Invoke-TheHash", "https://github.com/Kevin-Robertson/Invoke-TheHash.git"),
            ("PrivescCheck", "https://github.com/itm4n/PrivescCheck.git"),
            ("AMSI-Bypass-PS", "https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell.git"),
        ],
        "files": [
            ("jaws-enum.ps1", "https://raw.githubusercontent.com/411Hall/JAWS/master/jaws-enum.ps1"),
            ("SharpHound.ps1", "https://github.com/BloodHoundAD/SharpHound/releases/latest/download/SharpHound.ps1"),
        ]
    },
    "Linux Tools": {
        "description": "linPEAS, LinEnum, pspy, exploit suggesters, static binaries",
        "function": "setup_linux_tools",
        "files": [
            ("linpeas.sh", "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh"),
            ("LinEnum.sh", "https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"),
            ("lse.sh", "https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh"),
            ("pspy64", "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64"),
            ("pspy32", "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy32"),
            ("nmap_static", "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/nmap"),
            ("socat_static", "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat"),
        ],
        "repos": [
            ("linux-exploit-suggester", "https://github.com/mzet-/linux-exploit-suggester.git"),
            ("linux-exploit-suggester-2", "https://github.com/jondonas/linux-exploit-suggester-2.git"),
        ]
    },
    "Pivoting Tools": {
        "description": "Chisel, Ligolo-ng, plink, rpivot, Stowaway, Neo-reGeorg",
        "function": "setup_pivoting_tools",
        "files": [
            ("plink.exe", "https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe"),
        ],
        "repos": [
            ("rpivot", "https://github.com/klsecservices/rpivot.git"),
            ("revsocks", "https://github.com/kost/revsocks.git"),
            ("Stowaway", "https://github.com/ph4ntonn/Stowaway.git"),
            ("Neo-reGeorg", "https://github.com/L-codes/Neo-reGeorg.git"),
        ],
        "special": ["chisel", "ligolo-ng"]
    },
    "C2 Frameworks": {
        "description": "Havoc, Sliver, Villain, Mythic, Covenant, PoshC2, Merlin",
        "function": "setup_c2_frameworks",
        "repos": [
            ("Havoc", "https://github.com/HavocFramework/Havoc.git"),
            ("Sliver", "https://github.com/BishopFox/sliver.git"),
            ("Villain", "https://github.com/t3l3machus/Villain.git"),
            ("Mythic", "https://github.com/its-a-feature/Mythic.git"),
            ("Covenant", "https://github.com/cobbr/Covenant.git"),
            ("PoshC2", "https://github.com/nettitude/PoshC2.git"),
            ("SILENTTRINITY", "https://github.com/byt3bl33d3r/SILENTTRINITY.git"),
            ("Merlin", "https://github.com/Ne0nd0g/merlin.git"),
            ("SharpC2", "https://github.com/rasta-mouse/SharpC2.git"),
            ("Hoaxshell", "https://github.com/t3l3machus/hoaxshell.git"),
        ]
    },
    "Maldev Tools": {
        "description": "Syscall loaders, process injection, evasion, crypters",
        "function": "setup_maldev_academy",
        "repos": [
            ("HellsGate", "https://github.com/am0nsec/HellsGate.git"),
            ("SysWhispers2", "https://github.com/jthuraisamy/SysWhispers2.git"),
            ("SysWhispers3", "https://github.com/klezVirus/SysWhispers3.git"),
            ("BokuLoader", "https://github.com/boku7/BokuLoader.git"),
            ("ThreadlessInject", "https://github.com/CCob/ThreadlessInject.git"),
            ("DInjector", "https://github.com/snovvcrash/DInjector.git"),
            ("Freeze", "https://github.com/optiv/Freeze.git"),
            ("ScareCrow", "https://github.com/optiv/ScareCrow.git"),
            ("PEzor", "https://github.com/phra/PEzor.git"),
            ("inceptor", "https://github.com/klezVirus/inceptor.git"),
            ("Nimcrypt2", "https://github.com/icyguider/Nimcrypt2.git"),
            ("ProtectMyTooling", "https://github.com/mgeeky/ProtectMyTooling.git"),
            ("OffensiveRust", "https://github.com/trickster0/OffensiveRust.git"),
            ("OffensiveNim", "https://github.com/byt3bl33d3r/OffensiveNim.git"),
            ("UACME", "https://github.com/hfiref0x/UACME.git"),
        ]
    },
    "Web Tools": {
        "description": "dirsearch, sqlmap, XSStrike, wpscan, jwt_tool, API testing",
        "function": "setup_web_tools",
        "repos": [
            ("dirsearch", "https://github.com/maurosoria/dirsearch.git"),
            ("wfuzz", "https://github.com/xmendez/wfuzz.git"),
            ("arjun", "https://github.com/s0md3v/Arjun.git"),
            ("paramspider", "https://github.com/devanshbatham/ParamSpider.git"),
            ("LinkFinder", "https://github.com/GerbenJavado/LinkFinder.git"),
            ("sqlmap", "https://github.com/sqlmapproject/sqlmap.git"),
            ("ghauri", "https://github.com/r0oth3x49/ghauri.git"),
            ("NoSQLMap", "https://github.com/codingo/NoSQLMap.git"),
            ("XSStrike", "https://github.com/s0md3v/XSStrike.git"),
            ("dalfox", "https://github.com/hahwul/dalfox.git"),
            ("SSRFmap", "https://github.com/swisskyrepo/SSRFmap.git"),
            ("wpscan", "https://github.com/wpscanteam/wpscan.git"),
            ("joomscan", "https://github.com/OWASP/joomscan.git"),
            ("CMSmap", "https://github.com/Dionach/CMSmap.git"),
            ("jwt_tool", "https://github.com/ticarpi/jwt_tool.git"),
            ("GraphQLmap", "https://github.com/swisskyrepo/GraphQLmap.git"),
        ]
    },
    "Cloud Tools": {
        "description": "AWS, Azure, GCP attack tools - pacu, ROADtools, ScoutSuite",
        "function": "setup_cloud_tools",
        "repos": [
            ("pacu", "https://github.com/RhinoSecurityLabs/pacu.git"),
            ("prowler", "https://github.com/prowler-cloud/prowler.git"),
            ("enumerate-iam", "https://github.com/andresriancho/enumerate-iam.git"),
            ("cloudsplaining", "https://github.com/salesforce/cloudsplaining.git"),
            ("PMapper", "https://github.com/nccgroup/PMapper.git"),
            ("ROADtools", "https://github.com/dirkjanm/ROADtools.git"),
            ("AzureHound", "https://github.com/BloodHoundAD/AzureHound.git"),
            ("MicroBurst", "https://github.com/NetSPI/MicroBurst.git"),
            ("AADInternals", "https://github.com/Gerenios/AADInternals.git"),
            ("TokenTactics", "https://github.com/rvrsh3ll/TokenTactics.git"),
            ("MSOLSpray", "https://github.com/dafthack/MSOLSpray.git"),
            ("GraphRunner", "https://github.com/dafthack/GraphRunner.git"),
            ("ScoutSuite", "https://github.com/nccgroup/ScoutSuite.git"),
            ("cloudfox", "https://github.com/BishopFox/cloudfox.git"),
        ]
    },
    "Container Tools": {
        "description": "Kubernetes attack tools - peirates, CDK, kube-hunter",
        "function": "setup_container_tools",
        "repos": [
            ("peirates", "https://github.com/inguardians/peirates.git"),
            ("CDK", "https://github.com/cdk-team/CDK.git"),
            ("kube-hunter", "https://github.com/aquasecurity/kube-hunter.git"),
            ("kubeaudit", "https://github.com/Shopify/kubeaudit.git"),
            ("kubeletctl", "https://github.com/cyberark/kubeletctl.git"),
            ("deepce", "https://github.com/stealthcopter/deepce.git"),
            ("trivy", "https://github.com/aquasecurity/trivy.git"),
        ]
    },
    "Phishing Tools": {
        "description": "GoPhish, Evilginx2, Modlishka, payload generators",
        "function": "setup_phishing_tools",
        "repos": [
            ("gophish", "https://github.com/gophish/gophish.git"),
            ("evilginx2", "https://github.com/kgretzky/evilginx2.git"),
            ("Modlishka", "https://github.com/drk1wi/Modlishka.git"),
            ("muraena", "https://github.com/muraenateam/muraena.git"),
            ("zphisher", "https://github.com/htr-tech/zphisher.git"),
            ("MailSniper", "https://github.com/dafthack/MailSniper.git"),
            ("CredSniper", "https://github.com/Raikia/CredSniper.git"),
            ("macro_pack", "https://github.com/sevagas/macro_pack.git"),
            ("EvilClippy", "https://github.com/outflanknl/EvilClippy.git"),
        ]
    },
    "Wireless Tools": {
        "description": "WiFi attack tools - bettercap, airgeddon, wifite2, eaphammer",
        "function": "setup_wireless_tools",
        "repos": [
            ("bettercap", "https://github.com/bettercap/bettercap.git"),
            ("airgeddon", "https://github.com/v1s1t0r1sh3r3/airgeddon.git"),
            ("wifite2", "https://github.com/derv82/wifite2.git"),
            ("hostapd-mana", "https://github.com/sensepost/hostapd-mana.git"),
            ("wifiphisher", "https://github.com/wifiphisher/wifiphisher.git"),
            ("eaphammer", "https://github.com/s0lst1c3/eaphammer.git"),
            ("wifipumpkin3", "https://github.com/P0cL4bs/wifipumpkin3.git"),
            ("fluxion", "https://github.com/FluxionNetwork/fluxion.git"),
        ]
    },
    "Webshells & Payloads": {
        "description": "Webshells, reverse shells, exploit collections, PayloadsAllTheThings",
        "function": "setup_webshells",
        "repos": [
            ("webshell-collection", "https://github.com/tennc/webshell.git"),
            ("PayloadsAllTheThings", "https://github.com/swisskyrepo/PayloadsAllTheThings.git"),
            ("webshells", "https://github.com/BlackArch/webshells.git"),
            ("php-webshells", "https://github.com/JohnTroony/php-webshells.git"),
            ("webshell-detect", "https://github.com/emposha/PHP-Shell-Detector.git"),
            ("weevely3", "https://github.com/epinna/weevely3.git"),
            ("p0wny-shell", "https://github.com/flozz/p0wny-shell.git"),
            ("b374k", "https://github.com/b374k/b374k.git"),
            ("WSO-webshell", "https://github.com/mIcHyAmRaNe/wso-webshell.git"),
            ("Alfa-Shell", "https://github.com/mIcHyAmRaNe/Starter-Alfa-Shell.git"),
            ("reverse-shell-generator", "https://github.com/0dayCTF/reverse-shell-generator.git"),
            ("php-reverse-shell", "https://github.com/pentestmonkey/php-reverse-shell.git"),
            ("wwwolf-php-webshell", "https://github.com/WhiteWinterWolf/wwwolf-php-webshell.git"),
            ("aspx-reverse-shell", "https://github.com/borjmz/aspx-reverse-shell.git"),
            ("JSP-Webshell", "https://github.com/SecurityRiskAdvisors/cmd.jsp.git"),
            ("GodGeneral-Shell", "https://github.com/0x4M3R/GodGeneral-Shell.git"),
            ("AndroxGh0st", "https://github.com/Androxgh0st/Androxgh0st.git"),
            ("Laudanum", "https://github.com/jbarcia/Web-Shells.git"),
            ("nano", "https://github.com/s0md3v/nano.git"),
            ("SharPyShell", "https://github.com/antonioCoco/SharPyShell.git"),
            ("priv8-webshells", "https://github.com/xl7dev/WebShell.git"),
            ("shell-backdoor-list", "https://github.com/TheBinitGhimire/Web-Shells.git"),
        ],
        "files": [
            ("php-reverse-shell.php", "https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php"),
            ("simple-backdoor.php", "https://raw.githubusercontent.com/BlackArch/webshells/master/php/simple-backdoor.php"),
            ("cmd.php", "https://raw.githubusercontent.com/WhiteWinterWolf/wwwolf-php-webshell/master/webshell.php"),
            ("p0wny-shell.php", "https://raw.githubusercontent.com/flozz/p0wny-shell/master/shell.php"),
            ("mini-shell.php", "https://raw.githubusercontent.com/JohnTroony/php-webshells/master/Collection/Simple_PHP_backdoor_by_DK.php"),
            ("cmd.aspx", "https://raw.githubusercontent.com/tennc/webshell/master/asp/webshell.aspx"),
            ("cmd.jsp", "https://raw.githubusercontent.com/SecurityRiskAdvisors/cmd.jsp/master/cmd.jsp"),
            ("cmd.war", "https://raw.githubusercontent.com/SecurityRiskAdvisors/cmd.jsp/master/cmd.war"),
            ("perl-reverse.pl", "https://raw.githubusercontent.com/pentestmonkey/perl-reverse-shell/master/perl-reverse-shell.pl"),
            ("python-reverse.py", "https://raw.githubusercontent.com/pentestmonkey/python-pty-shells/master/tcp_pty_backconnect.py"),
            ("ruby-reverse.rb", "https://raw.githubusercontent.com/pentestmonkey/ruby-reverse-shell/master/revshell.rb"),
            ("nc-reverse.sh", "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md"),
        ]
    },
    "Exploit Frameworks": {
        "description": "Exploit databases, PoC collections, vulnerability scanners",
        "function": "setup_exploits",
        "repos": [
            ("exploitdb", "https://github.com/offensive-security/exploitdb.git"),
            ("exploitdb-bin-sploits", "https://github.com/offensive-security/exploitdb-bin-sploits.git"),
            ("exploitdb-papers", "https://github.com/offensive-security/exploitdb-papers.git"),
            ("PoC-in-GitHub", "https://github.com/nomi-sec/PoC-in-GitHub.git"),
            ("Awesome-CVE-PoC", "https://github.com/qazbnm456/awesome-cve-poc.git"),
            ("CVE-Exploits", "https://github.com/Threekiii/Awesome-POC.git"),
            ("Windows-Exploit-Suggester", "https://github.com/AonCyberLabs/Windows-Exploit-Suggester.git"),
            ("wesng", "https://github.com/bitsadmin/wesng.git"),
            ("AutoBlue-MS17-010", "https://github.com/3ndG4me/AutoBlue-MS17-010.git"),
            ("MS17-010", "https://github.com/worawit/MS17-010.git"),
            ("CVE-2021-1675", "https://github.com/cube0x0/CVE-2021-1675.git"),
            ("CVE-2021-34527", "https://github.com/JohnHammond/CVE-2021-34527.git"),
            ("PrintNightmare", "https://github.com/calebstewart/CVE-2021-1675.git"),
            ("ZeroLogon", "https://github.com/dirkjanm/CVE-2020-1472.git"),
            ("ProxyLogon", "https://github.com/hausec/ProxyLogon.git"),
            ("ProxyShell", "https://github.com/GossiTheDog/scanning.git"),
            ("Log4Shell", "https://github.com/kozmer/log4j-shell-poc.git"),
            ("Spring4Shell", "https://github.com/reznok/Spring4Shell-POC.git"),
            ("Follina", "https://github.com/chvancooten/follina.py.git"),
            ("noPac", "https://github.com/Ridter/noPac.git"),
            ("PetitPotam", "https://github.com/topotam/PetitPotam.git"),
            ("ShadowCoerce", "https://github.com/ShutdownRepo/ShadowCoerce.git"),
            ("DFSCoerce", "https://github.com/Wh04m1001/DFSCoerce.git"),
            ("Coercer", "https://github.com/p0dalirius/Coercer.git"),
            ("SpoolFool", "https://github.com/ly4k/SpoolFool.git"),
            ("Certifried", "https://github.com/ly4k/Certifried.git"),
        ]
    },
    "Wordlists": {
        "description": "SecLists, rockyou, Kerberos usernames",
        "function": "setup_wordlists",
        "repos": [
            ("SecLists", "https://github.com/danielmiessler/SecLists.git"),
        ],
        "files": [
            ("A-ZSurnames.txt", "https://raw.githubusercontent.com/attackdebris/kerberos_enum_userlists/master/A-ZSurnames.txt"),
        ]
    },
}

APT_TOOLS = [
    # Reconnaissance & Scanning
    "nmap", "masscan", "zmap", "unicornscan", "netdiscover", "arp-scan",
    "amass", "subfinder", "assetfinder", "dnsrecon", "dnsenum", "fierce",
    "whois", "host", "dig", "traceroute", "hping3", "fping",
    # Web Application Testing
    "gobuster", "feroxbuster", "dirb", "dirbuster", "nikto", "whatweb",
    "wpscan", "wfuzz", "sqlmap", "commix", "xsser", "cadaver",
    "davtest", "curl", "wget", "httpie", "lynx",
    # Password Attacks
    "hydra", "medusa", "john", "hashcat", "hashid", "hash-identifier",
    "crunch", "cewl", "wordlists", "seclists",
    # Wireless
    "aircrack-ng", "reaver", "bully", "pixiewps", "wifite", "kismet",
    "mdk3", "mdk4", "macchanger", "iw", "wireless-tools",
    # Exploitation
    "metasploit-framework", "exploitdb", "searchsploit",
    "shellnoob", "veil", "msfpc",
    # Sniffing & Spoofing
    "wireshark", "tshark", "tcpdump", "ettercap-common", "ettercap-text-only",
    "bettercap", "dsniff", "macof", "arpspoof", "responder",
    # Post-Exploitation
    "enum4linux-ng", "smbclient", "smbmap", "rpcclient", "nbtscan",
    "onesixtyone", "snmpwalk", "snmp", "redis-tools",
    "ldap-utils", "nfs-common", "rpcbind",
    # Pivoting & Tunneling
    "proxychains4", "sshuttle", "socat", "stunnel4", "redsocks",
    "chisel", "netcat-traditional", "ncat", "cryptcat",
    # Forensics & Recovery
    "binwalk", "foremost", "exiftool", "steghide", "stegcracker",
    "volatility3", "autopsy", "sleuthkit", "testdisk", "photorec",
    "bulk-extractor", "scalpel", "dc3dd",
    # Utilities
    "rlwrap", "tmux", "screen", "vim", "nano", "jq", "yq",
    "tree", "htop", "ncdu", "lsof", "strace", "ltrace",
    "gdb", "radare2", "ghidra",
    # Development & Build
    "golang-go", "rustc", "cargo", "python3-pip", "pipx",
    "ruby", "ruby-dev", "ruby-bundler", "nodejs", "npm",
    "build-essential", "cmake", "make", "gcc", "g++",
    "git", "git-lfs", "p7zip-full", "unzip", "zip",
    # Networking
    "openvpn", "wireguard", "iproute2", "net-tools", "bridge-utils",
    "iptables", "nftables", "ufw",
]

PIPX_TOOLS = [
    # Active Directory & Windows
    "impacket",
    "certipy-ad",
    "bloodhound",
    "bloodhound-python",
    "bloodhound-ce-python",
    "ldapdomaindump",
    "coercer",
    "mitm6",
    "adidnsdump",
    "ldeep",
    "pypykatz",
    "bloodyAD",
    "pywerview",
    "dploot",
    "donpapi",
    "roadrecon",
    "pre2k",
    "kerbrute",
    "sprayhound",
    "crackmapexec",
    "evil-winrm",
    # Web & Recon
    "httpx",
    "nuclei",
    "subfinder",
    "waybackurls",
    "gau",
    "arjun",
    "photon",
    "dirsearch",
    "uro",
    "hakrawler",
    # Cloud & Infrastructure
    "awscli",
    "azure-cli",
    "cloudsplaining",
    "scoutsuite",
    "prowler",
    "pacu",
    # Exploitation & Post-Ex
    "pwntools",
    "ropgadget",
    "ropper",
    "pwncat-cs",
    "villain",
    "hoaxshell",
    # OSINT & Recon
    "theHarvester",
    "holehe",
    "socialscan",
    "maigret",
    "sherlock-project",
    "h8mail",
    # Password & Crypto
    "hashcrack",
    "name-that-hash",
    "stegcracker",
    # Misc Utilities
    "updog",
    "python-pptx",
    "xlrd",
    "oletools",
    "yara-python",
]

GO_TOOLS = [
    ("rustscan", "https://github.com/RustScan/RustScan/releases/latest/download/rustscan_2.3.0_amd64.deb"),
    ("nuclei", "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    ("httpx", "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    ("subfinder", "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    ("naabu", "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
    ("dnsx", "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),
    ("katana", "go install -v github.com/projectdiscovery/katana/cmd/katana@latest"),
    ("ffuf", "go install -v github.com/ffuf/ffuf/v2@latest"),
    ("gobuster", "go install -v github.com/OJ/gobuster/v3@latest"),
    ("gau", "go install -v github.com/lc/gau/v2/cmd/gau@latest"),
    ("hakrawler", "go install -v github.com/hakluke/hakrawler@latest"),
    ("waybackurls", "go install -v github.com/tomnomnom/waybackurls@latest"),
    ("assetfinder", "go install -v github.com/tomnomnom/assetfinder@latest"),
    ("httprobe", "go install -v github.com/tomnomnom/httprobe@latest"),
    ("anew", "go install -v github.com/tomnomnom/anew@latest"),
    ("qsreplace", "go install -v github.com/tomnomnom/qsreplace@latest"),
    ("dalfox", "go install -v github.com/hahwul/dalfox/v2@latest"),
    ("kxss", "go install -v github.com/Emoe/kxss@latest"),
    ("crlfuzz", "go install -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"),
    ("interactsh-client", "go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"),
]

CARGO_TOOLS = [
    "rustscan",
    "feroxbuster", 
    "ripgrep",
    "fd-find",
    "bat",
    "exa",
    "hyperfine",
]

class VoidWalker:
    def __init__(self):
        self.term_width = shutil.get_terminal_size().columns
        self.term_height = shutil.get_terminal_size().lines
        self.running = True
        self.base_path = Path.home() / "voidwalker"
        self.stats = {"ok": 0, "fail": 0}
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, sig, frame):
        self.running = False
        self.clear_screen()
        self.print_centered(f"{Colors.BRIGHT_RED}Installation interrupted!{Colors.RESET}")
        print()
        sys.exit(0)

    def clear_screen(self):
        print("\033[2J\033[H", end="")

    def hide_cursor(self):
        print("\033[?25l", end="")

    def show_cursor(self):
        print("\033[?25h", end="")

    def print_centered(self, text: str):
        import re
        clean_text = re.sub(r'\033\[[0-9;]*m', '', text)
        padding = (self.term_width - len(clean_text)) // 2
        print(" " * max(0, padding) + text)

    def typing_effect(self, text: str, delay: float = 0.02, color: str = Colors.NEON_CYAN):
        for char in text:
            print(f"{color}{char}{Colors.RESET}", end="", flush=True)
            time.sleep(delay)
        print()

    def matrix_rain(self, duration: float = 2.0):
        self.hide_cursor()
        columns = self.term_width
        drops = [random.randint(0, 20) for _ in range(columns)]
        start_time = time.time()
        
        while time.time() - start_time < duration and self.running:
            line = ""
            for i in range(columns):
                if drops[i] > 0:
                    char = random.choice(Symbols.CYBER_CHARS)
                    intensity = min(255, drops[i] * 20)
                    color = f"\033[38;2;0;{intensity};0m"
                    line += f"{color}{char}"
                    drops[i] -= 1
                    if drops[i] <= 0 and random.random() < 0.1:
                        drops[i] = random.randint(5, 20)
                else:
                    line += " "
                    if random.random() < 0.02:
                        drops[i] = random.randint(5, 20)
            print(f"{line}{Colors.RESET}")
            time.sleep(0.05)
        
        self.show_cursor()

    def draw_box(self, title: str, content: List[str], width: int = 60):
        import re
        title_colored = f"{Colors.NEON_MAGENTA}{title}{Colors.RESET}"
        
        top = f"{Colors.ELECTRIC_BLUE}{Symbols.BOX_TL}{Symbols.BOX_H * (width - 2)}{Symbols.BOX_TR}{Colors.RESET}"
        bottom = f"{Colors.ELECTRIC_BLUE}{Symbols.BOX_BL}{Symbols.BOX_H * (width - 2)}{Symbols.BOX_BR}{Colors.RESET}"
        
        self.print_centered(top)
        
        title_clean = re.sub(r'\033\[[0-9;]*m', '', title_colored)
        title_line = f"{Colors.ELECTRIC_BLUE}{Symbols.BOX_V}{Colors.RESET} {title_colored}"
        padding = width - len(title_clean) - 4
        title_line += " " * max(0, padding) + f" {Colors.ELECTRIC_BLUE}{Symbols.BOX_V}{Colors.RESET}"
        self.print_centered(title_line)
        
        separator = f"{Colors.ELECTRIC_BLUE}{Symbols.BOX_V}{Colors.GRAY}{'─' * (width - 2)}{Colors.ELECTRIC_BLUE}{Symbols.BOX_V}{Colors.RESET}"
        self.print_centered(separator)
        
        for line in content:
            clean_len = len(re.sub(r'\033\[[0-9;]*m', '', line))
            padding = width - clean_len - 4
            padded_line = f"{Colors.ELECTRIC_BLUE}{Symbols.BOX_V}{Colors.RESET} {line}" + " " * max(0, padding) + f" {Colors.ELECTRIC_BLUE}{Symbols.BOX_V}{Colors.RESET}"
            self.print_centered(padded_line)
        
        self.print_centered(bottom)

    def animated_progress_bar(self, current: int, total: int, width: int = 40, label: str = "", item_name: str = ""):
        percentage = current / total if total > 0 else 0
        filled = int(width * percentage)
        
        bar = ""
        for i in range(width):
            if i < filled:
                if i == filled - 1:
                    bar += f"{Colors.NEON_CYAN}{Symbols.BLOCK_DARK}"
                else:
                    bar += f"{Colors.NEON_GREEN}{Symbols.BLOCK_FULL}"
            else:
                bar += f"{Colors.GRAY}{Symbols.BLOCK_LIGHT}"
        
        spinner_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        spinner = spinner_chars[int(time.time() * 10) % len(spinner_chars)]
        
        item_display = f" {Colors.WHITE}{item_name[:25]:<25}{Colors.RESET}" if item_name else ""
        count_display = f"{Colors.GRAY}[{current}/{total}]{Colors.RESET}"
        
        status = f"\r{Colors.NEON_MAGENTA}{spinner}{Colors.RESET} [{bar}{Colors.RESET}] {Colors.NEON_CYAN}{percentage*100:5.1f}%{Colors.RESET} {count_display}{item_display}"
        if label:
            status = f"\r{Colors.ELECTRIC_BLUE}{label:8}{Colors.RESET} {Colors.NEON_MAGENTA}{spinner}{Colors.RESET} [{bar}{Colors.RESET}] {Colors.NEON_CYAN}{percentage*100:5.1f}%{Colors.RESET} {count_display}{item_display}"
        
        print(status + " " * 10, end="", flush=True)

    def spinner_animation(self, message: str, done_event: threading.Event):
        frames = ["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"]
        colors = [Colors.NEON_CYAN, Colors.ELECTRIC_BLUE, Colors.NEON_MAGENTA]
        i = 0
        while not done_event.is_set():
            frame = frames[i % len(frames)]
            color = colors[i % len(colors)]
            print(f"\r{color}{frame}{Colors.RESET} {Colors.NEON_CYAN}{message}{Colors.RESET}" + " " * 20, end="", flush=True)
            time.sleep(0.08)
            i += 1
        print("\r" + " " * 80 + "\r", end="")

    def show_live_status(self, category: str, current: int, total: int, item: str, status: str = "downloading"):
        spinner_chars = ["◐", "◓", "◑", "◒"]
        spinner = spinner_chars[int(time.time() * 8) % len(spinner_chars)]
        
        status_colors = {
            "downloading": Colors.YELLOW,
            "success": Colors.NEON_GREEN,
            "failed": Colors.BRIGHT_RED,
            "cloning": Colors.ELECTRIC_BLUE,
        }
        status_icons = {
            "downloading": "↓",
            "success": Symbols.CHECK,
            "failed": Symbols.CROSS,
            "cloning": "⟳",
        }
        
        color = status_colors.get(status, Colors.WHITE)
        icon = status_icons.get(status, "•")
        
        progress = f"{current}/{total}"
        bar_width = 20
        filled = int(bar_width * (current / total)) if total > 0 else 0
        bar = f"{Colors.NEON_GREEN}{'█' * filled}{Colors.GRAY}{'░' * (bar_width - filled)}{Colors.RESET}"
        
        line = f"\r  {Colors.NEON_MAGENTA}{spinner}{Colors.RESET} {Colors.ELECTRIC_BLUE}{category:18}{Colors.RESET} [{bar}] {Colors.GRAY}{progress:>7}{Colors.RESET}  {color}{icon} {item[:30]:<30}{Colors.RESET}"
        print(line + " " * 10, end="", flush=True)

    def complete_status_line(self, category: str, success: int, failed: int):
        total = success + failed
        bar_width = 20
        bar = f"{Colors.NEON_GREEN}{'█' * bar_width}{Colors.RESET}"
        
        result = f"{Colors.NEON_GREEN}{Symbols.CHECK} {success}{Colors.RESET}"
        if failed > 0:
            result += f" {Colors.BRIGHT_RED}{Symbols.CROSS} {failed}{Colors.RESET}"
        
        line = f"\r  {Colors.NEON_GREEN}{Symbols.CHECK}{Colors.RESET} {Colors.ELECTRIC_BLUE}{category:18}{Colors.RESET} [{bar}] {Colors.GRAY}{total:>3} tools{Colors.RESET}  {result}"
        print(line + " " * 20)

    def download_with_animation(self, name: str, download_func, *args) -> bool:
        done_event = threading.Event()
        result = [False]
        
        def do_download():
            result[0] = download_func(*args)
            done_event.set()
        
        download_thread = threading.Thread(target=do_download)
        download_thread.start()
        
        frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        i = 0
        while not done_event.is_set():
            frame = frames[i % len(frames)]
            color = [Colors.NEON_CYAN, Colors.ELECTRIC_BLUE, Colors.NEON_MAGENTA][i % 3]
            print(f"\r      {color}{frame}{Colors.RESET} {Colors.GRAY}{name[:50]}{Colors.RESET}" + " " * 20, end="", flush=True)
            time.sleep(0.08)
            i += 1
        
        download_thread.join()
        return result[0]

    def show_ascii_banner(self):
        banner = f"""
{Colors.NEON_CYAN}██╗   ██╗ ██████╗ ██╗██████╗ {Colors.NEON_MAGENTA}██╗    ██╗ █████╗ ██╗     ██╗  ██╗███████╗██████╗ 
{Colors.NEON_CYAN}██║   ██║██╔═══██╗██║██╔══██╗{Colors.NEON_MAGENTA}██║    ██║██╔══██╗██║     ██║ ██╔╝██╔════╝██╔══██╗
{Colors.NEON_CYAN}██║   ██║██║   ██║██║██║  ██║{Colors.NEON_MAGENTA}██║ █╗ ██║███████║██║     █████╔╝ █████╗  ██████╔╝
{Colors.NEON_CYAN}╚██╗ ██╔╝██║   ██║██║██║  ██║{Colors.NEON_MAGENTA}██║███╗██║██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
{Colors.NEON_CYAN} ╚████╔╝ ╚██████╔╝██║██████╔╝{Colors.NEON_MAGENTA}╚███╔███╔╝██║  ██║███████╗██║  ██╗███████╗██║  ██║
{Colors.NEON_CYAN}  ╚═══╝   ╚═════╝ ╚═╝╚═════╝ {Colors.NEON_MAGENTA} ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
{Colors.RESET}"""
        
        for line in banner.split('\n'):
            self.print_centered(line)
            time.sleep(0.05)
        
        subtitle = f"{Colors.ELECTRIC_BLUE}{'═' * 15} {Colors.NEON_GREEN}Elite Penetration Testing Arsenal {Colors.NEON_MAGENTA}v{__version__} {Colors.ELECTRIC_BLUE}{'═' * 15}{Colors.RESET}"
        self.print_centered(subtitle)
        print()
        
        tagline = f"{Colors.GRAY}[ {Colors.NEON_CYAN}250+ Security Tools for Ubuntu/Debian {Colors.GRAY}]{Colors.RESET}"
        self.print_centered(tagline)
        print()

    def show_skull_art(self):
        skull = f"""
{Colors.BRIGHT_RED}              ██████████████████            
{Colors.BRIGHT_RED}          ████{Colors.WHITE}░░░░░░░░░░░░░░░░{Colors.BRIGHT_RED}████        
{Colors.BRIGHT_RED}        ██{Colors.WHITE}░░░░░░░░░░░░░░░░░░░░░░{Colors.BRIGHT_RED}██      
{Colors.BRIGHT_RED}      ██{Colors.WHITE}░░░░░░░░░░░░░░░░░░░░░░░░░░{Colors.BRIGHT_RED}██    
{Colors.BRIGHT_RED}    ██{Colors.WHITE}░░░░░░{Colors.NEON_CYAN}████{Colors.WHITE}░░░░░░░░{Colors.NEON_CYAN}████{Colors.WHITE}░░░░░░{Colors.BRIGHT_RED}██  
{Colors.BRIGHT_RED}    ██{Colors.WHITE}░░░░░░{Colors.NEON_CYAN}████{Colors.WHITE}░░░░░░░░{Colors.NEON_CYAN}████{Colors.WHITE}░░░░░░{Colors.BRIGHT_RED}██  
{Colors.BRIGHT_RED}    ██{Colors.WHITE}░░░░░░░░░░░░░░░░░░░░░░░░░░░░{Colors.BRIGHT_RED}██  
{Colors.BRIGHT_RED}    ██{Colors.WHITE}░░░░░░░░░░░░{Colors.NEON_MAGENTA}████{Colors.WHITE}░░░░░░░░░░░░{Colors.BRIGHT_RED}██  
{Colors.BRIGHT_RED}      ██{Colors.WHITE}░░░░░░░░░░░░░░░░░░░░░░░░{Colors.BRIGHT_RED}██    
{Colors.BRIGHT_RED}        ██{Colors.WHITE}░░{Colors.NEON_GREEN}██{Colors.WHITE}░░{Colors.NEON_GREEN}██{Colors.WHITE}░░{Colors.NEON_GREEN}██{Colors.WHITE}░░{Colors.NEON_GREEN}██{Colors.WHITE}░░{Colors.BRIGHT_RED}██      
{Colors.BRIGHT_RED}          ████████████████████████        
{Colors.RESET}"""
        for line in skull.split('\n'):
            self.print_centered(line)
            time.sleep(0.03)

    def show_intro_animation(self):
        self.clear_screen()
        self.hide_cursor()
        self.matrix_rain(1.5)
        self.clear_screen()
        self.show_ascii_banner()
        time.sleep(0.5)
        self.show_skull_art()
        print()
        
        warnings = [
            f"{Colors.BRIGHT_RED}{Symbols.LIGHTNING} AUTHORIZED USE ONLY {Symbols.LIGHTNING}{Colors.RESET}",
            f"{Colors.YELLOW}For educational and authorized security testing purposes{Colors.RESET}",
            f"{Colors.GRAY}Requires root/sudo privileges for installation{Colors.RESET}",
        ]
        for warning in warnings:
            self.print_centered(warning)
            time.sleep(0.2)
        
        print()
        self.show_cursor()

    def show_main_menu(self) -> str:
        print()
        menu_items = [
            (f"{Symbols.ROCKET}", "Install Full Arsenal (250+ tools)", "full"),
            (f"{Symbols.GEAR}", "Select Categories", "categories"),
            (f"{Symbols.STAR}", "View All Tools", "list"),
            (f"{Symbols.CHECK}", "APT/PIPX Tools Only", "apt"),
            (f"{Symbols.DIAMOND}", "Windows Binaries Only", "windows"),
            (f"{Symbols.CROSS}", "Exit", "exit"),
        ]
        
        content = []
        for i, (icon, label, _) in enumerate(menu_items, 1):
            if i == len(menu_items):
                content.append(f"{Colors.BRIGHT_RED}[{i}] {icon} {label}{Colors.RESET}")
            else:
                content.append(f"{Colors.NEON_CYAN}[{i}] {Colors.NEON_GREEN}{icon} {Colors.WHITE}{label}{Colors.RESET}")
        
        self.draw_box(f"{Symbols.SHIELD} MAIN MENU", content, 55)
        print()
        
        while True:
            prompt = f"{Colors.NEON_MAGENTA}{Symbols.ARROW_RIGHT}{Colors.RESET} Select option {Colors.GRAY}[1-{len(menu_items)}]{Colors.RESET}: "
            try:
                choice = input(prompt).strip()
                if choice.isdigit() and 1 <= int(choice) <= len(menu_items):
                    return menu_items[int(choice) - 1][2]
                print(f"{Colors.BRIGHT_RED}Invalid option. Please try again.{Colors.RESET}")
            except EOFError:
                return "exit"

    def show_category_menu(self) -> List[str]:
        print()
        categories = list(TOOL_CATEGORIES.keys())
        content = []
        for i, cat in enumerate(categories, 1):
            desc = TOOL_CATEGORIES[cat].get("description", "")[:40]
            content.append(f"{Colors.NEON_CYAN}[{i:2}] {Colors.WHITE}{cat}{Colors.RESET}")
            content.append(f"     {Colors.GRAY}{desc}...{Colors.RESET}")
        content.append(f"{Colors.NEON_GREEN}[A ] All Categories{Colors.RESET}")
        content.append(f"{Colors.BRIGHT_RED}[B ] Back to Main Menu{Colors.RESET}")
        
        self.draw_box(f"{Symbols.GEAR} SELECT CATEGORIES", content, 60)
        print()
        
        prompt = f"{Colors.NEON_MAGENTA}{Symbols.ARROW_RIGHT}{Colors.RESET} Enter selections {Colors.GRAY}(comma-separated, e.g., 1,3,5){Colors.RESET}: "
        try:
            choice = input(prompt).strip().upper()
        except EOFError:
            return []
        
        if choice == 'B':
            return []
        if choice == 'A':
            return categories
        
        selected = []
        for part in choice.split(','):
            part = part.strip()
            if part.isdigit():
                idx = int(part) - 1
                if 0 <= idx < len(categories):
                    selected.append(categories[idx])
        
        return selected

    def show_tool_list(self):
        print()
        for category, data in TOOL_CATEGORIES.items():
            print(f"\n  {Colors.NEON_MAGENTA}{Symbols.DIAMOND} {category}{Colors.RESET}")
            print(f"  {Colors.GRAY}{'─' * 60}{Colors.RESET}")
            print(f"  {Colors.ELECTRIC_BLUE}{data.get('description', '')}{Colors.RESET}")
            
            if 'tools' in data:
                for tool in data['tools'][:5]:
                    print(f"    {Colors.NEON_CYAN}{Symbols.ARROW_RIGHT}{Colors.RESET} {Colors.WHITE}{tool[0]:20}{Colors.RESET} {Colors.GRAY}{tool[3][:35]}...{Colors.RESET}")
                if len(data['tools']) > 5:
                    print(f"    {Colors.GRAY}... and {len(data['tools']) - 5} more{Colors.RESET}")
            
            if 'repos' in data:
                print(f"    {Colors.YELLOW}+ {len(data['repos'])} Git repositories{Colors.RESET}")
        
        print()
        input(f"{Colors.GRAY}Press Enter to continue...{Colors.RESET}")

    def show_installation_preview(self, categories: List[str]) -> bool:
        self.clear_screen()
        self.show_ascii_banner()
        
        print()
        self.print_centered(f"{Colors.NEON_MAGENTA}{Symbols.ROCKET} INSTALLATION PREVIEW {Symbols.ROCKET}{Colors.RESET}")
        self.print_centered(f"{Colors.ELECTRIC_BLUE}{'─' * 50}{Colors.RESET}")
        print()
        
        total_tools = 0
        total_repos = 0
        total_files = 0
        
        for cat in categories:
            if cat in TOOL_CATEGORIES:
                data = TOOL_CATEGORIES[cat]
                total_tools += len(data.get('tools', []))
                total_repos += len(data.get('repos', []))
                total_files += len(data.get('files', []))
        
        stats_line = f"{Colors.NEON_CYAN}Categories: {len(categories)}{Colors.RESET} | "
        stats_line += f"{Colors.NEON_GREEN}Binaries: {total_tools}{Colors.RESET} | "
        stats_line += f"{Colors.YELLOW}Repos: {total_repos}{Colors.RESET} | "
        stats_line += f"{Colors.NEON_MAGENTA}Files: {total_files}{Colors.RESET}"
        self.print_centered(stats_line)
        print()
        
        for cat in categories:
            if cat not in TOOL_CATEGORIES:
                continue
            data = TOOL_CATEGORIES[cat]
            
            print(f"  {Colors.NEON_MAGENTA}{Symbols.DIAMOND} {cat}{Colors.RESET}")
            print(f"  {Colors.GRAY}{'─' * 60}{Colors.RESET}")
            
            items = []
            if 'tools' in data:
                for tool in data['tools'][:3]:
                    items.append(f"    {Colors.NEON_GREEN}{Symbols.ARROW_RIGHT}{Colors.RESET} {tool[0]} - {Colors.GRAY}{tool[3][:40]}{Colors.RESET}")
                if len(data['tools']) > 3:
                    items.append(f"    {Colors.GRAY}... +{len(data['tools']) - 3} more binaries{Colors.RESET}")
            
            if 'repos' in data:
                items.append(f"    {Colors.YELLOW}+ {len(data['repos'])} Git repos to clone{Colors.RESET}")
            
            for item in items:
                print(item)
            print()
        
        print(f"  {Colors.ELECTRIC_BLUE}{'═' * 60}{Colors.RESET}")
        print()
        
        try:
            prompt = f"{Colors.NEON_MAGENTA}{Symbols.ARROW_RIGHT}{Colors.RESET} Proceed with installation? {Colors.GRAY}[Y/n]{Colors.RESET}: "
            choice = input(prompt).strip().lower()
            return choice != 'n'
        except EOFError:
            return False

    def download_file(self, url: str, dest: Path, timeout: int = 120) -> bool:
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                with open(dest, 'wb') as f:
                    f.write(resp.read())
            if dest.suffix in ['', '.sh', '.py']:
                dest.chmod(0o755)
            return True
        except Exception:
            return False

    def download_and_extract_zip(self, url: str, dest: Path, timeout: int = 120) -> bool:
        try:
            dest.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as tmp:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    tmp.write(resp.read())
                tmp_path = tmp.name
            
            with zipfile.ZipFile(tmp_path, 'r') as zf:
                zf.extractall(dest)
            os.unlink(tmp_path)
            return True
        except Exception:
            return False

    def git_clone(self, url: str, dest: Path, timeout: int = 120) -> bool:
        try:
            if dest.exists():
                return True
            dest.parent.mkdir(parents=True, exist_ok=True)
            result = subprocess.run(
                ["git", "clone", "--depth=1", url, str(dest)],
                capture_output=True,
                timeout=timeout
            )
            return result.returncode == 0
        except Exception:
            return False

    def run_cmd(self, cmd: List[str], timeout: int = 300) -> bool:
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=timeout)
            return result.returncode == 0
        except Exception:
            return False

    def install_apt_tools(self):
        self.clear_screen()
        self.show_ascii_banner()
        
        print()
        self.print_centered(f"{Colors.NEON_MAGENTA}{Symbols.ROCKET} INSTALLING SYSTEM PACKAGES {Symbols.ROCKET}{Colors.RESET}")
        self.print_centered(f"{Colors.GRAY}{'─' * 60}{Colors.RESET}")
        print()
        
        done_event = threading.Event()
        spinner_thread = threading.Thread(
            target=self.spinner_animation,
            args=("Updating package lists...", done_event)
        )
        spinner_thread.start()
        self.run_cmd(["sudo", "apt-get", "update"])
        done_event.set()
        spinner_thread.join()
        print(f"  {Colors.NEON_GREEN}{Symbols.CHECK}{Colors.RESET} {Colors.WHITE}Package lists updated{Colors.RESET}")
        print()
        
        apt_success, apt_fail = 0, 0
        total_apt = len(APT_TOOLS)
        
        for i, tool in enumerate(APT_TOOLS, 1):
            self.show_live_status("APT Packages", i, total_apt, tool, "downloading")
            if self.run_cmd(["sudo", "apt-get", "install", "-y", tool]):
                apt_success += 1
                self.stats["ok"] += 1
            else:
                apt_fail += 1
                self.stats["fail"] += 1
        
        self.complete_status_line("APT Packages", apt_success, apt_fail)
        print()
        
        self.run_cmd(["pipx", "ensurepath"])
        
        pipx_success, pipx_fail = 0, 0
        total_pipx = len(PIPX_TOOLS)
        
        for i, tool in enumerate(PIPX_TOOLS, 1):
            self.show_live_status("PIPX Tools", i, total_pipx, tool, "downloading")
            if self.run_cmd(["pipx", "install", tool]):
                pipx_success += 1
                self.stats["ok"] += 1
            else:
                pipx_fail += 1
        
        self.complete_status_line("PIPX Tools", pipx_success, pipx_fail)
        print()
        
        go_success, go_fail = 0, 0
        total_go = len(GO_TOOLS)
        
        os.environ["GOPATH"] = str(Path.home() / "go")
        os.environ["PATH"] = os.environ.get("PATH", "") + ":" + str(Path.home() / "go" / "bin")
        
        for i, (name, cmd) in enumerate(GO_TOOLS, 1):
            self.show_live_status("Go Tools", i, total_go, name, "downloading")
            if cmd.startswith("go install"):
                if self.run_cmd(cmd.split()):
                    go_success += 1
                    self.stats["ok"] += 1
                else:
                    go_fail += 1
                    self.stats["fail"] += 1
            elif cmd.endswith(".deb"):
                deb_path = Path("/tmp") / f"{name}.deb"
                if self.download_file(cmd, deb_path):
                    self.run_cmd(["sudo", "dpkg", "-i", str(deb_path)])
                    go_success += 1
                    self.stats["ok"] += 1
                else:
                    go_fail += 1
                    self.stats["fail"] += 1
        
        self.complete_status_line("Go Tools", go_success, go_fail)
        print()
        self.show_summary()

    def install_windows_binaries(self):
        self.clear_screen()
        self.show_ascii_banner()
        
        print()
        self.print_centered(f"{Colors.NEON_MAGENTA}{Symbols.ROCKET} DOWNLOADING WINDOWS ARSENAL {Symbols.ROCKET}{Colors.RESET}")
        self.print_centered(f"{Colors.GRAY}{'─' * 60}{Colors.RESET}")
        print()
        
        tools_dir = self.base_path / "tools" / "windows"
        data = TOOL_CATEGORIES.get("Windows Binaries", {})
        tools = data.get("tools", [])
        repos = data.get("repos", [])
        
        bin_success, bin_fail = 0, 0
        total_tools = len(tools)
        
        for i, (name, method, url, desc) in enumerate(tools, 1):
            self.show_live_status("Windows Binaries", i, total_tools, name, "downloading")
            
            success = False
            if method == "file":
                success = self.download_with_animation(name, self.download_file, url, tools_dir / "precompiled" / name)
            elif method == "zip":
                success = self.download_with_animation(name, self.download_and_extract_zip, url, tools_dir / name.lower())
            elif method == "git":
                success = self.download_with_animation(name, self.git_clone, url, tools_dir / name)
            
            if success:
                bin_success += 1
                self.stats["ok"] += 1
            else:
                bin_fail += 1
                self.stats["fail"] += 1
        
        self.complete_status_line("Windows Binaries", bin_success, bin_fail)
        print()
        
        repo_success, repo_fail = 0, 0
        total_repos = len(repos)
        
        for i, (name, url) in enumerate(repos, 1):
            self.show_live_status("Git Repositories", i, total_repos, name, "cloning")
            
            if self.download_with_animation(name, self.git_clone, url, tools_dir / name):
                repo_success += 1
                self.stats["ok"] += 1
            else:
                repo_fail += 1
                self.stats["fail"] += 1
        
        self.complete_status_line("Git Repositories", repo_success, repo_fail)
        print()
        self.show_summary()

    def install_category(self, category: str):
        if category not in TOOL_CATEGORIES:
            return
        
        data = TOOL_CATEGORIES[category]
        base_dir = self.base_path / "tools"
        dest = base_dir / category.lower().replace(" ", "_").replace("&", "and")
        
        all_items = []
        if 'tools' in data:
            for item in data['tools']:
                all_items.append(('tool', item[0], item[1], item[2]))
        if 'files' in data:
            for item in data['files']:
                all_items.append(('file', item[0], 'file', item[1]))
        if 'repos' in data:
            for item in data['repos']:
                all_items.append(('repo', item[0], 'git', item[1]))
        
        if not all_items:
            return
        
        cat_success, cat_fail = 0, 0
        total_items = len(all_items)
        short_name = category[:18] if len(category) > 18 else category
        
        for i, (item_type, name, method, url) in enumerate(all_items, 1):
            status_type = "cloning" if item_type == 'repo' else "downloading"
            self.show_live_status(short_name, i, total_items, name, status_type)
            
            success = False
            if item_type == 'tool':
                if method == "file":
                    success = self.download_with_animation(name, self.download_file, url, dest / name)
                elif method == "zip":
                    success = self.download_with_animation(name, self.download_and_extract_zip, url, dest / name.lower())
                elif method == "git":
                    success = self.download_with_animation(name, self.git_clone, url, dest / name)
            elif item_type == 'file':
                success = self.download_with_animation(name, self.download_file, url, dest / name)
            elif item_type == 'repo':
                success = self.download_with_animation(name, self.git_clone, url, dest / name)
            
            if success:
                cat_success += 1
                self.stats["ok"] += 1
            else:
                cat_fail += 1
                self.stats["fail"] += 1
        
        self.complete_status_line(short_name, cat_success, cat_fail)

    def install_full_arsenal(self):
        categories = list(TOOL_CATEGORIES.keys())
        if not self.show_installation_preview(categories):
            print(f"\n{Colors.YELLOW}Installation cancelled.{Colors.RESET}")
            time.sleep(1)
            return
        
        self.clear_screen()
        self.show_ascii_banner()
        
        print()
        self.print_centered(f"{Colors.NEON_MAGENTA}{Symbols.ROCKET} FULL ARSENAL INSTALLATION {Symbols.ROCKET}{Colors.RESET}")
        print()
        
        for d in WORKSPACE_DIRS:
            (self.base_path / d).mkdir(parents=True, exist_ok=True)
        print(f"  {Colors.NEON_GREEN}{Symbols.CHECK} Workspace created at {self.base_path}{Colors.RESET}")
        
        self.install_apt_tools()
        
        for category in categories:
            self.install_category(category)
        
        print()
        self.show_summary()

    def install_categories(self, categories: List[str]):
        if not self.show_installation_preview(categories):
            print(f"\n{Colors.YELLOW}Installation cancelled.{Colors.RESET}")
            time.sleep(1)
            return
        
        self.clear_screen()
        self.show_ascii_banner()
        
        print()
        self.print_centered(f"{Colors.NEON_MAGENTA}{Symbols.ROCKET} INSTALLING SELECTED CATEGORIES {Symbols.ROCKET}{Colors.RESET}")
        print()
        
        for d in WORKSPACE_DIRS:
            (self.base_path / d).mkdir(parents=True, exist_ok=True)
        
        for category in categories:
            self.install_category(category)
        
        print()
        self.show_summary()

    def show_summary(self):
        print()
        self.print_centered(f"{Colors.NEON_MAGENTA}{'═' * 50}{Colors.RESET}")
        self.print_centered(f"{Colors.NEON_CYAN}{Symbols.STAR} INSTALLATION COMPLETE {Symbols.STAR}{Colors.RESET}")
        self.print_centered(f"{Colors.NEON_MAGENTA}{'═' * 50}{Colors.RESET}")
        print()
        
        stats = [
            f"{Colors.NEON_GREEN}{Symbols.CHECK} Successful: {self.stats['ok']}{Colors.RESET}",
            f"{Colors.BRIGHT_RED}{Symbols.CROSS} Failed: {self.stats['fail']}{Colors.RESET}",
            f"{Colors.ELECTRIC_BLUE}Tools installed to: {self.base_path}{Colors.RESET}",
        ]
        
        self.draw_box(f"{Symbols.SHIELD} SUMMARY", stats, 50)
        print()
        
        input(f"{Colors.GRAY}Press Enter to continue...{Colors.RESET}")

    def run(self):
        self.show_intro_animation()
        
        while self.running:
            choice = self.show_main_menu()
            
            if choice == "exit":
                self.clear_screen()
                self.print_centered(f"{Colors.NEON_MAGENTA}")
                self.print_centered("╔═══════════════════════════════════════════╗")
                self.print_centered("║       Thanks for using VoidWalker!        ║")
                self.print_centered("║        Stay safe, hack responsibly        ║")
                self.print_centered("╚═══════════════════════════════════════════╝")
                print(Colors.RESET)
                break
            
            elif choice == "full":
                self.install_full_arsenal()
            
            elif choice == "categories":
                selected = self.show_category_menu()
                if selected:
                    self.install_categories(selected)
            
            elif choice == "list":
                self.show_tool_list()
            
            elif choice == "apt":
                self.install_apt_tools()
            
            elif choice == "windows":
                self.install_windows_binaries()

def search_poc(query: str):
    """Search for PoC exploits on GitHub."""
    print(f"\n{Colors.NEON_MAGENTA}{'═' * 60}{Colors.RESET}")
    print(f"{Colors.NEON_CYAN}  {Symbols.LIGHTNING} VoidWalker PoC Search {Symbols.LIGHTNING}{Colors.RESET}")
    print(f"{Colors.NEON_MAGENTA}{'═' * 60}{Colors.RESET}")
    print(f"\n  {Colors.ELECTRIC_BLUE}Searching for:{Colors.RESET} {Colors.WHITE}{query}{Colors.RESET}\n")
    
    base_path = Path.home() / "voidwalker" / "tools" / "exploit_frameworks" / "PoC-in-GitHub"
    
    if not base_path.exists():
        print(f"  {Colors.YELLOW}{Symbols.CIRCLE} PoC repository not found.{Colors.RESET}")
        print(f"  {Colors.GRAY}Run VoidWalker installer first to download exploit databases.{Colors.RESET}")
        print(f"\n  {Colors.NEON_CYAN}Searching GitHub API instead...{Colors.RESET}\n")
        
        try:
            api_url = f"https://api.github.com/search/repositories?q={query}+poc+exploit&sort=updated&per_page=20"
            req = urllib.request.Request(api_url, headers={"User-Agent": "VoidWalker/3.9.2"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                
            if data.get("items"):
                print(f"  {Colors.NEON_GREEN}Found {len(data['items'])} results:{Colors.RESET}\n")
                for i, item in enumerate(data["items"][:15], 1):
                    stars = item.get("stargazers_count", 0)
                    star_color = Colors.YELLOW if stars > 100 else Colors.GRAY
                    print(f"  {Colors.NEON_CYAN}[{i:2}]{Colors.RESET} {Colors.WHITE}{item['full_name']}{Colors.RESET}")
                    print(f"      {star_color}{Symbols.STAR} {stars}{Colors.RESET} | {Colors.GRAY}{item.get('description', 'No description')[:60]}{Colors.RESET}")
                    print(f"      {Colors.ELECTRIC_BLUE}{item['html_url']}{Colors.RESET}\n")
            else:
                print(f"  {Colors.BRIGHT_RED}No results found for '{query}'{Colors.RESET}")
        except Exception as e:
            print(f"  {Colors.BRIGHT_RED}API search failed: {e}{Colors.RESET}")
        return
    
    print(f"  {Colors.NEON_GREEN}Searching local PoC database...{Colors.RESET}\n")
    
    results = []
    query_lower = query.lower()
    
    for year_dir in base_path.iterdir():
        if year_dir.is_dir() and year_dir.name.isdigit():
            for cve_dir in year_dir.iterdir():
                if query_lower in cve_dir.name.lower():
                    readme = cve_dir / "README.md"
                    if readme.exists():
                        try:
                            content = readme.read_text()[:500]
                            urls = re.findall(r'https://github\.com/[^\s\)]+', content)
                            results.append((cve_dir.name, urls[:3], str(cve_dir)))
                        except:
                            results.append((cve_dir.name, [], str(cve_dir)))
    
    if results:
        print(f"  {Colors.NEON_GREEN}Found {len(results)} matching CVEs:{Colors.RESET}\n")
        for cve, urls, path in results[:20]:
            print(f"  {Colors.NEON_CYAN}{Symbols.DIAMOND}{Colors.RESET} {Colors.WHITE}{cve}{Colors.RESET}")
            for url in urls:
                print(f"      {Colors.ELECTRIC_BLUE}{url}{Colors.RESET}")
            print(f"      {Colors.GRAY}Local: {path}{Colors.RESET}\n")
    else:
        print(f"  {Colors.YELLOW}No local results. Trying GitHub API...{Colors.RESET}\n")
        try:
            api_url = f"https://api.github.com/search/repositories?q={query}+poc+exploit&sort=updated&per_page=15"
            req = urllib.request.Request(api_url, headers={"User-Agent": "VoidWalker/3.9.2"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
            if data.get("items"):
                for item in data["items"][:10]:
                    print(f"  {Colors.NEON_CYAN}{Symbols.DIAMOND}{Colors.RESET} {Colors.WHITE}{item['full_name']}{Colors.RESET}")
                    print(f"      {Colors.ELECTRIC_BLUE}{item['html_url']}{Colors.RESET}\n")
        except:
            print(f"  {Colors.BRIGHT_RED}No results found.{Colors.RESET}")
    
    print(f"{Colors.NEON_MAGENTA}{'═' * 60}{Colors.RESET}\n")


def search_nse(query: str):
    """Search for Nmap NSE scripts."""
    print(f"\n{Colors.NEON_MAGENTA}{'═' * 60}{Colors.RESET}")
    print(f"{Colors.NEON_CYAN}  {Symbols.GEAR} VoidWalker NSE Script Search {Symbols.GEAR}{Colors.RESET}")
    print(f"{Colors.NEON_MAGENTA}{'═' * 60}{Colors.RESET}")
    print(f"\n  {Colors.ELECTRIC_BLUE}Searching for:{Colors.RESET} {Colors.WHITE}{query}{Colors.RESET}\n")
    
    nse_paths = [
        Path("/usr/share/nmap/scripts"),
        Path("/usr/local/share/nmap/scripts"),
        Path.home() / "nmap" / "scripts",
    ]
    
    nse_dir = None
    for path in nse_paths:
        if path.exists():
            nse_dir = path
            break
    
    if not nse_dir:
        print(f"  {Colors.YELLOW}{Symbols.CIRCLE} Nmap scripts directory not found.{Colors.RESET}")
        print(f"  {Colors.GRAY}Install nmap first: sudo apt install nmap{Colors.RESET}")
        print(f"\n  {Colors.NEON_CYAN}Showing common scripts for '{query}'...{Colors.RESET}\n")
        
        common_scripts = {
            "http": ["http-enum", "http-vuln-*", "http-shellshock", "http-sql-injection", "http-headers", "http-methods", "http-title", "http-robots.txt"],
            "smb": ["smb-enum-shares", "smb-enum-users", "smb-vuln-*", "smb-os-discovery", "smb-protocols", "smb2-vuln-uptime"],
            "ssh": ["ssh-brute", "ssh-auth-methods", "ssh-hostkey", "ssh2-enum-algos"],
            "ftp": ["ftp-anon", "ftp-bounce", "ftp-brute", "ftp-vuln-*"],
            "dns": ["dns-brute", "dns-zone-transfer", "dns-cache-snoop", "dns-recursion"],
            "mysql": ["mysql-brute", "mysql-enum", "mysql-vuln-*", "mysql-info"],
            "ldap": ["ldap-search", "ldap-brute", "ldap-rootdse"],
            "vuln": ["vulners", "vulscan", "smb-vuln-*", "http-vuln-*", "ssl-heartbleed", "ssl-poodle"],
            "ssl": ["ssl-cert", "ssl-enum-ciphers", "ssl-heartbleed", "ssl-poodle", "sslv2"],
            "snmp": ["snmp-brute", "snmp-info", "snmp-sysdescr", "snmp-processes"],
            "rdp": ["rdp-enum-encryption", "rdp-vuln-ms12-020", "rdp-ntlm-info"],
            "default": ["default", "discovery", "safe", "vuln", "exploit", "brute", "auth"],
        }
        
        query_lower = query.lower()
        matches = common_scripts.get(query_lower, [])
        
        if not matches:
            for cat, scripts in common_scripts.items():
                for script in scripts:
                    if query_lower in script.lower():
                        matches.append(script)
        
        if matches:
            print(f"  {Colors.NEON_GREEN}Suggested scripts:{Colors.RESET}\n")
            for script in matches[:15]:
                print(f"  {Colors.NEON_CYAN}{Symbols.ARROW_RIGHT}{Colors.RESET} {Colors.WHITE}{script}{Colors.RESET}")
            print(f"\n  {Colors.GRAY}Usage: nmap --script={matches[0]} <target>{Colors.RESET}")
        else:
            print(f"  {Colors.GRAY}Try: http, smb, ssh, ftp, dns, vuln, ssl, mysql, ldap{Colors.RESET}")
        
        print(f"\n{Colors.NEON_MAGENTA}{'═' * 60}{Colors.RESET}\n")
        return
    
    print(f"  {Colors.NEON_GREEN}Searching {nse_dir}...{Colors.RESET}\n")
    
    results = []
    query_lower = query.lower()
    
    for script in nse_dir.glob("*.nse"):
        if query_lower in script.name.lower():
            try:
                content = script.read_text()[:1000]
                desc_match = re.search(r'description\s*=\s*[\[\{]*(.*?)[\]\}]*,?\s*(?:categories|author)', content, re.DOTALL | re.IGNORECASE)
                desc = desc_match.group(1).strip()[:100] if desc_match else ""
                desc = re.sub(r'[\[\]"\'\n]', '', desc).strip()
                results.append((script.name, desc))
            except:
                results.append((script.name, ""))
    
    if results:
        print(f"  {Colors.NEON_GREEN}Found {len(results)} scripts:{Colors.RESET}\n")
        for name, desc in sorted(results)[:25]:
            print(f"  {Colors.NEON_CYAN}{Symbols.ARROW_RIGHT}{Colors.RESET} {Colors.WHITE}{name}{Colors.RESET}")
            if desc:
                print(f"      {Colors.GRAY}{desc[:70]}...{Colors.RESET}")
        
        if results:
            print(f"\n  {Colors.ELECTRIC_BLUE}Example usage:{Colors.RESET}")
            print(f"  {Colors.WHITE}nmap --script={results[0][0].replace('.nse', '')} <target>{Colors.RESET}")
    else:
        print(f"  {Colors.BRIGHT_RED}No scripts found matching '{query}'{Colors.RESET}")
        print(f"  {Colors.GRAY}Try: http, smb, ssh, ftp, dns, vuln, ssl{Colors.RESET}")
    
    print(f"\n{Colors.NEON_MAGENTA}{'═' * 60}{Colors.RESET}\n")


def search_exploitdb(query: str):
    """Search Exploit-DB for exploits."""
    print(f"\n{Colors.NEON_MAGENTA}{'═' * 60}{Colors.RESET}")
    print(f"{Colors.NEON_CYAN}  {Symbols.LIGHTNING} VoidWalker Exploit-DB Search {Symbols.LIGHTNING}{Colors.RESET}")
    print(f"{Colors.NEON_MAGENTA}{'═' * 60}{Colors.RESET}")
    print(f"\n  {Colors.ELECTRIC_BLUE}Searching for:{Colors.RESET} {Colors.WHITE}{query}{Colors.RESET}\n")
    
    local_db = Path.home() / "voidwalker" / "tools" / "exploit_frameworks" / "exploitdb"
    
    if local_db.exists():
        print(f"  {Colors.NEON_GREEN}Searching local Exploit-DB...{Colors.RESET}\n")
        try:
            result = subprocess.run(
                ["grep", "-ri", query, str(local_db / "exploits")],
                capture_output=True, text=True, timeout=30
            )
            if result.stdout:
                lines = result.stdout.strip().split('\n')[:20]
                for line in lines:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        filepath = parts[0].replace(str(local_db), "")
                        print(f"  {Colors.NEON_CYAN}{Symbols.ARROW_RIGHT}{Colors.RESET} {Colors.WHITE}{filepath}{Colors.RESET}")
                print(f"\n  {Colors.GRAY}Found {len(lines)} results (showing first 20){Colors.RESET}")
            else:
                print(f"  {Colors.YELLOW}No local results. Searching online...{Colors.RESET}")
        except:
            pass
    
    print(f"\n  {Colors.NEON_CYAN}Querying Exploit-DB API...{Colors.RESET}\n")
    
    try:
        url = f"https://exploits.shodan.io/api/search?query={urllib.parse.quote(query)}&key=public"
        alt_url = f"https://www.exploit-db.com/search?q={urllib.parse.quote(query)}"
        
        print(f"  {Colors.ELECTRIC_BLUE}Search online at:{Colors.RESET}")
        print(f"  {Colors.WHITE}https://www.exploit-db.com/search?q={query}{Colors.RESET}")
        print(f"  {Colors.WHITE}https://sploitus.com/?query={query}{Colors.RESET}")
        print(f"\n  {Colors.GRAY}Or use searchsploit locally:{Colors.RESET}")
        print(f"  {Colors.WHITE}searchsploit {query}{Colors.RESET}")
    except Exception as e:
        print(f"  {Colors.BRIGHT_RED}Search failed: {e}{Colors.RESET}")
    
    print(f"\n{Colors.NEON_MAGENTA}{'═' * 60}{Colors.RESET}\n")


def search_shodan(query: str, api_key: str = None):
    """Search Shodan for hosts."""
    print(f"\n{Colors.NEON_MAGENTA}{'═' * 60}{Colors.RESET}")
    print(f"{Colors.NEON_CYAN}  {Symbols.GEAR} VoidWalker Shodan Search {Symbols.GEAR}{Colors.RESET}")
    print(f"{Colors.NEON_MAGENTA}{'═' * 60}{Colors.RESET}")
    print(f"\n  {Colors.ELECTRIC_BLUE}Searching for:{Colors.RESET} {Colors.WHITE}{query}{Colors.RESET}\n")
    
    if not api_key:
        api_key = os.environ.get("SHODAN_API_KEY")
    
    if not api_key:
        print(f"  {Colors.YELLOW}{Symbols.CIRCLE} No Shodan API key found.{Colors.RESET}")
        print(f"\n  {Colors.GRAY}Set your API key:{Colors.RESET}")
        print(f"  {Colors.WHITE}export SHODAN_API_KEY='your-api-key'{Colors.RESET}")
        print(f"\n  {Colors.GRAY}Or get a free key at:{Colors.RESET}")
        print(f"  {Colors.ELECTRIC_BLUE}https://account.shodan.io/register{Colors.RESET}")
        print(f"\n  {Colors.NEON_CYAN}Showing common Shodan dorks...{Colors.RESET}\n")
        
        dorks = [
            ("Webcams", 'webcam has_screenshot:true'),
            ("Apache servers", 'apache country:US'),
            ("Open MongoDB", 'mongodb port:27017'),
            ("Jenkins", 'jenkins 200 ok'),
            ("Kubernetes", 'kubernetes'),
            ("RDP servers", 'port:3389 has_screenshot:true'),
            ("VNC servers", 'vnc authentication disabled'),
            ("Elastic", 'elastic port:9200'),
            ("FTP anon", 'ftp anonymous'),
            ("Default creds", '"default password"'),
        ]
        
        for name, dork in dorks:
            print(f"  {Colors.NEON_CYAN}{Symbols.ARROW_RIGHT}{Colors.RESET} {Colors.WHITE}{name}:{Colors.RESET} {Colors.GRAY}{dork}{Colors.RESET}")
        
        print(f"\n  {Colors.ELECTRIC_BLUE}Search manually at:{Colors.RESET}")
        print(f"  {Colors.WHITE}https://www.shodan.io/search?query={urllib.parse.quote(query)}{Colors.RESET}")
    else:
        try:
            api_url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query={urllib.parse.quote(query)}"
            req = urllib.request.Request(api_url, headers={"User-Agent": "VoidWalker/3.9.2"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
            
            if data.get("matches"):
                print(f"  {Colors.NEON_GREEN}Found {data.get('total', 0)} results:{Colors.RESET}\n")
                for match in data["matches"][:15]:
                    ip = match.get("ip_str", "N/A")
                    port = match.get("port", "N/A")
                    org = match.get("org", "N/A")
                    product = match.get("product", "")
                    country = match.get("location", {}).get("country_name", "")
                    
                    print(f"  {Colors.NEON_CYAN}{Symbols.DIAMOND}{Colors.RESET} {Colors.WHITE}{ip}:{port}{Colors.RESET}")
                    print(f"      {Colors.GRAY}Org: {org} | {country}{Colors.RESET}")
                    if product:
                        print(f"      {Colors.YELLOW}{product}{Colors.RESET}")
                    print()
            else:
                print(f"  {Colors.YELLOW}No results found for '{query}'{Colors.RESET}")
        except Exception as e:
            print(f"  {Colors.BRIGHT_RED}API error: {e}{Colors.RESET}")
    
    print(f"\n{Colors.NEON_MAGENTA}{'═' * 60}{Colors.RESET}\n")


def dork_generator():
    """Interactive Google Dork generator TUI."""
    print(f"\n{Colors.NEON_MAGENTA}{'═' * 70}{Colors.RESET}")
    print(f"{Colors.NEON_CYAN}  {Symbols.STAR} VoidWalker Google Dork Generator {Symbols.STAR}{Colors.RESET}")
    print(f"{Colors.NEON_MAGENTA}{'═' * 70}{Colors.RESET}\n")
    
    while True:
        print(f"  {Colors.ELECTRIC_BLUE}Select dork type:{Colors.RESET}\n")
        
        options = [
            ("1", "inurl", "Search in URL path"),
            ("2", "intext", "Search in page content"),
            ("3", "intitle", "Search in page title"),
            ("4", "filetype", "Search for file types (pdf, xls, doc, sql, log)"),
            ("5", "site", "Search within specific site"),
            ("6", "ext", "Search by file extension"),
            ("7", "cache", "View cached version"),
            ("8", "link", "Find pages linking to URL"),
            ("9", "Sensitive Files", "Pre-built dorks for sensitive files"),
            ("10", "Login Pages", "Pre-built dorks for login pages"),
            ("11", "Exposed Databases", "Pre-built dorks for databases"),
            ("12", "Config Files", "Pre-built dorks for configs"),
            ("13", "Vulnerable Servers", "Pre-built dorks for vulnerable servers"),
            ("14", "Custom Combine", "Combine multiple operators"),
            ("0", "Exit", "Return to main menu"),
        ]
        
        for num, name, desc in options:
            if num == "0":
                print(f"  {Colors.BRIGHT_RED}[{num}]{Colors.RESET} {Colors.GRAY}{desc}{Colors.RESET}")
            else:
                print(f"  {Colors.NEON_CYAN}[{num:2}]{Colors.RESET} {Colors.WHITE}{name:20}{Colors.RESET} {Colors.GRAY}{desc}{Colors.RESET}")
        
        print()
        try:
            choice = input(f"  {Colors.NEON_MAGENTA}{Symbols.ARROW_RIGHT}{Colors.RESET} Select option: ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        
        if choice == "0":
            break
        
        dork = ""
        
        if choice in ["1", "2", "3", "5", "6", "7", "8"]:
            operators = {"1": "inurl", "2": "intext", "3": "intitle", "5": "site", "6": "ext", "7": "cache", "8": "link"}
            op = operators[choice]
            try:
                keyword = input(f"  {Colors.ELECTRIC_BLUE}Enter search term for {op}:{Colors.RESET} ").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if keyword:
                dork = f'{op}:{keyword}'
        
        elif choice == "4":
            print(f"\n  {Colors.GRAY}Common file types: pdf, doc, docx, xls, xlsx, ppt, sql, log, bak, conf, xml, json, env{Colors.RESET}")
            try:
                filetype = input(f"  {Colors.ELECTRIC_BLUE}Enter file type:{Colors.RESET} ").strip()
                keyword = input(f"  {Colors.ELECTRIC_BLUE}Enter search keyword (optional):{Colors.RESET} ").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if filetype:
                dork = f'filetype:{filetype}'
                if keyword:
                    dork += f' {keyword}'
        
        elif choice == "9":
            prebuilt = [
                ('Passwords in files', 'filetype:txt intext:password'),
                ('SQL dumps', 'filetype:sql intext:"INSERT INTO"'),
                ('Environment files', 'filetype:env intext:DB_PASSWORD'),
                ('SSH keys', 'filetype:pem intext:"PRIVATE KEY"'),
                ('Backup files', 'filetype:bak | filetype:backup | filetype:old'),
                ('Log files', 'filetype:log intext:password'),
                ('Config files', 'filetype:conf | filetype:config | filetype:cfg'),
                ('Excel with passwords', 'filetype:xls intext:password'),
                ('Git exposed', 'inurl:".git" intitle:"index of"'),
                ('AWS credentials', 'filetype:json intext:aws_access_key_id'),
            ]
            print(f"\n  {Colors.NEON_GREEN}Sensitive File Dorks:{Colors.RESET}\n")
            for i, (name, d) in enumerate(prebuilt, 1):
                print(f"  {Colors.NEON_CYAN}[{i:2}]{Colors.RESET} {Colors.WHITE}{name}{Colors.RESET}")
                print(f"      {Colors.GRAY}{d}{Colors.RESET}")
            
            try:
                sel = input(f"\n  {Colors.NEON_MAGENTA}{Symbols.ARROW_RIGHT}{Colors.RESET} Select (1-{len(prebuilt)}): ").strip()
                if sel.isdigit() and 1 <= int(sel) <= len(prebuilt):
                    dork = prebuilt[int(sel)-1][1]
            except (EOFError, KeyboardInterrupt):
                continue
        
        elif choice == "10":
            prebuilt = [
                ('Admin login', 'inurl:admin inurl:login'),
                ('WordPress login', 'inurl:wp-login.php'),
                ('phpMyAdmin', 'inurl:phpmyadmin'),
                ('cPanel login', 'inurl:2082 | inurl:2083 | inurl:2086'),
                ('Webmail', 'inurl:webmail'),
                ('VPN login', 'inurl:vpn inurl:login'),
                ('Router login', 'intitle:"router" inurl:login'),
                ('FTP login', 'intitle:"index of" "ftp"'),
                ('SSH login', 'inurl:ssh inurl:login'),
                ('Citrix', 'inurl:citrix inurl:login'),
            ]
            print(f"\n  {Colors.NEON_GREEN}Login Page Dorks:{Colors.RESET}\n")
            for i, (name, d) in enumerate(prebuilt, 1):
                print(f"  {Colors.NEON_CYAN}[{i:2}]{Colors.RESET} {Colors.WHITE}{name}{Colors.RESET}")
                print(f"      {Colors.GRAY}{d}{Colors.RESET}")
            
            try:
                sel = input(f"\n  {Colors.NEON_MAGENTA}{Symbols.ARROW_RIGHT}{Colors.RESET} Select (1-{len(prebuilt)}): ").strip()
                if sel.isdigit() and 1 <= int(sel) <= len(prebuilt):
                    dork = prebuilt[int(sel)-1][1]
            except (EOFError, KeyboardInterrupt):
                continue
        
        elif choice == "11":
            prebuilt = [
                ('MongoDB exposed', 'intitle:"MongoDB" inurl:27017'),
                ('Elasticsearch', 'intitle:"elasticsearch" inurl:9200'),
                ('MySQL dumps', 'filetype:sql intext:"CREATE TABLE"'),
                ('PostgreSQL', 'inurl:5432 intext:postgres'),
                ('Redis', 'intitle:"redis" inurl:6379'),
                ('phpMyAdmin open', 'intitle:"phpMyAdmin" intext:"Welcome to phpMyAdmin"'),
                ('Adminer open', 'intitle:"Adminer" intext:"Login"'),
                ('Database backups', 'filetype:sql site:*.edu'),
                ('CouchDB', 'inurl:5984 intext:"couchdb"'),
                ('SQLite files', 'filetype:sqlite | filetype:db'),
            ]
            print(f"\n  {Colors.NEON_GREEN}Exposed Database Dorks:{Colors.RESET}\n")
            for i, (name, d) in enumerate(prebuilt, 1):
                print(f"  {Colors.NEON_CYAN}[{i:2}]{Colors.RESET} {Colors.WHITE}{name}{Colors.RESET}")
                print(f"      {Colors.GRAY}{d}{Colors.RESET}")
            
            try:
                sel = input(f"\n  {Colors.NEON_MAGENTA}{Symbols.ARROW_RIGHT}{Colors.RESET} Select (1-{len(prebuilt)}): ").strip()
                if sel.isdigit() and 1 <= int(sel) <= len(prebuilt):
                    dork = prebuilt[int(sel)-1][1]
            except (EOFError, KeyboardInterrupt):
                continue
        
        elif choice == "12":
            prebuilt = [
                ('wp-config.php', 'inurl:wp-config.php'),
                ('.htaccess', 'filetype:htaccess'),
                ('web.config', 'filetype:config inurl:web.config'),
                ('.env files', 'filetype:env'),
                ('nginx.conf', 'filetype:conf inurl:nginx'),
                ('apache conf', 'filetype:conf inurl:apache'),
                ('php.ini', 'filetype:ini inurl:php.ini'),
                ('settings.py', 'filetype:py inurl:settings'),
                ('application.yml', 'filetype:yml inurl:application'),
                ('docker-compose', 'filetype:yml inurl:docker-compose'),
            ]
            print(f"\n  {Colors.NEON_GREEN}Config File Dorks:{Colors.RESET}\n")
            for i, (name, d) in enumerate(prebuilt, 1):
                print(f"  {Colors.NEON_CYAN}[{i:2}]{Colors.RESET} {Colors.WHITE}{name}{Colors.RESET}")
                print(f"      {Colors.GRAY}{d}{Colors.RESET}")
            
            try:
                sel = input(f"\n  {Colors.NEON_MAGENTA}{Symbols.ARROW_RIGHT}{Colors.RESET} Select (1-{len(prebuilt)}): ").strip()
                if sel.isdigit() and 1 <= int(sel) <= len(prebuilt):
                    dork = prebuilt[int(sel)-1][1]
            except (EOFError, KeyboardInterrupt):
                continue
        
        elif choice == "13":
            prebuilt = [
                ('Directory listing', 'intitle:"index of /"'),
                ('Open FTP', 'intitle:"index of" inurl:ftp'),
                ('Apache default', 'intitle:"Apache2 Ubuntu Default Page"'),
                ('IIS default', 'intitle:"IIS Windows Server"'),
                ('Tomcat manager', 'inurl:manager/html intitle:tomcat'),
                ('JBoss console', 'inurl:jmx-console'),
                ('Jenkins open', 'intitle:"Dashboard [Jenkins]"'),
                ('GitLab exposed', 'inurl:gitlab intext:"sign in"'),
                ('Kibana open', 'intitle:"Kibana" inurl:app/kibana'),
                ('Grafana', 'intitle:"Grafana"'),
            ]
            print(f"\n  {Colors.NEON_GREEN}Vulnerable Server Dorks:{Colors.RESET}\n")
            for i, (name, d) in enumerate(prebuilt, 1):
                print(f"  {Colors.NEON_CYAN}[{i:2}]{Colors.RESET} {Colors.WHITE}{name}{Colors.RESET}")
                print(f"      {Colors.GRAY}{d}{Colors.RESET}")
            
            try:
                sel = input(f"\n  {Colors.NEON_MAGENTA}{Symbols.ARROW_RIGHT}{Colors.RESET} Select (1-{len(prebuilt)}): ").strip()
                if sel.isdigit() and 1 <= int(sel) <= len(prebuilt):
                    dork = prebuilt[int(sel)-1][1]
            except (EOFError, KeyboardInterrupt):
                continue
        
        elif choice == "14":
            print(f"\n  {Colors.NEON_GREEN}Custom Dork Builder{Colors.RESET}")
            print(f"  {Colors.GRAY}Combine operators. Leave blank to skip.{Colors.RESET}\n")
            
            parts = []
            try:
                site = input(f"  {Colors.ELECTRIC_BLUE}site:{Colors.RESET} ").strip()
                if site: parts.append(f"site:{site}")
                
                inurl = input(f"  {Colors.ELECTRIC_BLUE}inurl:{Colors.RESET} ").strip()
                if inurl: parts.append(f"inurl:{inurl}")
                
                intitle = input(f"  {Colors.ELECTRIC_BLUE}intitle:{Colors.RESET} ").strip()
                if intitle: parts.append(f'intitle:"{intitle}"')
                
                intext = input(f"  {Colors.ELECTRIC_BLUE}intext:{Colors.RESET} ").strip()
                if intext: parts.append(f'intext:"{intext}"')
                
                filetype = input(f"  {Colors.ELECTRIC_BLUE}filetype:{Colors.RESET} ").strip()
                if filetype: parts.append(f"filetype:{filetype}")
                
                extra = input(f"  {Colors.ELECTRIC_BLUE}Extra keywords:{Colors.RESET} ").strip()
                if extra: parts.append(extra)
            except (EOFError, KeyboardInterrupt):
                continue
            
            dork = " ".join(parts)
        
        if dork:
            encoded = urllib.parse.quote(dork)
            google_url = f"https://www.google.com/search?q={encoded}"
            
            print(f"\n  {Colors.NEON_MAGENTA}{'─' * 60}{Colors.RESET}")
            print(f"\n  {Colors.NEON_GREEN}{Symbols.CHECK} Generated Dork:{Colors.RESET}")
            print(f"\n  {Colors.WHITE}{dork}{Colors.RESET}")
            print(f"\n  {Colors.ELECTRIC_BLUE}Google URL:{Colors.RESET}")
            print(f"  {Colors.GRAY}{google_url}{Colors.RESET}")
            print(f"\n  {Colors.NEON_MAGENTA}{'─' * 60}{Colors.RESET}\n")
            
            try:
                copy = input(f"  {Colors.NEON_CYAN}Open in browser? [y/N]:{Colors.RESET} ").strip().lower()
                if copy == 'y':
                    import webbrowser
                    webbrowser.open(google_url)
            except (EOFError, KeyboardInterrupt):
                pass
        
        print()
    
    print(f"\n{Colors.NEON_MAGENTA}{'═' * 70}{Colors.RESET}\n")


def main():
    parser = argparse.ArgumentParser(
        description=f"{Colors.NEON_CYAN}VoidWalker v{__version__}{Colors.RESET} - Elite Penetration Testing Arsenal",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Colors.NEON_GREEN}Commands:{Colors.RESET}
  {Colors.WHITE}poc <CVE-ID>{Colors.RESET}       Search for PoC exploits (e.g., poc CVE-2021-1675)
  {Colors.WHITE}nse <keyword>{Colors.RESET}      Search Nmap NSE scripts (e.g., nse http, nse smb)
  {Colors.WHITE}shodan <query>{Colors.RESET}     Search Shodan (requires SHODAN_API_KEY env var)
  {Colors.WHITE}exploitdb <query>{Colors.RESET}  Search Exploit-DB
  {Colors.WHITE}dork{Colors.RESET}               Interactive Google Dork generator

{Colors.NEON_GREEN}Examples:{Colors.RESET}
  python3 voidwalker.py                    # Interactive installer menu
  python3 voidwalker.py poc CVE-2021-44228 # Search Log4Shell PoCs
  python3 voidwalker.py poc printnightmare # Search PrintNightmare
  python3 voidwalker.py nse http           # Find HTTP scripts
  python3 voidwalker.py nse vuln           # Find vulnerability scripts
  python3 voidwalker.py shodan apache      # Search Shodan for Apache servers
  python3 voidwalker.py exploitdb wordpress# Search Exploit-DB for WordPress
  python3 voidwalker.py dork               # Launch dork generator TUI
"""
    )
    
    parser.add_argument("command", nargs="?", choices=["poc", "nse", "shodan", "exploitdb", "dork"], 
                        help="Command to execute")
    parser.add_argument("query", nargs="?", help="Search query (CVE ID, keyword, etc.)")
    parser.add_argument("-v", "--version", action="version", version=f"VoidWalker v{__version__}")
    
    args = parser.parse_args()
    
    if args.command == "poc":
        if not args.query:
            print(f"{Colors.BRIGHT_RED}Error: Please provide a CVE ID or keyword{Colors.RESET}")
            print(f"{Colors.GRAY}Example: python3 voidwalker.py poc CVE-2021-1675{Colors.RESET}")
            sys.exit(1)
        search_poc(args.query)
    
    elif args.command == "nse":
        if not args.query:
            print(f"{Colors.BRIGHT_RED}Error: Please provide a search keyword{Colors.RESET}")
            print(f"{Colors.GRAY}Example: python3 voidwalker.py nse http{Colors.RESET}")
            sys.exit(1)
        search_nse(args.query)
    
    elif args.command == "shodan":
        if not args.query:
            print(f"{Colors.BRIGHT_RED}Error: Please provide a search query{Colors.RESET}")
            print(f"{Colors.GRAY}Example: python3 voidwalker.py shodan apache{Colors.RESET}")
            sys.exit(1)
        search_shodan(args.query)
    
    elif args.command == "exploitdb":
        if not args.query:
            print(f"{Colors.BRIGHT_RED}Error: Please provide a search query{Colors.RESET}")
            print(f"{Colors.GRAY}Example: python3 voidwalker.py exploitdb wordpress{Colors.RESET}")
            sys.exit(1)
        search_exploitdb(args.query)
    
    elif args.command == "dork":
        dork_generator()
    
    else:
        if os.geteuid() != 0:
            print(f"{Colors.YELLOW}Note: Some installations require sudo privileges.{Colors.RESET}")
            print(f"{Colors.GRAY}Run with 'sudo python3 voidwalker.py' for full functionality.{Colors.RESET}")
            print()
        
        installer = VoidWalker()
        installer.run()


if __name__ == "__main__":
    main()
