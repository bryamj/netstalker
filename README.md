# NETSTALKER

```
███╗   ██╗███████╗████████╗███████╗████████╗ █████╗ ██╗     ██╗  ██╗███████╗██████╗
████╗  ██║██╔════╝╚══██╔══╝██╔════╝╚══██╔══╝██╔══██╗██║     ██║ ██╔╝██╔════╝██╔══██╗
██╔██╗ ██║█████╗     ██║   ███████╗   ██║   ███████║██║     █████╔╝ █████╗  ██████╔╝
██║╚██╗██║██╔══╝     ██║   ╚════██║   ██║   ██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
██║ ╚████║███████╗   ██║   ███████║   ██║   ██║  ██║███████╗██║  ██╗███████╗██║  ██║
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝

═══════════ ⚡ Cyberpunk Penetration Testing Arsenal ⚡ ══════════

[ Ethical Hacking Framework • Rose Pine Themed • v2.0 CYBER ]
```

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python" alt="Python 3.8+"/>
  <img src="https://img.shields.io/badge/Platform-Linux-green?style=for-the-badge&logo=linux" alt="Linux"/>
  <img src="https://img.shields.io/badge/License-Educational-orange?style=for-the-badge" alt="Educational"/>
  <img src="https://img.shields.io/badge/Theme-Cyberpunk-purple?style=for-the-badge" alt="Cyberpunk"/>
</p>

---

## 🌃 Overview

**NETSTALKER** is a comprehensive, cyberpunk-themed penetration testing framework designed for ethical hackers, security professionals, and CTF players. Built with a focus on automation, flexibility, and aesthetics, it combines powerful security tools with a beautiful Rose Pine color scheme and intuitive command-line interface.

### ✨ Key Features

- 🎨 **Rose Pine Cyberpunk Theme** - Beautiful terminal aesthetics inspired by neon-lit cityscapes
- ⚡ **Multiple RustScan Presets** - Fast, full, stealth, and custom scanning modes
- 🔧 **Tool-Specific CLI Arguments** - Clear, explicit command names (no generic flags)
- 📊 **Universal -oA Output** - All scans save in .nmap, .xml, and .gnmap formats
- 🎯 **Anonymous Access Testing** - Comprehensive testing for 12+ services
- 🪟 **Active Directory Enumeration** - Complete AD attack chain support
- 🌐 **Web Application Testing** - Integrated web fuzzing and vulnerability scanning
- 🛠️ **System Setup Integration** - Voidwalker installation script included
- 📁 **Organized Output Structure** - Clean, categorized scan results
- 🎮 **Dual Interface** - Both CLI arguments and interactive menus

---

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/netstalker.git
cd netstalker

# Setup your system (installs 250+ security tools)
python voidwalker.py --setup-full

# Run NETSTALKER
python netstalker.py

# Quick scan example
python netstalker.py -t 10.10.10.10 --rustscan-full --anon-all
```

---

## 📚 Table of Contents

- [Installation](#-installation)
- [RustScan Modes](#-rustscan-modes)
- [Nmap Enumeration](#-nmap-enumeration)
- [Web Application Testing](#-web-application-testing)
- [Active Directory](#-active-directory)
- [Anonymous Testing](#-anonymous-access-testing)
- [SMB/NetBIOS](#-smbnetbios-enumeration)
- [CLI Reference](#-cli-reference)
- [Output Structure](#-output-structure)
- [Workflow Examples](#-workflow-examples)
- [Theme](#-theme--customization)
- [Legal & Ethics](#%EF%B8%8F-legal--ethics)

---

## 🔧 Installation

### Prerequisites

- Operating System: Kali Linux, Ubuntu 22.04+, Debian 11+
- Python: 3.8 or higher
- Privileges: sudo access for some operations

### Quick Installation

```bash
# 1. Clone repository
git clone https://github.com/yourusername/netstalker.git
cd netstalker

# 2. Install Python dependencies
pip3 install -r requirements.txt

# 3. Run system setup (optional but recommended)
python voidwalker.py --setup-quick  # Essential tools (~10 min)
# OR
python voidwalker.py --setup-full   # All 250+ tools (~60 min)

# 4. Verify installation
python netstalker.py --check-tools
```

---

## ⚡ RustScan Modes

NETSTALKER provides **4 optimized RustScan presets** for different scenarios:

### 1. Fast Mode
```bash
python netstalker.py -t 10.10.10.10 --rustscan-fast
```
- **Ports:** Top 1000 common ports
- **Speed:** ~30 seconds
- **Use Case:** Initial reconnaissance, CTF time limits

### 2. Full Mode ⭐ DEFAULT
```bash
python netstalker.py -t 10.10.10.10 --rustscan-full
```
- **Ports:** All 65535 ports
- **Speed:** ~5-10 minutes
- **Use Case:** Comprehensive enumeration, professional pentests

### 3. Stealth Mode
```bash
python netstalker.py -t 10.10.10.10 --rustscan-stealth
```
- **Ports:** All ports, slow timing
- **Speed:** ~30-60 minutes
- **Use Case:** IDS/IPS evasion, production environments

### 4. Custom Mode
```bash
python netstalker.py -t 10.10.10.10 --rustscan-custom -- -A -oA myscan --script vuln
```
- **Custom Nmap arguments** after `--`
- **Use Case:** Maximum flexibility, specific enumeration needs

---

## 🔍 Nmap Enumeration

Tool-specific Nmap commands for targeted enumeration:

### Active Directory Scan
```bash
python netstalker.py -t 10.10.10.10 --nmap-ad
```
Runs 16 AD-specific NSE scripts for comprehensive AD enumeration.

### Web Application Scan
```bash
python netstalker.py -t 10.10.10.10 --nmap-web
```
Runs 20+ web-specific NSE scripts including vulnerability detection.

### Vulnerability Scan
```bash
python netstalker.py -t 10.10.10.10 --nmap-vuln
```
Comprehensive vulnerability scanning with all vuln scripts.

---

## 🌐 Web Application Testing

Direct tool invocation for web enumeration:

```bash
# Gobuster directory brute-force
python netstalker.py -t http://10.10.10.10 --gobuster -x php,html,txt

# ffuf fast fuzzing
python netstalker.py -t http://10.10.10.10 --ffuf -w /path/to/wordlist.txt

# Nikto web vulnerability scan
python netstalker.py -t http://10.10.10.10 --nikto

# Nuclei template-based scanning
python netstalker.py -t http://10.10.10.10 --nuclei --severity critical,high

# FeroxBuster recursive discovery
python netstalker.py -t http://10.10.10.10 --feroxbuster -x php --depth 4
```

---

## 🪟 Active Directory

Complete AD attack chain with tool-specific commands:

### AS-REP Roasting (No Authentication)
```bash
python netstalker.py -t 10.10.10.10 -d CORP.LOCAL --asreproast
python netstalker.py -t 10.10.10.10 -d CORP.LOCAL --asreproast --users users.txt
```

### Kerberoasting (Requires User)
```bash
python netstalker.py -t 10.10.10.10 -d CORP.LOCAL --kerberoast -u user -p password
```

### Secretsdump / DCSync (Requires Admin)
```bash
python netstalker.py -t 10.10.10.10 -d CORP.LOCAL --secretsdump -u admin -p password
```

### BloodHound Collection
```bash
python netstalker.py -t 10.10.10.10 -d CORP.LOCAL --bloodhound -u user -p password
```

### NetExec Hosts File Generation
```bash
python netstalker.py -t 10.10.10.10 --netexec-hosts
```

---

## 🔓 Anonymous Access Testing

Comprehensive anonymous/null session testing:

```bash
# Test all services
python netstalker.py -t 10.10.10.10 --anon-all

# Service-specific testing
python netstalker.py -t 10.10.10.10 --anon-ftp
python netstalker.py -t 10.10.10.10 --anon-smb
python netstalker.py -t 10.10.10.10 --anon-ldap
python netstalker.py -t 10.10.10.10 --anon-mysql
python netstalker.py -t 10.10.10.10 --anon-redis
python netstalker.py -t 10.10.10.10 --anon-mongo

# Combined scan + anonymous testing
python netstalker.py -t 10.10.10.10 --rustscan-full --anon-all
```

Tests: FTP, SMB, LDAP, MySQL, PostgreSQL, Redis, MongoDB, SNMP, NFS, rsync, telnet, RPC

---

## 📡 SMB/NetBIOS Enumeration

```bash
# enum4linux
python netstalker.py -t 10.10.10.10 --enum4linux -u user -p password

# SMBClient
python netstalker.py -t 10.10.10.10 --smbclient --no-pass

# NetExec SMB
python netstalker.py -t 10.10.10.10 --netexec-smb -u user -p password --spider

# RPCClient
python netstalker.py -t 10.10.10.10 --rpcclient
```

---

## 📖 CLI Reference

### RustScan Arguments

| Argument | Description | Speed | Coverage |
|----------|-------------|-------|----------|
| `--rustscan-fast` | Top 1000 ports | ~30s | Common |
| `--rustscan-full` | All 65535 ports | ~10min | Complete |
| `--rustscan-stealth` | Slow, evasive | ~60min | Complete |
| `--rustscan-custom --` | Custom args | Variable | Custom |

### Nmap Arguments

| Argument | Description |
|----------|-------------|
| `--nmap-ad` | Active Directory enumeration (16 scripts) |
| `--nmap-web` | Web application enumeration (20+ scripts) |
| `--nmap-vuln` | Vulnerability scanning |
| `--nmap-smb` | SMB enumeration |

### Web Testing Arguments

| Argument | Tool |
|----------|------|
| `--gobuster` | Directory brute-forcing |
| `--ffuf` | Fast web fuzzer |
| `--nikto` | Web vulnerability scanner |
| `--nuclei` | Template-based scanning |
| `--feroxbuster` | Recursive directory discovery |

### Active Directory Arguments

| Argument | Description | Auth |
|----------|-------------|------|
| `--asreproast` | AS-REP roasting | No |
| `--kerberoast` | Kerberoasting | User |
| `--secretsdump` | DCSync | Admin |
| `--bloodhound` | BloodHound collection | User |
| `--netexec-hosts` | Generate /etc/hosts | No |

### Anonymous Testing Arguments

| Argument | Service |
|----------|---------|
| `--anon-all` | Test all services |
| `--anon-ftp` | FTP anonymous login |
| `--anon-smb` | SMB null session |
| `--anon-ldap` | LDAP anonymous bind |
| `--anon-mysql` | MySQL no password |
| `--anon-redis` | Redis no auth |
| `--anon-mongo` | MongoDB no auth |

---

## 📁 Output Structure

```
results/
└── <target_ip>/
    ├── scans/
    │   ├── nmap_<target>_<time>.nmap   # Normal output
    │   ├── nmap_<target>_<time>.xml    # XML output
    │   └── nmap_<target>_<time>.gnmap  # Greppable output
    ├── services/
    │   ├── enum4linux_<target>.txt
    │   ├── netexec_smb_<target>.txt
    │   └── netexec_hosts_<target>.txt
    ├── ad/
    │   ├── asrep_<domain>.txt
    │   ├── kerberoast_<domain>.txt
    │   └── bloodhound_*.json
    ├── web/
    │   ├── gobuster_dir_<target>.txt
    │   ├── nuclei_<target>.txt
    │   └── nikto_<target>.txt
    └── anonymous/
        ├── ftp_anon_<target>.txt
        └── smb_anon_<target>.txt
```

**All Nmap scans use `-oA` to save in all three formats automatically.**

---

## 🔥 Workflow Examples

### HackTheBox Enumeration

```bash
# Fast initial scan
python netstalker.py -t 10.10.10.10 --rustscan-fast

# Full scan with anonymous testing
python netstalker.py -t 10.10.10.10 --rustscan-full --anon-all

# If AD detected
python netstalker.py -t 10.10.10.10 --nmap-ad
python netstalker.py -t 10.10.10.10 --netexec-hosts
python netstalker.py -t 10.10.10.10 -d HTB.LOCAL --asreproast

# If web services found
python netstalker.py -t 10.10.10.10 --nmap-web
python netstalker.py -t http://10.10.10.10 --gobuster -x php,txt
```

### Corporate Network Pentest

```bash
# Comprehensive scan
python netstalker.py -t 10.0.0.10 --rustscan-full

# AD enumeration
python netstalker.py -t 10.0.0.10 --nmap-ad
python netstalker.py -t 10.0.0.10 -d CORP.LOCAL --bloodhound -u user -p pass

# SMB enumeration
python netstalker.py -t 10.0.0.10 --netexec-smb -u user -p pass --spider
```

### Web Application Pentest

```bash
# Web-focused scan
python netstalker.py -t 10.10.10.50 --nmap-web

# Directory enumeration
python netstalker.py -t http://10.10.10.50 --gobuster -x php,html,asp

# Vulnerability scanning
python netstalker.py -t http://10.10.10.50 --nikto
python netstalker.py -t http://10.10.10.50 --nuclei --severity critical
```

---

## 🎨 Theme & Customization

### Rose Pine Color Palette

| Color | Hex | Usage |
|-------|-----|-------|
| Foam (Cyan) | #56949f | Highlights |
| Iris (Purple) | #907aa9 | Headers |
| Pine (Teal) | #286983 | Success |
| Love (Red) | #b4637a | Errors |
| Gold (Orange) | #ea9d34 | Warnings |

Customize colors in `modules/theme.py`.

---

## 🛠️ System Setup (Voidwalker)

```bash
# Quick setup (essential tools, ~10 min)
python voidwalker.py --setup-quick

# Full setup (250+ tools, ~60 min)
python voidwalker.py --setup-full
```

Includes: nmap, rustscan, netexec, gobuster, ffuf, nikto, nuclei, Impacket, BloodHound, and 240+ more tools.

---

## ⚖️ Legal & Ethics

### ⚠️ FOR AUTHORIZED SECURITY TESTING ONLY

Use of this tool for attacking targets **without prior mutual consent** is **illegal**.

### Legal Use Cases

✅ Authorized penetration testing with written permission
✅ CTF competitions (HackTheBox, TryHackMe, etc.)
✅ Security research in controlled environments
✅ Educational purposes on your own systems
✅ Bug bounty programs within scope

### Illegal Use

❌ Unauthorized access to computer systems
❌ Attacking targets without permission
❌ Violating terms of service
❌ Malicious hacking

**The authors are not responsible for any illegal use of this software.**

---

## 📊 Statistics

- **250+ Tools** in Voidwalker setup
- **16 AD NSE Scripts** in --nmap-ad
- **20+ Web NSE Scripts** in --nmap-web
- **12+ Services** for anonymous testing
- **4 RustScan Presets**
- **All 3 output formats** (.nmap, .xml, .gnmap)

---

```
╔════════════════════════════════════════════════════════════╗
║                  NETSTALKER v2.0 CYBER                     ║
║            "Jack in. Own the network. Disconnect."         ║
╚════════════════════════════════════════════════════════════╝

⚡ Cyberpunk Penetration Testing Arsenal ⚡
```

**Made with 💜 for the ethical hacking community**

**Stay legal. Stay ethical. Stay cyberpunk. 🌃**
