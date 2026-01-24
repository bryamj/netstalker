# Installation Guide

## Quick Install

```bash
git clone https://github.com/yourusername/netstalker.git
cd netstalker
python voidwalker.py --setup-full
python netstalker.py --check-tools
```

## Detailed Installation

### 1. System Requirements

**Operating Systems:**
- Kali Linux 2023.1+
- Ubuntu 22.04+
- Debian 11+

**Requirements:**
- Python 3.8 or higher
- 20GB free disk space (for full tool installation)
- sudo/root access
- Internet connection

### 2. Clone Repository

```bash
git clone https://github.com/yourusername/netstalker.git
cd netstalker
```

### 3. Install Python Dependencies

```bash
pip3 install -r requirements.txt
```

### 4. Install Security Tools

**Option A: Quick Setup (~10 minutes)**
```bash
python voidwalker.py --setup-quick
```

Installs essential tools:
- nmap, rustscan
- netexec, smbclient
- gobuster, ffuf
- Impacket suite
- Basic wordlists

**Option B: Full Setup (~60 minutes)**
```bash
python voidwalker.py --setup-full
```

Installs 250+ tools including:
- All quick setup tools
- nikto, nuclei, feroxbuster
- BloodHound, pypykatz
- Windows binaries (mimikatz, rubeus, etc.)
- Complete wordlist collections
- Post-exploitation frameworks

### 5. Verify Installation

```bash
python netstalker.py --check-tools
```

This will show which tools are installed (✓) and which are missing (✗).

## Manual Tool Installation

If you prefer manual installation:

### Core Tools (Required)

```bash
# Debian/Ubuntu/Kali
sudo apt update
sudo apt install nmap netexec smbclient rpcclient enum4linux

# RustScan
wget https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb
sudo dpkg -i rustscan_2.0.1_amd64.deb
```

### Web Tools (Recommended)

```bash
sudo apt install gobuster ffuf nikto feroxbuster

# Nuclei
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

### AD Tools (Recommended)

```bash
# Impacket
pip3 install impacket

# BloodHound
sudo apt install bloodhound

# pypykatz
pip3 install pypykatz
```

## Post-Installation

### Create Results Directory

```bash
mkdir -p results
```

### Test Your Installation

```bash
# Test RustScan
python netstalker.py -t scanme.nmap.org --rustscan-fast

# Test Nmap
python netstalker.py -t scanme.nmap.org --nmap-web

# Check anonymous testing
python netstalker.py --check-tools
```

## Troubleshooting

### RustScan Not Found

```bash
# Add to PATH
echo 'export PATH="$PATH:$HOME/.cargo/bin"' >> ~/.bashrc
source ~/.bashrc
```

### NetExec Not Found

```bash
# Install via pipx
pipx install git+https://github.com/Pennyw0rth/NetExec
```

### Permission Denied

```bash
# Some scans require sudo
sudo python netstalker.py -t <target> --rustscan-full
```

### Python Module Not Found

```bash
pip3 install -r requirements.txt --user
```

## Uninstall

```bash
# Remove NETSTALKER
rm -rf netstalker/

# Remove installed tools (optional)
# This removes tools installed by voidwalker
# Review before running!
sudo apt remove nmap rustscan netexec
pip3 uninstall impacket pypykatz
```

## Upgrading

```bash
cd netstalker
git pull origin main
python voidwalker.py --setup-quick  # Re-run setup if needed
```

## Docker Installation (Alternative)

Coming soon! Star the repo to get notified.

---

For issues, see our [GitHub Issues](https://github.com/yourusername/netstalker/issues)
