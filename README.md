# nullsec-netprobe

```
    ███▄    █  █    ██  ██▓     ██▓      ██████ ▓█████  ▄████▄  
    ██ ▀█   █  ██  ▓██▒▓██▒    ▓██▒    ▒██    ▒ ▓█   ▀ ▒██▀ ▀█  
   ▓██  ▀█ ██▒▓██  ▒██░▒██░    ▒██░    ░ ▓██▄   ▒███   ▒▓█    ▄ 
   ▓██▒  ▐▌██▒▓▓█  ░██░▒██░    ▒██░      ▒   ██▒▒▓█  ▄ ▒▓▓▄ ▄██▒
   ▒██░   ▓██░▒▒█████▓ ░██████▒░██████▒▒██████▒▒░▒████▒▒ ▓███▀ ░
   ░ ▒░   ▒ ▒ ░▒▓▒ ▒ ▒ ░ ▒░▓  ░░ ▒░▓  ░▒ ▒▓▒ ▒ ░░░ ▒░ ░░ ░▒ ▒  ░
   ░ ░░   ░ ▒░░░▒░ ░ ░ ░ ░ ▒  ░░ ░ ▒  ░░ ░▒  ░ ░ ░ ░  ░  ░  ▒   
      ░   ░ ░  ░░░ ░ ░   ░ ░     ░ ░   ░  ░  ░     ░   ░        
            ░                          ░    ░           ░        
   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
   █░░░░░░░░░░░░░░░░ N E T P R O B E ░░░░░░░░░░░░░░░░░░░░░░░░█
   ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
                       bad-antics
```

![Nim](https://img.shields.io/badge/Nim-FFE953?style=for-the-badge&logo=nim&logoColor=black)

## Overview

**nullsec-netprobe** is a stealthy network reconnaissance tool written in Nim. Compiles to tiny native binaries with minimal footprint, perfect for covert operations and embedded deployment.

## Features

- 🔍 **Service Detection** - Banner grabbing and version fingerprinting
- 🌐 **DNS Enumeration** - Zone transfers, subdomain brute-force
- 🎭 **Stealth Scans** - SYN, FIN, NULL, XMAS scan modes
- 📡 **ARP Discovery** - Local network mapping
- 🔐 **SSL/TLS Analysis** - Certificate inspection, cipher enumeration
- 📊 **OS Fingerprinting** - TCP/IP stack analysis

## Requirements

- Nim 2.0+
- libpcap (for raw packet operations)
- Root privileges (for raw sockets)

## Installation

```bash
git clone https://github.com/bad-antics/nullsec-netprobe.git
cd nullsec-netprobe
nim c -d:release --opt:size netprobe.nim
strip netprobe
```

## Usage

```bash
# Quick TCP scan
./netprobe scan -t 192.168.1.1 -p 1-1000

# Stealth SYN scan
./netprobe scan -t 192.168.1.0/24 -p 22,80,443 --syn

# DNS enumeration
./netprobe dns -d example.com --subdomains wordlist.txt

# ARP scan local network
./netprobe arp -i eth0

# SSL certificate analysis
./netprobe ssl -t 192.168.1.1 -p 443

# OS fingerprinting
./netprobe os -t 192.168.1.1
```

## Options

| Flag | Description |
|------|-------------|
| `-t, --target` | Target IP/hostname/CIDR |
| `-p, --ports` | Port(s) to scan |
| `-i, --interface` | Network interface |
| `--syn` | SYN stealth scan |
| `--fin` | FIN scan |
| `--null` | NULL scan |
| `--xmas` | XMAS scan |
| `-T, --timing` | Timing (0-5) |
| `-o, --output` | Output file |

## Binary Size

Nim compiles to efficient native code:
- **Debug**: ~500KB
- **Release**: ~150KB
- **Release + Strip + UPX**: ~50KB

## Disclaimer

For authorized security testing only. Unauthorized network scanning is illegal.

## License

NullSec Proprietary License

## Author

**bad-antics** - NullSec Security Team

---

*Part of the NullSec Security Toolkit*

---

[![GitHub](https://img.shields.io/badge/GitHub-bad--antics-181717?style=flat&logo=github&logoColor=white)](https://github.com/bad-antics)
[![Discord](https://img.shields.io/badge/Discord-killers-5865F2?style=flat&logo=discord&logoColor=white)](https://discord.gg/killers)
