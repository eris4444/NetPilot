# 🌐 Advanced Network Toolkit v2.0

A comprehensive and advanced tool for network analysis and management with SSH capabilities and a custom command-line interface.

## 📋 Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [Usage](#-usage)
- [Available Commands](#-available-commands)
- [Examples](#-examples)
- [Platform Support](#-platform-support)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)

## ✨ Features

### 🔧 Network Tools
- **Ping** - Check connectivity to hosts with detailed output
- **Traceroute** - Advanced network route tracing
- **DNS Lookup** - Resolve domain names
- **Whois** - Domain registration info using multiple APIs
- **GeoIP** - Geolocation of IP addresses
- **Public IP** - Show your public IP

### 🔍 Scanning and Analysis
- **Port Scanner** - Multi-threaded port scanning
- **OS Detection** - OS detection via TTL
- **Network Status** - Show active connections

### 💬 Chat Server
- **Chat Server** - Start a server on a desired port
- **Multi-client** - Support for multiple clients
- **Real-time** - Instant messaging
- **Server Commands** - Server control and message broadcasting

### 🔐 SSH and Remote Access
- **SSH Connection** - Secure SSH access with error handling
- **Remote Commands** - Run remote shell commands
- **Connection Testing** - Test SSH connection beforehand
- **Auto-cleanup** - Automatically closes connections

### 🎨 UI
- **Colorful Interface** - Beautiful colored output
- **Real-time Prompt** - Time and connection status display
- **Cross-platform** - Works on Windows, Linux, macOS
- **Error Handling** - Robust error management

## 🚀 Installation

### Prerequisites
- Python 3.6 or higher
- Internet access (for some features)

### Install Dependencies

```bash
pip install colorama requests paramiko
# or using requirements.txt
pip install -r requirements.txt
```

### Download and Run

```bash
git clone https://github.com/eris4444/NetPilot
cd NetPilot
python network_toolkit.py
```

## 📖 Usage

### Initial Launch

```bash
python network_toolkit.py
```

Welcome screen will appear:
```
╔════════════════════════════════════════════════════════════╗
║          🌐 Advanced Network Toolkit v2.0                 ║
║                    by eris                                 ║
╚════════════════════════════════════════════════════════════╝
Connected to: localhost
OS: Windows 10
──────────────────────────────────────────────────────────────
Welcome! Type 'help' for available commands.
[13:21:41] NetTool ➤ 
```

## 📝 Available Commands

### 🌐 Network Tools

#### `ping <host>`
Ping a host

```bash
ping google.com
```

#### `trace <host>`
Trace route to a host

```bash
trace google.com
```

#### `nslookup <domain>`
DNS Lookup

```bash
nslookup github.com
```

#### `whois <domain>`
Domain registration info

```bash
whois google.com
```

#### `geoip <ip>`
IP Geolocation

```bash
geoip 8.8.8.8
```

#### `myip`
Show your public IP

```bash
myip
```

### 🔍 Scanning & Analysis

#### `portscan <host>`
Scan common ports

```bash
portscan google.com
```

#### `osdetect <host>`
Detect OS using TTL

```bash
osdetect 8.8.8.8
```

#### `netstat`
Show network connections

```bash
netstat
```

### 💬 Chat Server

#### `serverm -p <port>`
Start chat server

```bash
serverm -p 8080
```

#### `stopserver`
Stop chat server

```bash
stopserver
```

#### `broadcast <message>`
Send message to all clients

```bash
broadcast Hello all!
```

#### `join <host> -p <port>`
Join a chat server

```bash
join localhost -p 8080
```

#### `leavechat`
Leave the chat

```bash
leavechat
```

### 🔐 SSH Access

#### `ssh <user@host>` or `ssh <host>`
SSH Connection

```bash
ssh user@192.168.1.100
```

#### `testssh <host>`
Test SSH connection

```bash
testssh server.example.com
```

#### `disconnect`
Disconnect SSH

```bash
disconnect
```

### 🎛️ System Commands

#### `clear`
Clear the screen

```bash
clear
```

#### `help`
Show help

```bash
help
```

#### `exit` or `quit`
Exit the app

```bash
exit
```

## 💡 Examples

### Network Status

```bash
ping google.com
myip
trace 8.8.8.8
```

### Security Analysis

```bash
portscan target.com
osdetect 192.168.1.100
netstat
```

### Chat Server

```bash
serverm -p 8080
join localhost -p 8080
broadcast Hello friends!
```

### SSH Access

```bash
testssh 192.168.1.100
ssh user@192.168.1.100
ls -la
disconnect
```

### Domain Analysis

```bash
nslookup github.com
whois github.com
geoip 140.82.112.4
```

## 🖥️ Platform Support

### Windows
- Full support for all features
- Uses `tracert` and `ping -n`

### Linux
- Full support with native tools

### macOS
- Compatible with Unix-based commands

## 🔧 Troubleshooting

### "Module not found" error

```bash
pip install colorama requests paramiko
```

### Whois issues
- Uses multiple APIs and local command as fallback

### SSH issues

```bash
pip install paramiko
testssh hostname
```

### Internet connection required
- Some features need internet access

### Error Logging
- 🔴 Red: Critical errors
- 🟡 Yellow: Warnings
- 🟢 Green: Success
- 🔵 Blue: Info

## 🤝 Contributing

1. Fork the project
2. Create a new branch
3. Commit your changes
4. Push to your branch
5. Create a Pull Request

### Feature Ideas

- [ ] DNS enumeration
- [ ] Network discovery
- [ ] Vulnerability scanner
- [ ] Logging system
- [ ] Config file
- [ ] File transfer
- [ ] Private messaging
- [ ] Chat rooms
- [ ] User authentication
- [ ] Chat logging
- [ ] Persian language support
- [ ] Network speed test
- [ ] DNS server switcher
- [ ] MAC address lookup
- [ ] Interface info

## 📄 License

This project is licensed under the MIT License.

## 👨‍💻 Author

**Eris** - [erisrtg.ir](https://erisrtg.ir)

---

## 📞 Support

If you have any issues:

1. Check the [Troubleshooting](#troubleshooting) section
2. Open an issue on GitHub
3. Contact via [erisrtg.ir](https://erisrtg.ir)

---

**Note**: This tool is for educational and network testing purposes. Use it responsibly.
