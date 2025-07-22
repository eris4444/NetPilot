# 🌐 NetPilot - Advanced Network Toolkit v2.0

A comprehensive and advanced tool for network analysis and management with SSH capabilities and a custom command-line interface.

## 🔗 Quick Links

- **[Tool webpage](https://tools.erisrtg.ir/netpilot.html)**
- **[GitHub Repository](https://github.com/eris4444/NetPilot)**
- **[Author Website](https://erisrtg.ir)**

---

## 📋 Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [Usage](#-usage)
- [Available Commands](#-available-commands)
- [Examples](#-examples)
- [Platform Support](#-platform-support)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [Author](#-author)
- [Support](#-support)

---

## ✨ Features

### 🔧 Network Tools
- **Ping** - Check connectivity to hosts with detailed output
- **Traceroute** - Advanced network route tracing  
- **DNS Lookup** - Resolve domain names
- **Whois** - Domain registration info using multiple APIs
- **GeoIP** - Geolocation of IP addresses
- **Public IP** - Show your public IP address

### 🔍 Scanning and Analysis
- **Port Scanner** - Multi-threaded port scanning
- **OS Detection** - Operating system detection via TTL analysis
- **Network Status** - Show active network connections

### 💬 Chat Server
- **Chat Server** - Start a multi-client server on desired port
- **Multi-client Support** - Handle multiple clients simultaneously
- **Real-time Messaging** - Instant message delivery
- **Server Commands** - Server control and message broadcasting
- **Connection Management** - Automatic client handling

### 🔐 SSH and Remote Access
- **SSH Connection** - Secure SSH access with comprehensive error handling
- **Remote Commands** - Execute shell commands on remote systems
- **Connection Testing** - Test SSH connectivity before connecting
- **Auto-cleanup** - Automatically closes connections and handles timeouts

### 🎨 User Interface
- **Colorful Interface** - Beautiful colored terminal output
- **Real-time Prompt** - Live time and connection status display
- **Cross-platform** - Full compatibility on Windows, Linux, macOS
- **Error Handling** - Robust error management and user feedback

---

## 🚀 Installation

### Prerequisites
- **Python 3.6** or higher
- **Internet connection** (for GeoIP, Whois, and other online features)

### Method 1: Debian/Ubuntu Package Installation

#### 📦 Download and Install
```bash
# Download the package
wget https://tools.erisrtg.ir/eris-netpilot.deb

# Install the package
sudo dpkg -i eris-netpilot.deb

# Fix any dependency issues
sudo apt-get install -f
```

#### 🌐 One-line Installation with wget
```bash
wget -O eris-netpilot.deb https://tools.erisrtg.ir/eris-netpilot.deb && sudo dpkg -i eris-netpilot.deb && sudo apt-get install -f
```

#### 🔄 One-line Installation with curl
```bash
curl -L -o eris-netpilot.deb https://tools.erisrtg.ir/eris-netpilot.deb && sudo dpkg -i eris-netpilot.deb && sudo apt-get install -f
```

#### 🚀 Direct Installation (Advanced)
```bash
curl -L https://tools.erisrtg.ir/eris-netpilot.deb | sudo dpkg --install /dev/stdin
```

**After Debian installation, run:**
```bash
eris-netpilot
```

### Method 2: Python Source Installation

#### Install Dependencies
```bash
# Install required Python packages
pip install colorama requests paramiko

# Or use requirements.txt if available
pip install -r requirements.txt
```

#### Download and Run
```bash
# Clone the repository
git clone https://github.com/eris4444/NetPilot
cd NetPilot

# Run the application
python netpilot.py
```

---

## 📖 Usage

### Starting NetPilot

**For Debian package installation:**
```bash
netpilot
```

**For Python installation:**
```bash
python netpilot.py
```

### Welcome Screen
```
╔═══════════════════════════════════════════════════╗
║         🌐 Advanced Network Toolkit v2.0          ║
║                      by Eris                      ║
║             visit https://erisrtg.ir              ║
╚═══════════════════════════════════════════════════╝
Connected to: localhost
OS: Linux Ubuntu 20.04
──────────────────────────────────────────────────────────────
Welcome! Type 'help' for available commands.
[13:21:41] NetPilot ➤ 
```

---

## 📝 Available Commands

### 🌐 Network Tools

#### `ping <host>`
Test connectivity to a host
```bash
ping google.com
ping 8.8.8.8
```

#### `trace <host>`
Trace network route to destination
```bash
trace google.com
trace github.com
```

#### `nslookup <domain>`
Perform DNS lookup
```bash
nslookup github.com
nslookup google.com
```

#### `whois <domain>`
Get domain registration information
```bash
whois google.com
whois github.com
```

#### `geoip <ip>`
Get geographical location of IP address
```bash
geoip 8.8.8.8
geoip 1.1.1.1
```

#### `myip`
Show your public IP address
```bash
myip
```

### 🔍 Scanning & Analysis

#### `portscan <host>`
Scan common ports on target host
```bash
portscan google.com
portscan 192.168.1.1
```

#### `osdetect <host>`
Detect operating system using TTL analysis
```bash
osdetect 8.8.8.8
osdetect google.com
```

#### `netstat`
Show active network connections
```bash
netstat
```

### 💬 Chat Server

#### `serverm -p <port>`
Start chat server on specified port
```bash
serverm -p 8080
serverm -p 9000
```

#### `stopserver`
Stop the running chat server
```bash
stopserver
```

#### `broadcast <message>`
Send message to all connected clients
```bash
broadcast Hello everyone!
broadcast Server maintenance in 5 minutes
```

#### `join <host> -p <port>`
Join an existing chat server
```bash
join localhost -p 8080
join 192.168.1.100 -p 9000
```

#### `leavechat`
Leave the current chat session
```bash
leavechat
```

### 🔐 SSH Access

#### `ssh <user@host>` or `ssh <host>`
Establish SSH connection
```bash
ssh user@192.168.1.100
ssh root@server.example.com
ssh 10.0.0.1  # Will prompt for username
```

#### `testssh <host>`
Test SSH connection availability
```bash
testssh server.example.com
testssh 192.168.1.100
```

#### `disconnect`
Disconnect current SSH session
```bash
disconnect
```

### 🎛️ System Commands

#### `clear`
Clear the terminal screen
```bash
clear
```

#### `help`
Display help information
```bash
help
```

#### `exit` or `quit`
Exit NetPilot application
```bash
exit
quit
```

---

## 💡 Usage Examples

### 🌐 Network Status Testing
```bash
# Test connectivity and get network info
ping google.com
myip
trace 8.8.8.8

# Check DNS resolution
nslookup github.com
```

### 🔍 Security Analysis
```bash
# Scan target for open ports
portscan target.com

# Detect operating system
osdetect 192.168.1.100

# Check network connections
netstat
```

### 💬 Chat Server Setup
```bash
# Start server
serverm -p 8080

# In another terminal/instance, join the server
join localhost -p 8080

# Broadcast message to all clients
broadcast Welcome to NetPilot Chat!
```

### 🔐 SSH Remote Access
```bash
# Test SSH connectivity first
testssh 192.168.1.100

# Connect via SSH
ssh user@192.168.1.100

# Run remote commands
ls -la
ps aux
df -h

# Disconnect when done
disconnect
```

### 🌍 Domain and IP Analysis
```bash
# Complete domain analysis
nslookup github.com
whois github.com
geoip 140.82.112.4

# Check your own IP location
myip
geoip [your-ip-from-myip-command]
```

---

## 🖥️ Platform Support

### 🪟 Windows
- **Full Support**: All features available
- **Native Commands**: Uses `tracert` and `ping -n`
- **SSH Support**: Full paramiko integration
- **Chat Server**: Complete functionality

### 🐧 Linux
- **Complete Support**: All native tools available
- **Package Installation**: Native .deb package available
- **SSH Integration**: Native SSH client support
- **Performance**: Optimized for Linux systems

### 🍎 macOS
- **Full Compatibility**: Unix-based command support
- **SSH Support**: Native SSH integration
- **Network Tools**: Complete toolkit available

### 📦 Debian/Ubuntu Specific
- **Native Package**: `.deb` package for easy installation
- **System Integration**: Installs to system PATH
- **Dependency Management**: Automatic dependency resolution

---

## 🔧 Troubleshooting

### Installation Issues

#### "Module not found" error
```bash
# Install required packages
pip install colorama requests paramiko

# Or install all dependencies
pip install -r requirements.txt
```

#### Debian package dependency issues
```bash
# Fix broken dependencies
sudo apt-get install -f

# Reinstall if needed
sudo dpkg --remove eris-netpilot
sudo dpkg -i eris-netpilot.deb
```

### Network Issues

#### Whois lookup problems
- Uses multiple APIs (ipwhois.app, whois.com) and local whois command as fallback
- Check internet connection if all methods fail

#### DNS resolution issues
```bash
# Test DNS servers
nslookup google.com 8.8.8.8
nslookup google.com 1.1.1.1
```

### SSH Connection Problems

#### SSH module issues
```bash
# Reinstall paramiko
pip uninstall paramiko
pip install paramiko
```

#### Connection testing
```bash
# Always test SSH before connecting
testssh hostname
testssh 192.168.1.100
```

#### Permission issues
```bash
# Run with appropriate permissions if needed
sudo netpilot  # For Debian package
sudo python netpilot.py  # For Python installation
```

### Chat Server Issues

#### Port binding problems
```bash
# Use different port if 8080 is busy
serverm -p 9000
serverm -p 8081
```

#### Connection refused
- Check firewall settings
- Ensure port is not blocked
- Verify server is running before joining

### General Issues

#### Internet connection required
- GeoIP lookup needs internet access
- Whois queries require online APIs
- Public IP detection needs external services

#### Error Color Coding
- 🔴 **Red**: Critical errors requiring attention
- 🟡 **Yellow**: Warnings and non-critical issues  
- 🟢 **Green**: Success messages and confirmations
- 🔵 **Blue**: Information and status updates

---

## 🤝 Contributing

We welcome contributions! Here's how to get started:

### Development Setup
```bash
# Fork and clone the repository
git clone https://github.com/yourusername/NetPilot
cd NetPilot

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
```

### Contribution Process
1. **Fork** the project
2. **Create** a feature branch (`git checkout -b feature/AmazingFeature`)
3. **Commit** your changes (`git commit -m 'Add some AmazingFeature'`)
4. **Push** to the branch (`git push origin feature/AmazingFeature`)
5. **Open** a Pull Request

### Feature Ideas & Roadmap

#### 🔄 Planned Features
- [ ] **DNS Enumeration** - Comprehensive DNS record scanning
- [ ] **Network Discovery** - Local network device discovery
- [ ] **Vulnerability Scanner** - Basic security vulnerability detection
- [ ] **Enhanced Logging** - Comprehensive logging system
- [ ] **Configuration File** - User preferences and settings
- [ ] **File Transfer** - Secure file transfer capabilities

#### 💬 Chat Enhancements
- [ ] **Private Messaging** - Direct user-to-user communication
- [ ] **Chat Rooms** - Multiple channel support
- [ ] **User Authentication** - Secure user login system
- [ ] **Chat History** - Message logging and history
- [ ] **Persian Language Support** - Localization support

#### 🌐 Network Enhancements  
- [ ] **Network Speed Test** - Bandwidth testing capabilities
- [ ] **Interface Information** - Network interface details
- [ ] **Advanced Port Scanning** - Service detection and banner grabbing
- [ ] **Network Monitoring** - Real-time network activity monitoring

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**Eris** - Network Security Enthusiast & Developer

- 🌐 **Website**: [erisrtg.ir](https://erisrtg.ir)
- 📧 **Contact**: Available through website
- 🛠️ **Tools Page**: [tools.erisrtg.ir](https://tools.erisrtg.ir)
- 📁 **GitHub**: [github.com/eris4444](https://github.com/eris4444)

---

## 📞 Support & Help

If you encounter any issues or need assistance:

### 📖 Documentation
1. **Read** this README thoroughly
2. **Check** the [Troubleshooting](#-troubleshooting) section
3. **Review** command examples and usage patterns

### 🐛 Issue Reporting
1. **Search** existing issues on GitHub
2. **Create** a new issue with:
   - Operating System details
   - Python version
   - Complete error message
   - Steps to reproduce the problem

### 🌐 Contact Options
1. **GitHub Issues**: [github.com/eris4444/NetPilot/issues](https://github.com/eris4444/NetPilot/issues)
2. **Website Contact**: [erisrtg.ir](https://erisrtg.ir)
3. **Tool Page**: [tools.erisrtg.ir/netpilot.html](https://tools.erisrtg.ir/netpilot.html)

---

## ⚠️ Important Notice

**Educational and Legitimate Use Only**

This tool is designed for:
- ✅ **Network administration and troubleshooting**
- ✅ **Educational purposes and learning**
- ✅ **Authorized security testing**
- ✅ **System administration tasks**

**Please use responsibly and ethically!**

---

## 🎯 Quick Start Guide

```bash
# 1. Install NetPilot (choose one method)
wget https://tools.erisrtg.ir/eris-netpilot.deb && sudo dpkg -i eris-netpilot.deb

# 2. Launch NetPilot
netpilot

# 3. Try basic commands
ping google.com
myip
help

# 4. Test advanced features
portscan google.com
serverm -p 8080

# 5. Get help anytime
help
```

**Happy Networking! 🌐**
