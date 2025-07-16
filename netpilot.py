import colorama
import requests
import socket
import os
import platform
import threading
import time
import subprocess
import sys
import shlex
from datetime import datetime
import json

colorama.init()

class NetworkToolkit:
    def __init__(self):
        self.ssh_client = None
        self.ssh_connected = False
        self.current_host = "localhost"
        self.print_lock = threading.Lock()
        self.chat_connected = False
        self.server_running = False
        self.chat_clients = []
        self.chat_names = {}
        
    def clear(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def banner(self):
        print(colorama.Fore.CYAN + "╔" + "═"*60 + "╗")
        print(colorama.Fore.CYAN + "║" + colorama.Fore.YELLOW + "          🌐 Advanced Network Toolkit v2.0                  " + colorama.Fore.CYAN + "║")
        print(colorama.Fore.CYAN + "║" + colorama.Fore.GREEN + "                    by Eris                                 " + colorama.Fore.CYAN + "║")
        print(colorama.Fore.CYAN + "║" + colorama.Fore.WHITE + "              Visit https://erisrtg.ir                      " + colorama.Fore.CYAN + "║")

        print(colorama.Fore.CYAN + "╚" + "═"*60 + "╝")
        print(colorama.Fore.BLUE + f"Connected to: {self.current_host}")
        print(colorama.Fore.MAGENTA + f"OS: {platform.system()} {platform.release()}")
        print(colorama.Fore.CYAN + "─" * 62 + "\n")

    def show_help(self):
        help_text = f"""
{colorama.Fore.YELLOW}Available Commands:{colorama.Fore.RESET}

{colorama.Fore.GREEN}Network Utilities:{colorama.Fore.RESET}
  ping <host>           - Ping a host
  trace <host>          - Traceroute to host
  nslookup <domain>     - DNS lookup
  whois <domain>        - Whois information
  geoip <ip>            - Geographic IP information
  myip                  - Show your public IP
  
{colorama.Fore.GREEN}Scanning & Analysis:{colorama.Fore.RESET}
  portscan <host>       - Scan common ports
  osdetect <host>       - Detect remote OS
  netstat               - Show network connections
  
{colorama.Fore.GREEN}Chat Server:{colorama.Fore.RESET}
  serverm -p <port>     - Start chat server on port
  stopserver            - Stop chat server
  broadcast <msg>       - Send server message to all clients
  
{colorama.Fore.GREEN}Chat Client:{colorama.Fore.RESET}
  join <host> -p <port> - Join chat server
  leavechat             - Leave chat server
  
{colorama.Fore.GREEN}SSH & Remote:{colorama.Fore.RESET}
  ssh <user@host>       - Connect via SSH
  disconnect            - Disconnect SSH
  testssh <host>        - Test SSH connectivity
  
{colorama.Fore.GREEN}System Commands:{colorama.Fore.RESET}
  clear                 - Clear screen
  help                  - Show this help
  exit                  - Exit program
  
{colorama.Fore.GREEN}Examples:{colorama.Fore.RESET}
  ping google.com
  trace 8.8.8.8
  whois github.com
  serverm -p 8080
  join 192.168.1.100 -p 8080
  ssh user@192.168.1.100
        """
        print(help_text)

    def ping(self, host):
        if not host:
            print(colorama.Fore.RED + "Usage: ping <host>")
            return
        
        print(colorama.Fore.YELLOW + f"Pinging {host}...")
        try:
            if os.name == 'nt':
                result = subprocess.run(['ping', '-n', '4', host], 
                                      capture_output=True, text=True, timeout=10)
            else:
                result = subprocess.run(['ping', '-c', '4', host], 
                                      capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                print(colorama.Fore.GREEN + result.stdout)
            else:
                print(colorama.Fore.RED + f"Ping failed: {result.stderr}")
        except subprocess.TimeoutExpired:
            print(colorama.Fore.RED + "Ping timeout")
        except Exception as e:
            print(colorama.Fore.RED + f"Error: {str(e)}")

    def traceroute(self, host):
        if not host:
            print(colorama.Fore.RED + "Usage: trace <host>")
            return
            
        print(colorama.Fore.YELLOW + f"Tracing route to {host}...")
        try:
            if os.name == 'nt':
                result = subprocess.run(['tracert', host], 
                                      capture_output=True, text=True, timeout=120)
            else:
                result = subprocess.run(['traceroute', host], 
                                      capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                print(colorama.Fore.GREEN + result.stdout)
            else:
                print(colorama.Fore.RED + f"Traceroute failed: {result.stderr}")
        except subprocess.TimeoutExpired:
            print(colorama.Fore.RED + "Traceroute timeout - Host may be very far or unreachable")
        except Exception as e:
            print(colorama.Fore.RED + f"Error: {str(e)}")

    def nslookup(self, domain):
        if not domain:
            print(colorama.Fore.RED + "Usage: nslookup <domain>")
            return
            
        print(colorama.Fore.YELLOW + f"DNS lookup for {domain}...")
        try:
            result = subprocess.run(['nslookup', domain], 
                                  capture_output=True, text=True, timeout=10)
            print(colorama.Fore.GREEN + result.stdout)
            if result.stderr:
                print(colorama.Fore.YELLOW + result.stderr)
        except Exception as e:
            print(colorama.Fore.RED + f"Error: {str(e)}")

    def whois(self, domain):
        if not domain:
            print(colorama.Fore.RED + "Usage: whois <domain>")
            return
            
        print(colorama.Fore.YELLOW + f"Whois lookup for {domain}...")
        
        # Method 1: Try local whois command first (most reliable)
        try:
            if os.name != 'nt':  # Linux/macOS
                result = subprocess.run(['whois', domain], 
                                      capture_output=True, text=True, timeout=15)
                if result.returncode == 0 and result.stdout.strip():
                    print(colorama.Fore.GREEN + result.stdout)
                    return
                else:
                    print(colorama.Fore.YELLOW + "Local whois command failed, trying online APIs...")
            else:
                print(colorama.Fore.YELLOW + "Windows detected, using online whois APIs...")
        except FileNotFoundError:
            print(colorama.Fore.YELLOW + "Local whois not found, trying online APIs...")
        except Exception:
            print(colorama.Fore.YELLOW + "Local whois failed, trying online APIs...")

        # Method 2: Try multiple online APIs
        apis = [
            {
                'name': 'whois.freeapi.app',
                'url': f'https://whois.freeapi.app/api/whois?domainName={domain}',
                'parser': self._parse_freeapi_whois
            },
            {
                'name': 'api.whoisjson.com',
                'url': f'https://api.whoisjson.com/v1/{domain}',
                'parser': self._parse_whoisjson
            },
            {
                'name': 'whoisjsonapi.com',
                'url': f'https://whoisjsonapi.com/v1/{domain}',
                'parser': self._parse_whoisjson
            }
        ]
        
        for api in apis:
            try:
                print(colorama.Fore.CYAN + f"Trying {api['name']}...")
                response = requests.get(api['url'], timeout=10)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if api['parser'](data):
                            return
                    except json.JSONDecodeError:
                        # If not JSON, try as plain text
                        if response.text.strip():
                            print(colorama.Fore.GREEN + response.text)
                            return
                        
            except requests.exceptions.RequestException as e:
                print(colorama.Fore.YELLOW + f"{api['name']} failed: {str(e)}")
                continue
            except Exception as e:
                print(colorama.Fore.YELLOW + f"{api['name']} error: {str(e)}")
                continue
        
        # Method 3: Try basic socket-based whois
        try:
            print(colorama.Fore.CYAN + "Trying direct whois server connection...")
            whois_result = self._socket_whois(domain)
            if whois_result:
                print(colorama.Fore.GREEN + whois_result)
                return
        except Exception as e:
            print(colorama.Fore.YELLOW + f"Socket whois failed: {str(e)}")
        
        print(colorama.Fore.RED + "All whois methods failed. Domain may not exist or whois servers are unreachable.")

    def _parse_freeapi_whois(self, data):
        """Parse whois data from freeapi.app"""
        try:
            if data.get('success') and data.get('data'):
                whois_data = data['data']
                print(colorama.Fore.GREEN + f"Domain: {whois_data.get('domain_name', 'N/A')}")
                print(colorama.Fore.GREEN + f"Registrar: {whois_data.get('registrar', 'N/A')}")
                print(colorama.Fore.GREEN + f"Creation Date: {whois_data.get('creation_date', 'N/A')}")
                print(colorama.Fore.GREEN + f"Expiration Date: {whois_data.get('expiration_date', 'N/A')}")
                print(colorama.Fore.GREEN + f"Status: {whois_data.get('status', 'N/A')}")
                
                if whois_data.get('name_servers'):
                    print(colorama.Fore.GREEN + f"Name Servers: {', '.join(whois_data['name_servers'])}")
                
                return True
        except Exception:
            pass
        return False

    def _parse_whoisjson(self, data):
        """Parse whois data from whoisjson APIs"""
        try:
            if isinstance(data, dict) and not data.get('error'):
                print(colorama.Fore.GREEN + f"Domain: {data.get('domain', 'N/A')}")
                print(colorama.Fore.GREEN + f"Registrar: {data.get('registrar', 'N/A')}")
                print(colorama.Fore.GREEN + f"Creation Date: {data.get('created_date', data.get('creation_date', 'N/A'))}")
                print(colorama.Fore.GREEN + f"Expiration Date: {data.get('expires_date', data.get('expiration_date', 'N/A'))}")
                print(colorama.Fore.GREEN + f"Status: {data.get('status', 'N/A')}")
                
                if data.get('name_servers'):
                    ns = data['name_servers']
                    if isinstance(ns, list):
                        print(colorama.Fore.GREEN + f"Name Servers: {', '.join(ns)}")
                    else:
                        print(colorama.Fore.GREEN + f"Name Servers: {ns}")
                
                return True
        except Exception:
            pass
        return False

    def _socket_whois(self, domain):
        """Direct socket connection to whois server"""
        try:
            # Determine whois server based on TLD
            tld = domain.split('.')[-1].lower()
            whois_servers = {
                'com': 'whois.verisign-grs.com',
                'net': 'whois.verisign-grs.com',
                'org': 'whois.pir.org',
                'info': 'whois.afilias.net',
                'biz': 'whois.neulevel.biz',
                'us': 'whois.nic.us',
                'uk': 'whois.nic.uk',
                'de': 'whois.denic.de',
                'fr': 'whois.afnic.fr',
                'it': 'whois.nic.it',
                'ru': 'whois.tcinet.ru',
                'ir': 'whois.nic.ir',
            }
            
            whois_server = whois_servers.get(tld, 'whois.iana.org')
            
            # Connect to whois server
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((whois_server, 43))
            sock.send(f"{domain}\r\n".encode())
            
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            
            sock.close()
            return response.decode('utf-8', errors='ignore')
            
        except Exception:
            return None

    def geoip(self, ip):
        if not ip:
            print(colorama.Fore.RED + "Usage: geoip <ip>")
            return
            
        print(colorama.Fore.YELLOW + f"Geographic lookup for {ip}...")
        
        # Try multiple GeoIP APIs
        apis = [
            f"http://ip-api.com/json/{ip}",
            f"https://ipapi.co/{ip}/json/",
            f"https://ipinfo.io/{ip}/json"
        ]
        
        for api_url in apis:
            try:
                response = requests.get(api_url, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    
                    # Parse ip-api.com response
                    if 'status' in data and data.get('status') == 'success':
                        print(colorama.Fore.GREEN + f"IP: {data.get('query')}")
                        print(colorama.Fore.GREEN + f"Country: {data.get('country')} ({data.get('countryCode')})")
                        print(colorama.Fore.GREEN + f"Region: {data.get('regionName')}")
                        print(colorama.Fore.GREEN + f"City: {data.get('city')}")
                        print(colorama.Fore.GREEN + f"ZIP: {data.get('zip')}")
                        print(colorama.Fore.GREEN + f"ISP: {data.get('isp')}")
                        print(colorama.Fore.GREEN + f"Organization: {data.get('org')}")
                        print(colorama.Fore.GREEN + f"Timezone: {data.get('timezone')}")
                        lat, lon = data.get('lat'), data.get('lon')
                        if lat and lon:
                            print(colorama.Fore.BLUE + f"Location: {lat}, {lon}")
                            print(colorama.Fore.BLUE + f"Google Maps: https://www.google.com/maps/search/?api=1&query={lat},{lon}")
                        return
                    
                    # Parse ipapi.co response
                    elif 'country_name' in data:
                        print(colorama.Fore.GREEN + f"IP: {data.get('ip')}")
                        print(colorama.Fore.GREEN + f"Country: {data.get('country_name')} ({data.get('country')})")
                        print(colorama.Fore.GREEN + f"Region: {data.get('region')}")
                        print(colorama.Fore.GREEN + f"City: {data.get('city')}")
                        print(colorama.Fore.GREEN + f"ZIP: {data.get('postal')}")
                        print(colorama.Fore.GREEN + f"ISP: {data.get('org')}")
                        print(colorama.Fore.GREEN + f"Timezone: {data.get('timezone')}")
                        lat, lon = data.get('latitude'), data.get('longitude')
                        if lat and lon:
                            print(colorama.Fore.BLUE + f"Location: {lat}, {lon}")
                            print(colorama.Fore.BLUE + f"Google Maps: https://www.google.com/maps/search/?api=1&query={lat},{lon}")
                        return
                    
                    # Parse ipinfo.io response
                    elif 'country' in data:
                        print(colorama.Fore.GREEN + f"IP: {data.get('ip')}")
                        print(colorama.Fore.GREEN + f"Country: {data.get('country')}")
                        print(colorama.Fore.GREEN + f"Region: {data.get('region')}")
                        print(colorama.Fore.GREEN + f"City: {data.get('city')}")
                        print(colorama.Fore.GREEN + f"ZIP: {data.get('postal')}")
                        print(colorama.Fore.GREEN + f"Organization: {data.get('org')}")
                        print(colorama.Fore.GREEN + f"Timezone: {data.get('timezone')}")
                        if data.get('loc'):
                            lat, lon = data['loc'].split(',')
                            print(colorama.Fore.BLUE + f"Location: {lat}, {lon}")
                            print(colorama.Fore.BLUE + f"Google Maps: https://www.google.com/maps/search/?api=1&query={lat},{lon}")
                        return
                        
            except Exception as e:
                continue
        
        print(colorama.Fore.RED + "All GeoIP services failed")

    def get_public_ip(self):
        print(colorama.Fore.YELLOW + "Getting your public IP...")
        
        # Try multiple IP detection services
        services = [
            "https://api.ipify.org?format=json",
            "https://httpbin.org/ip",
            "https://ipinfo.io/json",
            "https://api.myip.com"
        ]
        
        for service in services:
            try:
                response = requests.get(service, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    
                    # Extract IP from different response formats
                    ip = data.get('ip') or data.get('origin') or data.get('query')
                    
                    if ip:
                        print(colorama.Fore.GREEN + f"Your Public IP: {ip}")
                        # Also get geo info for your IP
                        self.geoip(ip)
                        return
                        
            except Exception:
                continue
        
        print(colorama.Fore.RED + "Could not retrieve public IP from any service")

    def port_scanner(self, target):
        if not target:
            print(colorama.Fore.RED + "Usage: portscan <host>")
            return
            
        print(colorama.Fore.YELLOW + f"Scanning ports on {target}...")
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 587, 993, 995, 3306, 3389, 5432, 8080, 8443]
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "Unknown"
                    with self.print_lock:
                        print(colorama.Fore.GREEN + f"  Port {port:5d} - OPEN  [{service}]")
                    open_ports.append(port)
                sock.close()
            except:
                pass

        threads = []
        for port in common_ports:
            thread = threading.Thread(target=scan_port, args=(port,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        if not open_ports:
            print(colorama.Fore.RED + "No open ports found")
        else:
            print(colorama.Fore.CYAN + f"\nFound {len(open_ports)} open ports")

    def detect_os(self, ip):
        if not ip:
            print(colorama.Fore.RED + "Usage: osdetect <ip>")
            return
            
        print(colorama.Fore.YELLOW + f"Detecting OS for {ip}...")
        try:
            if os.name == 'nt':
                result = subprocess.run(['ping', '-n', '1', ip], 
                                      capture_output=True, text=True, timeout=10)
            else:
                result = subprocess.run(['ping', '-c', '1', ip], 
                                      capture_output=True, text=True, timeout=10)
            
            ttl = None
            for line in result.stdout.splitlines():
                if "TTL=" in line.upper() or "TTL " in line.upper():
                    try:
                        if "TTL=" in line.upper():
                            ttl_str = [s for s in line.upper().split() if "TTL=" in s][0]
                            ttl = int(ttl_str.split('=')[1])
                        else:
                            # For Linux ping output
                            parts = line.split()
                            for i, part in enumerate(parts):
                                if "ttl" in part.lower() and i + 1 < len(parts):
                                    ttl = int(parts[i + 1])
                                    break
                        break
                    except:
                        continue
            
            if ttl:
                if ttl <= 64:
                    print(colorama.Fore.GREEN + f"Likely OS: Linux/Unix/macOS (TTL={ttl})")
                elif ttl <= 128:
                    print(colorama.Fore.GREEN + f"Likely OS: Windows (TTL={ttl})")
                elif ttl <= 255:
                    print(colorama.Fore.GREEN + f"Likely OS: Cisco/Network Device (TTL={ttl})")
                else:
                    print(colorama.Fore.YELLOW + f"Unknown OS pattern (TTL={ttl})")
            else:
                print(colorama.Fore.RED + "Could not determine TTL - host may be unreachable")
        except Exception as e:
            print(colorama.Fore.RED + f"Error: {str(e)}")

    def netstat(self):
        print(colorama.Fore.YELLOW + "Network connections:")
        try:
            if os.name == 'nt':
                result = subprocess.run(['netstat', '-an'], 
                                      capture_output=True, text=True, timeout=30)
            else:
                result = subprocess.run(['netstat', '-tuln'], 
                                      capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                lines = result.stdout.splitlines()
                for line in lines[:20]:  # Show first 20 lines
                    if "LISTEN" in line or "ESTABLISHED" in line:
                        print(colorama.Fore.GREEN + line)
                    else:
                        print(colorama.Fore.CYAN + line)
                if len(lines) > 20:
                    print(colorama.Fore.YELLOW + f"... and {len(lines) - 20} more lines")
            else:
                print(colorama.Fore.RED + f"Netstat failed: {result.stderr}")
        except Exception as e:
            print(colorama.Fore.RED + f"Error: {str(e)}")

    def test_ssh(self, host):
        """Test SSH connectivity to a host"""
        if not host:
            print(colorama.Fore.RED + "Usage: testssh <host>")
            return
            
        print(colorama.Fore.YELLOW + f"Testing SSH connectivity to {host}...")
        
        try:
            # Test port 22
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(60)
            result = sock.connect_ex((host, 22))
            sock.close()
            
            if result == 0:
                print(colorama.Fore.GREEN + f"✅ SSH port (22) is open on {host}")
                
                # Try to get SSH banner
                try:
                    import paramiko
                    transport = paramiko.Transport((host, 22))
                    transport.start_client(timeout=60)
                    banner = transport.remote_version
                    print(colorama.Fore.CYAN + f"SSH Banner: {banner}")
                    transport.close()
                except Exception as e:
                    print(colorama.Fore.YELLOW + f"Could not get SSH banner: {str(e)}")
                    
            else:
                print(colorama.Fore.RED + f"❌ SSH port (22) is closed or filtered on {host}")
                
        except socket.gaierror:
            print(colorama.Fore.RED + f"❌ Cannot resolve hostname: {host}")
        except Exception as e:
            print(colorama.Fore.RED + f"Error testing SSH: {str(e)}")

    def ssh_connect(self, connection_string):
        if not connection_string:
            print(colorama.Fore.RED + "Usage: ssh <user@host> or ssh <host>")
            return
            
        try:
            # Try to import paramiko
            import paramiko
            
            if '@' in connection_string:
                username, hostname = connection_string.split('@', 1)
            else:
                username = input(colorama.Fore.YELLOW + "Username: ")
                hostname = connection_string
            
            # First test if host is reachable
            print(colorama.Fore.YELLOW + f"Testing connection to {hostname}...")
            try:
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_socket.settimeout(60)
                result = test_socket.connect_ex((hostname, 22))
                test_socket.close()
                
                if result != 0:
                    print(colorama.Fore.RED + f"Cannot reach {hostname}:22 - Host may be down or SSH service not running")
                    return
            except Exception as e:
                print(colorama.Fore.RED + f"Network error: {str(e)}")
                return
            
            password = input(colorama.Fore.YELLOW + f"Password for {username}@{hostname}: ")
            
            print(colorama.Fore.YELLOW + f"Connecting to {hostname}...")
            
            # Clean up any existing connection
            if hasattr(self, 'ssh_client') and self.ssh_client:
                try:
                    self.ssh_client.close()
                except:
                    pass
            
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Try connection with better error handling
            try:
                self.ssh_client.connect(
                    hostname=hostname, 
                    username=username, 
                    password=password, 
                    timeout=60,
                    banner_timeout=60,
                    auth_timeout=60,
                    look_for_keys=False,
                    allow_agent=False
                )
                
                self.ssh_connected = True
                self.current_host = f"{username}@{hostname}"
                print(colorama.Fore.GREEN + f"✅ Successfully connected to {hostname}")
                
            except paramiko.AuthenticationException:
                print(colorama.Fore.RED + "❌ Authentication failed - Invalid username or password")
            except paramiko.SSHException as e:
                print(colorama.Fore.RED + f"❌ SSH connection error: {str(e)}")
            except socket.timeout:
                print(colorama.Fore.RED + "❌ Connection timeout - Host may be slow or unreachable")
            except socket.gaierror:
                print(colorama.Fore.RED + f"❌ Cannot resolve hostname: {hostname}")
            except ConnectionRefusedError:
                print(colorama.Fore.RED + f"❌ Connection refused - SSH service may not be running on {hostname}")
            except Exception as e:
                print(colorama.Fore.RED + f"❌ Connection failed: {str(e)}")
                
        except ImportError:
            print(colorama.Fore.RED + "SSH functionality requires paramiko. Install with: pip install paramiko")
        except KeyboardInterrupt:
            print(colorama.Fore.YELLOW + "\nConnection cancelled by user")
        except Exception as e:
            print(colorama.Fore.RED + f"Unexpected error: {str(e)}")
        finally:
            # Clean up on failure
            if not getattr(self, 'ssh_connected', False):
                if hasattr(self, 'ssh_client') and self.ssh_client:
                    try:
                        self.ssh_client.close()
                    except:
                        pass
                    self.ssh_client = None

    def ssh_disconnect(self):
        if self.ssh_client:
            self.ssh_client.close()
            self.ssh_client = None
            self.ssh_connected = False
            self.current_host = "localhost"
            print(colorama.Fore.GREEN + "SSH connection closed")
        else:
            print(colorama.Fore.YELLOW + "No active SSH connection")

    def execute_ssh_command(self, command):
        if not self.ssh_connected or not self.ssh_client:
            print(colorama.Fore.RED + "No active SSH connection")
            return
            
        try:
            stdin, stdout, stderr = self.ssh_client.exec_command(command)
            output = stdout.read().decode()
            error = stderr.read().decode()
            
            if output:
                print(colorama.Fore.GREEN + output)
            if error:
                print(colorama.Fore.RED + error)
                
        except Exception as e:
            print(colorama.Fore.RED + f"SSH command failed: {str(e)}")

    def start_chat_server(self, port=8080):
        """Start a chat server on specified port"""
        try:
            self.chat_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.chat_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.chat_server.bind(('0.0.0.0', port))
            self.chat_server.listen(64)
            
            self.chat_clients = []
            self.chat_names = {}
            self.server_running = True
            
            print(colorama.Fore.GREEN + f"✅ Chat server started on port {port}")
            print(colorama.Fore.YELLOW + "Waiting for connections... (Type 'stopserver' to stop)")
            
            # Accept connections
            accept_thread = threading.Thread(target=self.accept_connections, daemon=True)
            accept_thread.start()
            
        except Exception as e:
            print(colorama.Fore.RED + f"Failed to start server: {str(e)}")

    def accept_connections(self):
        """Accept incoming client connections"""
        while self.server_running:
            try:
                conn, addr = self.chat_server.accept()
                client_thread = threading.Thread(target=self.handle_chat_client, args=(conn, addr), daemon=True)
                client_thread.start()
            except:
                break

    def handle_chat_client(self, conn, addr):
        """Handle individual chat client"""
        try:
            # Receive client name
            name = conn.recv(1024).decode().strip()
            self.chat_names[conn] = name
            self.chat_clients.append(conn)
            
            join_msg = f"👤 {name} joined the chat"
            print(colorama.Fore.GREEN + join_msg)
            self.broadcast_message(join_msg, conn)
            
            # Handle client messages
            while self.server_running:
                try:
                    msg = conn.recv(1024).decode()
                    if not msg or msg.lower() == "exit":
                        break
                    
                    chat_msg = f"{name}: {msg}"
                    print(colorama.Fore.CYAN + chat_msg)
                    self.broadcast_message(chat_msg, conn)
                    
                except:
                    break
                    
        except Exception as e:
            print(colorama.Fore.RED + f"Client error: {str(e)}")
        finally:
            # Client disconnected
            if conn in self.chat_clients:
                name = self.chat_names.get(conn, 'Unknown')
                leave_msg = f"👤 {name} left the chat"
                print(colorama.Fore.YELLOW + leave_msg)
                self.broadcast_message(leave_msg, conn)
                
                self.chat_clients.remove(conn)
                if conn in self.chat_names:
                    del self.chat_names[conn]
            conn.close()

    def broadcast_message(self, message, exclude=None):
        """Broadcast message to all connected clients"""
        for client in self.chat_clients[:]:  # Create a copy to avoid modification during iteration
            if client != exclude:
                try:
                    client.send(message.encode())
                except:
                    if client in self.chat_clients:
                        self.chat_clients.remove(client)
                    client.close()

    def stop_chat_server(self):
        """Stop the chat server"""
        if hasattr(self, 'server_running') and self.server_running:
            self.server_running = False
            if hasattr(self, 'chat_server'):
                for client in self.chat_clients:
                    client.close()
                self.chat_server.close()
            print(colorama.Fore.RED + "🔒 Chat server stopped")
        else:
            print(colorama.Fore.YELLOW + "No active chat server")

    def join_chat(self, host, port=8080):
        """Join a chat server"""
        if not host:
            print(colorama.Fore.RED + "Usage: join <host> [-p port]")
            return
            
        try:
            name = input(colorama.Fore.YELLOW + "Enter your name: ")
            if not name.strip():
                print(colorama.Fore.RED + "Name cannot be empty")
                return
            
            print(colorama.Fore.YELLOW + f"Connecting to {host}:{port}...")
            
            self.chat_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.chat_client.connect((host, port))
            self.chat_client.send(name.encode())
            
            self.chat_connected = True
            print(colorama.Fore.GREEN + f"✅ Connected to chat server at {host}:{port}")
            print(colorama.Fore.CYAN + "Chat mode activated. Type messages to send, 'leavechat' to exit chat mode")
            
            # Start receiving messages
            receive_thread = threading.Thread(target=self.receive_chat_messages, daemon=True)
            receive_thread.start()
            
        except Exception as e:
            print(colorama.Fore.RED + f"Failed to connect to chat: {str(e)}")

    def receive_chat_messages(self):
        """Receive messages from chat server"""
        while self.chat_connected:
            try:
                message = self.chat_client.recv(1024).decode()
                if not message:
                    break
                print(colorama.Fore.MAGENTA + f"💬 {message}")
            except:
                break

    def send_chat_message(self, message):
        """Send message to chat server"""
        if hasattr(self, 'chat_connected') and self.chat_connected:
            try:
                self.chat_client.send(message.encode())
            except:
                print(colorama.Fore.RED + "Failed to send message")
                self.leave_chat()

    def leave_chat(self):
        """Leave the chat server"""
        if hasattr(self, 'chat_connected') and self.chat_connected:
            try:
                self.chat_client.send("exit".encode())
                self.chat_client.close()
            except:
                pass
            self.chat_connected = False
            print(colorama.Fore.YELLOW + "Left chat server")
        else:
            print(colorama.Fore.YELLOW + "Not connected to any chat server")

    def server_broadcast(self, message):
        """Send message from server to all clients"""
        if hasattr(self, 'server_running') and self.server_running:
            server_msg = f"Server: {message}"
            print(colorama.Fore.BLUE + server_msg)
            self.broadcast_message(server_msg)
        else:
            print(colorama.Fore.YELLOW + "No active chat server")

    def get_prompt(self):
        timestamp = datetime.now().strftime("%H:%M:%S")
        if self.ssh_connected:
            return f"{colorama.Fore.GREEN}[{timestamp}] {colorama.Fore.CYAN}{self.current_host}{colorama.Fore.YELLOW} ➤ {colorama.Fore.RESET}"
        else:
            return f"{colorama.Fore.GREEN}[{timestamp}] {colorama.Fore.BLUE}NetPilot{colorama.Fore.YELLOW} ➤ {colorama.Fore.RESET}"

    def parse_command(self, command_line):
        try:
            return shlex.split(command_line)
        except ValueError:
            return command_line.split()

    def run(self):
        self.clear()
        self.banner()
        print(colorama.Fore.GREEN + "Welcome to NetPilot! Type 'help' for available commands.\n")
        
        while True:
            try:
                command_line = input(self.get_prompt()).strip()
                
                if not command_line:
                    continue
                    
                args = self.parse_command(command_line)
                command = args[0].lower()
                params = args[1:] if len(args) > 1 else []
                
                if command == 'help':
                    self.show_help()
                    
                elif command == 'clear':
                    self.clear()
                    self.banner()
                    
                elif command == 'exit' or command == 'quit':
                    if self.ssh_connected:
                        self.ssh_disconnect()
                    if hasattr(self, 'server_running') and self.server_running:
                        self.stop_chat_server()
                    if hasattr(self, 'chat_connected') and self.chat_connected:
                        self.leave_chat()
                    print(colorama.Fore.RED + "Goodbye! 👋")
                    break
                    
                elif command == 'ping':
                    self.ping(params[0] if params else None)
                    
                elif command == 'trace':
                    self.traceroute(params[0] if params else None)
                    
                elif command == 'nslookup':
                    self.nslookup(params[0] if params else None)
                    
                elif command == 'whois':
                    self.whois(params[0] if params else None)
                    
                elif command == 'geoip':
                    self.geoip(params[0] if params else None)
                    
                elif command == 'myip':
                    self.get_public_ip()
                    
                elif command == 'portscan':
                    self.port_scanner(params[0] if params else None)
                    
                elif command == 'osdetect':
                    self.detect_os(params[0] if params else None)
                    
                elif command == 'netstat':
                    self.netstat()

                elif command == 'ssh':
                    self.ssh_connect(params[0] if params else None)
                    
                elif command == 'testssh':
                    self.test_ssh(params[0] if params else None)
                    
                elif command == 'disconnect':
                    self.ssh_disconnect()
                    
                elif command == 'serverm':
                    port = 8080  # default port
                    if '-p' in params:
                        try:
                            port_index = params.index('-p') + 1
                            if port_index < len(params):
                                port = int(params[port_index])
                        except (ValueError, IndexError):
                            print(colorama.Fore.RED + "Invalid port number")
                            continue
                    self.start_chat_server(port)
                    
                elif command == 'stopserver':
                    self.stop_chat_server()
                    
                elif command == 'broadcast':
                    if params:
                        message = ' '.join(params)
                        self.server_broadcast(message)
                    else:
                        print(colorama.Fore.RED + "Usage: broadcast <message>")
                        
                elif command == 'join':
                    if params:
                        host = params[0]
                        port = 8080  # default port
                        if '-p' in params:
                            try:
                                port_index = params.index('-p') + 1
                                if port_index < len(params):
                                    port = int(params[port_index])
                            except (ValueError, IndexError):
                                print(colorama.Fore.RED + "Invalid port number")
                                continue
                        self.join_chat(host, port)
                    else:
                        print(colorama.Fore.RED + "Usage: join <host> [-p port]")
                        
                elif command == 'leavechat':
                    self.leave_chat()
                
                elif hasattr(self, 'chat_connected') and self.chat_connected and not command.startswith(('help', 'clear', 'exit', 'leavechat', 'disconnect', 'stopserver')):
                    # If connected to chat and command is not a system command, treat as chat message
                    self.send_chat_message(command_line)
                    
                else:
                    # If connected via SSH, try to execute the command remotely
                    if self.ssh_connected:
                        self.execute_ssh_command(command_line)
                    else:
                        print(colorama.Fore.RED + f"Unknown command: {command}")
                        print(colorama.Fore.YELLOW + "Type 'help' for available commands")
                        
            except KeyboardInterrupt:
                print(colorama.Fore.YELLOW + "\nUse 'exit' to quit")
            except EOFError:
                break
            except Exception as e:
                print(colorama.Fore.RED + f"Error: {str(e)}")

if __name__ == "__main__":
    toolkit = NetworkToolkit()
    toolkit.run()
