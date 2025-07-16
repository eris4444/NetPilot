import socket
import threading
import os
import colorama

colorama.init()

class ChatClient:
    def __init__(self):
        self.connected = False
        self.client = None
        
    def connect(self, host, port, name):
        try:
            self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client.connect((host, port))
            self.client.send(name.encode())
            self.connected = True
            
            print(colorama.Fore.GREEN + f"✅ Connected to chat server at {host}:{port}")
            print(colorama.Fore.CYAN + "Type your messages (type 'exit' to leave):")
            
            # Start receiving thread
            receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            receive_thread.start()
            
            # Handle sending messages
            self.send_messages()
            
        except Exception as e:
            print(colorama.Fore.RED + f"Connection failed: {str(e)}")
            
    def receive_messages(self):
        while self.connected:
            try:
                message = self.client.recv(1024).decode()
                if not message:
                    break
                print(colorama.Fore.MAGENTA + f"💬 {message}")
            except:
                break
                
    def send_messages(self):
        while self.connected:
            try:
                msg = input()
                if msg.lower() == 'exit':
                    self.client.send("exit".encode())
                    self.connected = False
                    break
                elif msg.strip():
                    self.client.send(msg.encode())
            except:
                break
        
        if self.client:
            self.client.close()

if __name__ == "__main__":
    os.system('cls' if os.name == 'nt' else 'clear')
    
    print(colorama.Fore.CYAN + "=== Chat Client ===")
    print(colorama.Fore.YELLOW + "Made by eris\n")
    
    try:
        host = input("Enter server IP: ").strip() or "localhost"
        port = int(input("Enter server port: ").strip() or "8080")
        name = input("Enter your name: ").strip()
        
        if not name:
            print(colorama.Fore.RED + "Name cannot be empty!")
            exit(1)
            
        client = ChatClient()
        client.connect(host, port, name)
        
    except KeyboardInterrupt:
        print(colorama.Fore.YELLOW + "\nDisconnected by user")
    except Exception as e:
        print(colorama.Fore.RED + f"Client error: {str(e)}")
