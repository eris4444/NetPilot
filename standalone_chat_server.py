import socket
import threading
import colorama

colorama.init()

class ChatServer:
    def __init__(self, port=8080):
        self.HOST = '0.0.0.0'
        self.PORT = port
        self.clients = []
        self.names = {}
        self.running = True
        
    def start(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.HOST, self.PORT))
        self.server.listen(64)
        
        print(colorama.Fore.GREEN + f"✅ Chat server started on port {self.PORT}")
        print(colorama.Fore.YELLOW + "Waiting for connections... (Type 'exit' to stop)")
        
        # Start server chat thread
        server_thread = threading.Thread(target=self.server_chat, daemon=True)
        server_thread.start()
        
        # Accept connections
        while self.running:
            try:
                conn, addr = self.server.accept()
                client_thread = threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True)
                client_thread.start()
            except:
                break
                
    def broadcast(self, message, exclude=None):
        for client in self.clients[:]:
            if client != exclude:
                try:
                    client.send(message.encode())
                except:
                    client.close()
                    if client in self.clients:
                        self.clients.remove(client)

    def handle_client(self, conn, addr):
        try:
            name = conn.recv(1024).decode().strip()
            self.names[conn] = name
            self.clients.append(conn)
            
            join_msg = f"👤 {name} joined the chat"
            print(colorama.Fore.GREEN + join_msg)
            self.broadcast(join_msg, conn)

            while self.running:
                try:
                    msg = conn.recv(1024).decode()
                    if not msg or msg.lower() == "exit":
                        break
                    
                    chat_msg = f"{name}: {msg}"
                    self.broadcast(chat_msg, conn)
                    print(colorama.Fore.CYAN + chat_msg)
                except:
                    break
        except:
            pass
        finally:
            if conn in self.clients:
                name = self.names.get(conn, 'Unknown')
                leave_msg = f"👤 {name} left the chat"
                print(colorama.Fore.YELLOW + leave_msg)
                self.broadcast(leave_msg, conn)
                self.clients.remove(conn)
                if conn in self.names:
                    del self.names[conn]
            conn.close()

    def server_chat(self):
        while self.running:
            try:
                msg = input()
                if msg.lower() == "exit":
                    print(colorama.Fore.RED + "🔒 Server shutting down...")
                    self.running = False
                    for client in self.clients:
                        client.close()
                    self.server.close()
                    break
                elif msg.strip():
                    server_msg = f"Server: {msg}"
                    print(colorama.Fore.BLUE + server_msg)
                    self.broadcast(server_msg)
            except:
                break

if __name__ == "__main__":
    try:
        port = int(input("Enter server port (default 8080): ") or "8080")
        server = ChatServer(port)
        server.start()
    except KeyboardInterrupt:
        print(colorama.Fore.RED + "\nServer stopped by user")
    except Exception as e:
        print(colorama.Fore.RED + f"Server error: {str(e)}")
