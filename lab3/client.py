#!/usr/bin/env python3
import socket
import sys
import os
import threading
import secrets
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

# Add the build directory to path to import the C++ module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lab2', 'build', 'Release'))

try:
    import crypto_module
except ImportError:
    print("Error: crypto_module not found")
    print("Run: cd lab2/build && cmake --build . --config Release --target crypto_module")
    sys.exit(1)

from helper import send_msg, recv_msg, b64, unb64


class P2PClient:
    def __init__(self, client_id, p2p_port, keyserver_host='localhost', keyserver_port=8000):
        self.client_id = client_id
        self.p2p_host = 'localhost'
        self.p2p_port = p2p_port
        self.keyserver_host = keyserver_host
        self.keyserver_port = keyserver_port
        
        # Generate RSA key pair for this client
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        # Serialize public key for transmission
        self.public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        # Store peer information: peer_id -> {'pubkey': key, 'host': host, 'port': port}
        self.peers = {}
        
        # Active connections: peer_id -> socket
        self.connections = {}
        self.connections_lock = threading.Lock()
        
        self.running = False
        self.server_socket = None
        
        print(f"Client '{client_id}' initialized")
        print(f"P2P listening on {self.p2p_host}:{self.p2p_port}")
    
    def register_with_keyserver(self):
        """Register this client's public key with the keyserver"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.keyserver_host, self.keyserver_port))
            
            send_msg(sock, {
                'type': 'register',
                'client_id': self.client_id,
                'pubkey': self.public_key_pem,
                'p2p_host': self.p2p_host,
                'p2p_port': self.p2p_port
            })
            
            response = recv_msg(sock)
            sock.close()
            
            if response and response.get('status') == 'ok':
                print(f"Registered with keyserver")
                return True
            else:
                print(f"Registration failed: {response}")
                return False
        except Exception as e:
            print(f"Failed to register with keyserver: {e}")
            return False
    
    def get_peer_info(self, peer_id):
        """Fetch peer's public key and connection info from keyserver"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.keyserver_host, self.keyserver_port))
            
            send_msg(sock, {
                'type': 'get',
                'client_id': peer_id
            })
            
            response = recv_msg(sock)
            sock.close()
            
            if response and response.get('status') == 'ok':
                # Deserialize public key
                pubkey_pem = response['pubkey']
                pubkey = serialization.load_pem_public_key(
                    pubkey_pem.encode('utf-8'),
                    backend=default_backend()
                )
                
                self.peers[peer_id] = {
                    'pubkey': pubkey,
                    'p2p_host': response['p2p_host'],
                    'p2p_port': response['p2p_port']
                }
                
                print(f"Retrieved info for '{peer_id}'")
                return True
            else:
                print(f"Peer '{peer_id}' not found")
                return False
        except Exception as e:
            print(f"Failed to get peer info: {e}")
            return False
    
    def connect_to_peer(self, peer_id):
        """Establish P2P connection to another client"""
        if peer_id not in self.peers:
            if not self.get_peer_info(peer_id):
                return None
        
        peer_info = self.peers[peer_id]
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((peer_info['p2p_host'], peer_info['p2p_port']))
            
            # Send handshake with our client ID
            send_msg(sock, {
                'type': 'handshake',
                'client_id': self.client_id
            })
            
            response = recv_msg(sock)
            if response and response.get('status') == 'ok':
                with self.connections_lock:
                    self.connections[peer_id] = sock
                
                # Start thread to receive messages from this peer
                threading.Thread(
                    target=self.handle_peer_messages,
                    args=(peer_id, sock),
                    daemon=True
                ).start()
                
                print(f"Connected to '{peer_id}'")
                return sock
            else:
                sock.close()
                return None
        except Exception as e:
            print(f"Failed to connect to '{peer_id}': {e}")
            return None
    
    def encrypt_message(self, peer_id, plaintext: str) -> dict:
        """
        Encrypt message using hybrid encryption:
        1. Generate random AES key and IV
        2. Encrypt message with AES (using C++ module)
        3. Encrypt AES key with peer's RSA public key
        """
        if peer_id not in self.peers:
            raise ValueError(f"Peer '{peer_id}' info not available")
        
        # Generate random AES key and IV for this message
        aes_key = secrets.token_bytes(16)
        aes_iv = secrets.token_bytes(16)
        
        # Encrypt plaintext with AES using C++ module
        plaintext_bytes = plaintext.encode('utf-8')
        ciphertext = crypto_module.encrypt(
            key=list(aes_key),
            iv=list(aes_iv),
            plaintext=list(plaintext_bytes),
            mode="CBC",
            padding="PKCS7"
        )
        
        # Encrypt AES key with peer's RSA public key
        peer_pubkey = self.peers[peer_id]['pubkey']
        encrypted_key = peer_pubkey.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return {
            'encrypted_key': b64(encrypted_key),
            'iv': b64(aes_iv),
            'ciphertext': b64(bytes(ciphertext))
        }
    
    def decrypt_message(self, encrypted_data: dict) -> str:
        """
        Decrypt message using hybrid encryption:
        1. Decrypt AES key with our RSA private key
        2. Decrypt message with AES (using C++ module)
        """
        # Decrypt AES key with our private key
        encrypted_key = unb64(encrypted_data['encrypted_key'])
        aes_key = self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Decrypt message with AES using C++ module
        aes_iv = unb64(encrypted_data['iv'])
        ciphertext = unb64(encrypted_data['ciphertext'])
        
        plaintext_bytes = crypto_module.decrypt(
            key=list(aes_key),
            iv=list(aes_iv),
            ciphertext=list(ciphertext),
            mode="CBC",
            padding="PKCS7"
        )
        
        return bytes(plaintext_bytes).decode('utf-8')
    
    def send_message(self, peer_id, message: str):
        """Send encrypted message to peer via P2P connection"""
        try:
            # Get or create connection
            with self.connections_lock:
                sock = self.connections.get(peer_id)
            
            if not sock:
                sock = self.connect_to_peer(peer_id)
                if not sock:
                    print(f"Cannot connect to '{peer_id}'")
                    return
            
            # Encrypt message
            encrypted_data = self.encrypt_message(peer_id, message)
            
            # Send encrypted message
            send_msg(sock, {
                'type': 'message',
                'from': self.client_id,
                'data': encrypted_data
            })
            
            print(f"Sent to {peer_id}: {message}")
        
        except Exception as e:
            print(f"Failed to send message to '{peer_id}': {e}")
            # Remove failed connection
            with self.connections_lock:
                if peer_id in self.connections:
                    try:
                        self.connections[peer_id].close()
                    except:
                        pass
                    del self.connections[peer_id]
    
    def handle_peer_messages(self, peer_id, sock):
        """Handle incoming messages from a peer connection"""
        try:
            while self.running:
                msg = recv_msg(sock)
                if not msg:
                    break
                
                msg_type = msg.get('type')
                
                if msg_type == 'message':
                    sender = msg.get('from')
                    encrypted_data = msg.get('data')
                    
                    try:
                        plaintext = self.decrypt_message(encrypted_data)
                        print(f"\nMessage from {sender}: {plaintext}")
                        print(f"[{self.client_id}] > ", end='', flush=True)
                    except Exception as e:
                        print(f"\nFailed to decrypt message from {sender}: {e}")
                        print(f"[{self.client_id}] > ", end='', flush=True)
        
        except Exception as e:
            if self.running:
                print(f"\nError with peer '{peer_id}': {e}")
        
        finally:
            with self.connections_lock:
                if peer_id in self.connections:
                    del self.connections[peer_id]
            try:
                sock.close()
            except:
                pass
    
    def start_p2p_server(self):
        """Start listening for incoming P2P connections"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.p2p_host, self.p2p_port))
        self.server_socket.listen(5)
        
        print(f"P2P server started on {self.p2p_host}:{self.p2p_port}")
        
        while self.running:
            try:
                sock, addr = self.server_socket.accept()
                
                # Receive handshake
                handshake = recv_msg(sock)
                if handshake and handshake.get('type') == 'handshake':
                    peer_id = handshake.get('client_id')
                    
                    # Fetch peer info if we don't have it
                    if peer_id not in self.peers:
                        self.get_peer_info(peer_id)
                    
                    send_msg(sock, {'status': 'ok'})
                    
                    with self.connections_lock:
                        self.connections[peer_id] = sock
                    
                    print(f"\nIncoming connection from '{peer_id}'")
                    print(f"[{self.client_id}] > ", end='', flush=True)
                    
                    # Handle messages from this peer
                    threading.Thread(
                        target=self.handle_peer_messages,
                        args=(peer_id, sock),
                        daemon=True
                    ).start()
                else:
                    sock.close()
            
            except Exception as e:
                if self.running:
                    print(f"Error accepting connection: {e}")
    
    def list_peers(self):
        """List all clients registered with keyserver"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.keyserver_host, self.keyserver_port))
            
            send_msg(sock, {'type': 'list'})
            response = recv_msg(sock)
            sock.close()
            
            if response and response.get('status') == 'ok':
                clients = response.get('clients', [])
                print("\nAvailable peers:")
                for client in clients:
                    if client != self.client_id:
                        print(f"  - {client}")
                if len(clients) <= 1:
                    print("  (none)")
            else:
                print("Failed to list peers")
        except Exception as e:
            print(f"Error listing peers: {e}")
    
    def start(self):
        """Start the P2P client"""
        # Register with keyserver
        if not self.register_with_keyserver():
            return
        
        self.running = True
        
        # Start P2P server in background
        server_thread = threading.Thread(target=self.start_p2p_server, daemon=True)
        server_thread.start()
        
        print("\nCommands:")
        print("  /send <peer_id> <message>  - Send encrypted message to peer")
        print("  /list                       - List available peers")
        print("  /quit                       - Exit")
        print()
        
        # Main input loop
        try:
            while self.running:
                try:
                    user_input = input(f"[{self.client_id}] > ").strip()
                    
                    if not user_input:
                        continue
                    
                    if user_input.startswith('/send '):
                        parts = user_input[6:].split(None, 1)
                        if len(parts) < 2:
                            print("Usage: /send <peer_id> <message>")
                        else:
                            peer_id, message = parts
                            self.send_message(peer_id, message)
                    
                    elif user_input == '/list':
                        self.list_peers()
                    
                    elif user_input == '/quit':
                        break
                    
                    else:
                        print("Unknown command. Use /send, /list, or /quit")
                
                except EOFError:
                    break
        
        except KeyboardInterrupt:
            print("\n\nShutting down...")
        
        finally:
            self.shutdown()
    
    def shutdown(self):
        """Clean shutdown"""
        self.running = False
        
        # Close all peer connections
        with self.connections_lock:
            for sock in self.connections.values():
                try:
                    sock.close()
                except:
                    pass
            self.connections.clear()
        
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        # Unregister from keyserver
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.keyserver_host, self.keyserver_port))
            send_msg(sock, {
                'type': 'unregister',
                'client_id': self.client_id
            })
            sock.close()
        except:
            pass
        
        print("Disconnected.")


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python client.py <client_id> <p2p_port> [keyserver_host] [keyserver_port]")
        print("Example: python client.py Alice 9001 localhost 8000")
        sys.exit(1)
    
    client_id = sys.argv[1]
    p2p_port = int(sys.argv[2])
    keyserver_host = sys.argv[3] if len(sys.argv) > 3 else 'localhost'
    keyserver_port = int(sys.argv[4]) if len(sys.argv) > 4 else 8000
    
    client = P2PClient(client_id, p2p_port, keyserver_host, keyserver_port)
    client.start()


class EncryptedClient:
    def __init__(self, client_id, server_host='localhost', server_port=9000):
        self.client_id = client_id
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None
        self.running = False
        
        # Generate a symmetric key and IV for this session
        # In a real system, you'd exchange keys securely
        self.key = secrets.token_bytes(16)  # 128-bit AES key
        self.iv = secrets.token_bytes(16)   # 128-bit IV
        
        print(f"Client '{client_id}' initialized")
        print(f"Session Key: {self.key.hex()}")
        print(f"Session IV: {self.iv.hex()}")
    
    def encrypt_message(self, plaintext: str) -> bytes:
        """Encrypt a message using C++ AES implementation"""
        plaintext_bytes = plaintext.encode('utf-8')
        ciphertext = crypto_module.encrypt(
            key=list(self.key),
            iv=list(self.iv),
            plaintext=list(plaintext_bytes),
            mode="CBC",
            padding="PKCS7"
        )
        return bytes(ciphertext)
    
    def decrypt_message(self, ciphertext: bytes) -> str:
        """Decrypt a message using C++ AES implementation"""
        plaintext_bytes = crypto_module.decrypt(
            key=list(self.key),
            iv=list(self.iv),
            ciphertext=list(ciphertext),
            mode="CBC",
            padding="PKCS7"
        )
        return bytes(plaintext_bytes).decode('utf-8')
    
    def connect(self):
        """Connect to the server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_host, self.server_port))
            
            # Send initial registration with client ID and key
            send_msg(self.socket, {
                'type': 'register',
                'client_id': self.client_id,
                'key': b64(self.key),
                'iv': b64(self.iv)
            })
            
            response = recv_msg(self.socket)
            if response and response.get('status') == 'ok':
                print(f"Connected to server at {self.server_host}:{self.server_port}")
                self.running = True
                return True
            else:
                print(f"Registration failed: {response}")
                return False
        except Exception as e:
            print(f"Connection failed: {e}")
            return False
    
    def send_encrypted_message(self, recipient_id: str, message: str):
        """Send an encrypted message to another client"""
        try:
            ciphertext = self.encrypt_message(message)
            
            send_msg(self.socket, {
                'type': 'message',
                'from': self.client_id,
                'to': recipient_id,
                'data': b64(ciphertext)
            })
            
            print(f"Sent to {recipient_id}: {message}")
        except Exception as e:
            print(f"Failed to send message: {e}")
    
    def broadcast_encrypted_message(self, message: str):
        """Broadcast an encrypted message to all connected clients"""
        try:
            ciphertext = self.encrypt_message(message)
            
            send_msg(self.socket, {
                'type': 'broadcast',
                'from': self.client_id,
                'data': b64(ciphertext)
            })
            
            print(f"Broadcast: {message}")
        except Exception as e:
            print(f"Failed to broadcast message: {e}")
    
    def receive_messages(self):
        """Background thread to receive messages from server"""
        while self.running:
            try:
                msg = recv_msg(self.socket)
                if not msg:
                    print("\nConnection to server lost")
                    self.running = False
                    break
                
                msg_type = msg.get('type')
                
                if msg_type == 'message':
                    sender = msg.get('from')
                    ciphertext = unb64(msg.get('data'))
                    
                    try:
                        plaintext = self.decrypt_message(ciphertext)
                        print(f"\nMessage from {sender}: {plaintext}")
                    except Exception as e:
                        print(f"\nFailed to decrypt message from {sender}: {e}")
                
                elif msg_type == 'broadcast':
                    sender = msg.get('from')
                    ciphertext = unb64(msg.get('data'))
                    
                    try:
                        plaintext = self.decrypt_message(ciphertext)
                        print(f"\nBroadcast from {sender}: {plaintext}")
                    except Exception as e:
                        print(f"\nFailed to decrypt broadcast from {sender}: {e}")
                
                elif msg_type == 'notification':
                    print(f"\n[Server] {msg.get('message')}")
                
            except Exception as e:
                if self.running:
                    print(f"\nError receiving message: {e}")
                    self.running = False
                break
    
    def start(self):
        """Start the client"""
        if not self.connect():
            return
        
        # Start background thread for receiving messages
        recv_thread = threading.Thread(target=self.receive_messages, daemon=True)
        recv_thread.start()
        
        print("\nCommands:")
        print("  /send <recipient> <message>  - Send encrypted message to specific client")
        print("  /broadcast <message>         - Broadcast encrypted message to all")
        print("  /quit                        - Exit")
        print()
        
        # Main input loop
        try:
            while self.running:
                try:
                    user_input = input(f"[{self.client_id}] > ").strip()
                    
                    if not user_input:
                        continue
                    
                    if user_input.startswith('/send '):
                        parts = user_input[6:].split(None, 1)
                        if len(parts) < 2:
                            print("Usage: /send <recipient> <message>")
                        else:
                            recipient, message = parts
                            self.send_encrypted_message(recipient, message)
                    
                    elif user_input.startswith('/broadcast '):
                        message = user_input[11:]
                        if message:
                            self.broadcast_encrypted_message(message)
                        else:
                            print("Usage: /broadcast <message>")
                    
                    elif user_input == '/quit':
                        self.running = False
                        break
                    
                    else:
                        print("Unknown command. Use /send, /broadcast, or /quit")
                
                except EOFError:
                    break
        
        except KeyboardInterrupt:
            print("\n\nShutting down...")
        
        finally:
            self.disconnect()
    
    def disconnect(self):
        """Disconnect from server"""
        self.running = False
        if self.socket:
            try:
                send_msg(self.socket, {'type': 'disconnect'})
                self.socket.close()
            except:
                pass
        print("Disconnected.")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python client.py <client_id> [server_host] [server_port]")
        print("Example: python client.py Alice localhost 9000")
        sys.exit(1)
    
    client_id = sys.argv[1]
    server_host = sys.argv[2] if len(sys.argv) > 2 else 'localhost'
    server_port = int(sys.argv[3]) if len(sys.argv) > 3 else 9000
    
    client = EncryptedClient(client_id, server_host, server_port)
    client.start()
