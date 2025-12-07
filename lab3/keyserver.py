#!/usr/bin/env python3
"""
Key Server - Facilitates public key exchange between P2P clients
Stores and provides public keys and connection info for clients
"""
import socket
import threading
import logging
from helper import send_msg, recv_msg

logging.basicConfig(level=logging.INFO, format='[KeyServer] %(message)s')


class KeyServer:
    def __init__(self, host='localhost', port=8000):
        self.host = host
        self.port = port
        # Store client info: client_id -> {'pubkey': key, 'host': host, 'port': port}
        self.clients = {}
        self.lock = threading.Lock()

    def start(self):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.host, self.port))
        server_sock.listen(5)
        logging.info(f'Key Server listening on {self.host}:{self.port}')

        try:
            while True:
                client_sock, addr = server_sock.accept()
                logging.info(f'Connection from {addr}')
                threading.Thread(target=self.handle_client, args=(client_sock, addr), daemon=True).start()
        except KeyboardInterrupt:
            logging.info('\nShutting down...')
        finally:
            server_sock.close()
    
    def handle_client(self, sock, addr):
        try:
            req = recv_msg(sock)
            if not req:
                return
            
            req_type = req.get('type')
            
            if req_type == 'register':
                # Register client with public key and P2P connection info
                client_id = req['client_id']
                pubkey = req['pubkey']
                p2p_host = req['p2p_host']
                p2p_port = req['p2p_port']
                
                with self.lock:
                    self.clients[client_id] = {
                        'pubkey': pubkey,
                        'p2p_host': p2p_host,
                        'p2p_port': p2p_port
                    }
                
                logging.info(f"✓ Registered '{client_id}' at {p2p_host}:{p2p_port}")
                send_msg(sock, {'status': 'ok'})
            
            elif req_type == 'get':
                # Retrieve another client's public key and connection info
                client_id = req['client_id']
                
                with self.lock:
                    client_info = self.clients.get(client_id)
                
                if client_info:
                    logging.info(f"✓ Provided info for '{client_id}'")
                    send_msg(sock, {
                        'status': 'ok',
                        'pubkey': client_info['pubkey'],
                        'p2p_host': client_info['p2p_host'],
                        'p2p_port': client_info['p2p_port']
                    })
                else:
                    logging.info(f"✗ Client '{client_id}' not found")
                    send_msg(sock, {'status': 'not_found'})
            
            elif req_type == 'list':
                # List all registered clients
                with self.lock:
                    client_list = list(self.clients.keys())
                
                logging.info(f"✓ Listing {len(client_list)} clients")
                send_msg(sock, {
                    'status': 'ok',
                    'clients': client_list
                })
            
            elif req_type == 'unregister':
                # Remove client registration
                client_id = req['client_id']
                
                with self.lock:
                    if client_id in self.clients:
                        del self.clients[client_id]
                        logging.info(f"✓ Unregistered '{client_id}'")
                        send_msg(sock, {'status': 'ok'})
                    else:
                        send_msg(sock, {'status': 'not_found'})
            
            else:
                send_msg(sock, {'status': 'bad_request'})
        
        except Exception as e:
            logging.exception("Error handling request")
        
        finally:
            sock.close()


if __name__ == '__main__':
    import sys
    
    host = sys.argv[1] if len(sys.argv) > 1 else 'localhost'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8000
    
    server = KeyServer(host, port)
    server.start()