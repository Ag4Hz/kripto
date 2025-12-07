import json, struct, socket
import base64

def send_msg(sock, msg):
    data = json.dumps(msg).encode('utf-8')
    sock.sendall(struct.pack('!I', len(data)) + data)

def recv_msg(sock):
    header = recv_all(sock, 4)
    if not header:
        return None
    (msg_len,) = struct.unpack('!I', header)
    data = recv_all(sock, msg_len)
    return json.loads(data.decode('utf-8'))

def recv_all(sock, n):
    buffer = b''
    while len(buffer) < n:
        chunk = sock.recv(n - len(buffer))
        if not chunk:
            return None
        buffer += chunk
    return buffer

def b64(data):
    return base64.b64encode(data).decode('ascii')

def unb64(data):
    return base64.b64decode(data.encode('ascii'))