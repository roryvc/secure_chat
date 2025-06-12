# server.py
import socket
import threading

HOST = '127.0.0.1'
PORT = 12345

clients = {} # socket -> username
user_sockets = {} # username -> socket
public_keys = {} # username -> public key pem string

def handle_client(conn, addr):
    # Receive username
    username_msg = conn.recv(1024).decode()
    if not username_msg.startswith("@username:"):
        conn.close()
        return
    
    username = username_msg[len("@username:"):].strip()
    print(f"[+] {username} connected from {addr}")

    clients[conn] = username
    user_sockets[username] = conn
    
    while True:
        try:
            msg = conn.recv(4096).decode()
            if not msg:
                break
            print(f"{username} sent: {msg}")
            # broadcast(msg, conn)
            process_message(conn, msg)
        except:
            break
    conn.close()
    clients.pop(conn, None)
    user_sockets.pop(username, None)
    print(f"[-] {username} disconnected from {addr}")

def process_message(connection, message):
    if message.startswith("@publickey"):
        get_user_public_key(connection, message)
        return
    if message.startswith("@"):
        try:
            to_user, message = message[1:].split(":", 1)  # remove '@', then split
            to_conn = user_sockets.get(to_user)
            if to_conn:
                to_conn.send(f"[Private] {clients[connection]}: {message}".encode())
            else:
                connection.send(b"[!] Recipient not connected.")
        except ValueError:
            connection.send(b"[!] Invalid private message format.")
    else:
        connection.send(b"[!] Invalid message format... @ someone's username at the start of the message...")

def get_user_public_key(connection, message):
    if message.startswith("@publickey"):
        try:
            public_key = message[11:]
            public_keys[clients[connection]] = public_key
            print(public_keys)
        except:
            pass

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[+] Server listening on {HOST}:{PORT}")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    start_server()
