"""
server.py - Secure messaging server.

Handles multiple client connections, public key registration and exchange, 
symmetric key forwarding, and private messaging using socket communication.
"""

import socket
import threading

HOST = '127.0.0.1'
PORT = 12345

clients = {} # socket -> username
user_sockets = {} # username -> socket
public_keys = {} # username -> public key pem string

def handle_client(conn, addr):
    """
    Handles communication with a connected client.

    Registers the client's username, listens for incoming messages,
    and delegates them for processing.

    Args:
        conn (socket.socket): The client socket connection.
        addr (tuple): The address of the connected client.
    """
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
    """
    Processes a message received from a client.

    Routes the message based on its prefix:
    - @publickey: Register a public key
    - @sendpublickey: Respond with a user's public key
    - @symkey: Forward a symmetric key to another user
    - @username:message: Forward a private message

    Args:
        connection (socket.socket): The socket of the sending client.
        message (str): The message received from the client.
    """
    if message.startswith("@publickey:"):
        register_user_public_key(connection, message)
        return
    
    elif message.startswith("@sendpublickey:"):
        target_user = message[len("@sendpublickey:"):].strip()
        public_key_pem = public_keys.get(target_user)
        if public_key_pem:
            connection.send(f"@publickeyresponse:{target_user}:{public_key_pem}".encode())
        else:
            connection.send(f"[!] Public key for {target_user} not found.".encode())
        return
    
    elif message.startswith("@symkey:"):
        # Forward the symmetric key message to the recipient
        try:
            _, to_user, key_hex = message.split(":", 2)
            to_conn = user_sockets.get(to_user)
            if to_conn:
                to_conn.send(f"@symkey:{clients[connection]}:{key_hex}".encode())
            else:
                connection.send(b"[!] Recipient not connected.")
        except ValueError:
            connection.send(b"[!] Invalid symkey format.")
    
    elif message.startswith("@"):
        try:
            to_user, message = message[1:].split(":", 1)  # remove '@', then split
            to_conn = user_sockets.get(to_user.strip())
            # print(f"[DEBUG] Processing message: {message}")
            # print(f"[DEBUG] Known users: {list(user_sockets.keys())}")
            # print(f"[DEBUG] to_user: '{to_user}'")
            # print(f"[DEBUG] to_conn: {to_conn}")
            if to_conn:
                to_conn.send(f"[Private] {clients[connection]}: {message}".encode())
            else:
                connection.send(b"[!] Recipient not connected.")
        except ValueError:
            connection.send(b"[!] Invalid private message format.")
    else:
        connection.send(b"[!] Invalid message format... @ someone's username at the start of the message...")

def register_user_public_key(connection, message):
    """
    Registers a client's public key for future exchange.

    Args:
        connection (socket.socket): The client socket sending the key.
        message (str): Message containing the public key prefixed with '@publickey:'.
    """
    if message.startswith("@publickey:"):
        try:
            public_key = message[11:]
            public_keys[clients[connection]] = public_key
            print(public_keys)
        except:
            pass

def start_server():
    """
    Starts the server and listens for incoming client connections.

    Creates a new thread for each connected client.
    """
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
