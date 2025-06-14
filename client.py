# client.py
import socket
import threading
import auth
import crypto_utils
import time

HOST = '127.0.0.1'
PORT = 12345
symmetric_keys = {} # username -> symmetric key
private_key = None
pending_public_keys = {}  # username -> PEM string

def receive_messages(sock):
    while True:
        try:
            msg = sock.recv(4096).decode()

            if msg.startswith("@symkey:"):
                recieve_symmetric_key(msg)

            elif msg.startswith("@publickeyresponse:"):
                # Extract username and public key
                _, username, public_key_pem = msg.split(":", 2)
                pending_public_keys[username] = public_key_pem

            elif msg.startswith("[Private]"):
                # Format: "[Private] sender_username: <hex string>"
                # print(msg)  # Optional: show raw message for debugging

                try:
                    prefix, content = msg.split("] ", 1)
                    sender_username, hex_cipher = content.split(":", 1)
                    sender_username = sender_username.strip()
                    hex_cipher = hex_cipher.strip()

                    if sender_username not in symmetric_keys:
                        print(f"[!] No symmetric key for {sender_username}. Cannot decrypt message.")
                        continue

                    encrypted_bytes = bytes.fromhex(hex_cipher)
                    plaintext = crypto_utils.decrypt_with_symmetric_key(encrypted_bytes, symmetric_keys[sender_username])
                    print(f"{sender_username}: {plaintext}")

                except Exception as e:
                    print(f"[!] Failed to decrypt private message: {e}")

            else:
                print(msg)

        except Exception as e:
            print(f"[!] Connection closed or error occurred: {e}")
            break

def send_messages(sock):
    authenticate_user(sock)
    generate_public_private_keys(sock)

    while True:
        msg = input("you: ").strip()

        if not msg.startswith("@") or ":" not in msg:
            print("[!] Invalid format. Use @username:message")
            continue

        try:
            to_user, plaintext = msg[1:].split(":", 1)
            to_user = to_user.strip()
            plaintext = plaintext.strip()

            # Get or create symmetric key
            symmetric_key = get_symmetric_key(to_user, sock)
            if symmetric_key is None:
                print(f"[!] Failed to obtain symmetric key for {to_user}")
                continue

            # Encrypt message
            encrypted_bytes = crypto_utils.encrypt_with_symmetric_key(plaintext, symmetric_key)
            hex_payload = encrypted_bytes.hex()

            # Send to server
            full_message = f"@{to_user}:{hex_payload}"
            sock.send(full_message.encode())

        except Exception as e:
            print(f"[!] Error sending message: {e}")

def authenticate_user(sock):
    # Give 3 login attempts
    for i in range(3):
        success, message, username = auth.run()
        print(message)
        if success:
            # tell server username
            sock.send(f"@username:{username}".encode())
            break
        if not success and i == 2:
            "Too many failed login attempts... Exiting app..."
            exit()

def generate_public_private_keys(sock):
    global private_key
    private_key, public_key = crypto_utils.generate_rsa_keys()
    # tell server public key
    public_key_pem = crypto_utils.serialize_public_key(public_key)
    sock.send(f"@publickey:{public_key_pem.decode()}".encode())

def get_symmetric_key(username, sock):
    if username in symmetric_keys:
        return symmetric_keys[username]
    
    # If not in dictionary, create it
    sym_key = create_symmetric_key(username, sock)
    symmetric_keys[username] = sym_key
    return sym_key


def create_symmetric_key(username, sock):
    # Ask server for recipient's public key
    sock.send(f"@sendpublickey:{username}".encode())

    # Wait for receive_messages() to store it
    for _ in range(50):  # wait up to ~5 seconds
        if username in pending_public_keys:
            public_key_pem = pending_public_keys.pop(username)
            recipient_public_key = crypto_utils.deserialize_public_key(public_key_pem.encode())
            break
        time.sleep(0.1)
    else:
        print(f"[!] Timeout waiting for {username}'s public key")
        return None

    # Generate symmetric key
    sym_key = crypto_utils.generate_symmetric_key()

    # Encrypt and send it to the recipient
    encrypted_key = crypto_utils.encrypt_with_public_key(sym_key, recipient_public_key)
    msg = f"@symkey:{username}:{encrypted_key.hex()}"
    sock.send(msg.encode())
    return sym_key

def recieve_symmetric_key(msg):
    parts = msg.split(":", 2)
    from_user = parts[1]
    encrypted_key = bytes.fromhex(parts[2])
    sym_key = crypto_utils.decrypt_with_private_key(encrypted_key, private_key)
    symmetric_keys[from_user] = sym_key
    print(f"[✓] Received symmetric key from {from_user}")

if __name__ == "__main__":
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))

    receive_thread = threading.Thread(target=receive_messages, args=(client,))
    send_thread = threading.Thread(target=send_messages, args=(client,))
    receive_thread.start()
    send_thread.start()
