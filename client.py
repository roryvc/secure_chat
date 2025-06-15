"""
client.py - Secure chat client with asymmetric key exchange and symmetric encryption.

Handles user authentication, key generation and exchange, and encrypted private messaging
between users over a TCP socket connection to a server.
"""
import socket
import threading
import time
import sys
import auth
import crypto_utils

HOST = '127.0.0.1'
PORT = 12345
symmetric_keys = {} # Maps username -> symmetric AES key
private_key = None # RSA private key for decrypting received symmetric keys
pending_public_keys = {}  # Maps username -> PEM encoded public RSA key

def receive_messages(sock):
    """
    Continuously receives messages from the server.

    Handles symmetric key exchange, public key responses, and decryption of
    private messages. Displays incoming messages in the terminal and maintains
    a clean user prompt.

    Args:
        sock (socket.socket): The socket object connected to the server.

    Returns:
        None
    """
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

                try:
                    prefix, content = msg.split("] ", 1)
                    sender_username, hex_cipher = content.split(":", 1)
                    sender_username = sender_username.strip()
                    hex_cipher = hex_cipher.strip()

                    if sender_username not in symmetric_keys:
                        # Clear current input line
                        sys.stdout.write('\r')         # Return cursor to the beginning
                        sys.stdout.write('\033[K')     # Clear the line
                        print(f"[!] No symmetric key for {sender_username}. Cannot decrypt message.")
                        print("you: ", end="", flush=True)
                        continue

                    encrypted_bytes = bytes.fromhex(hex_cipher)
                    # separate mac and encrypted message
                    encrypted_message = encrypted_bytes[:-32]
                    received_hmac = encrypted_bytes[-32:]
                    # verify hmac before decrypting
                    if not crypto_utils.verify_hmac(encrypted_message, symmetric_keys[sender_username], received_hmac):
                        print("[!] Message failed integrity check. Possible tampering!")
                    else:
                        plaintext = crypto_utils.decrypt_with_symmetric_key(encrypted_message, symmetric_keys[sender_username])
                        # Clear current input line
                        sys.stdout.write('\r')         # Return cursor to the beginning
                        sys.stdout.write('\033[K')     # Clear the line
                        print(f"{sender_username}: {plaintext}")
                        print("[✓] No message tampering detected")
                    print("you: ", end="", flush=True)

                except Exception as e:
                    # Clear current input line
                    sys.stdout.write('\r')         # Return cursor to the beginning
                    sys.stdout.write('\033[K')     # Clear the line
                    print(f"[!] Failed to decrypt private message: {e}")
                    print("you: ", end="", flush=True)

            else:
                print(msg)
                print("you: ", end="", flush=True)

        except Exception as e:
            print(f"[!] Connection closed or error occurred: {e}")
            break

def send_messages(sock):
    """
    Continuously reads user input and sends encrypted messages to the server.

    Messages must follow the format '@username:message'. Uses a symmetric key
    (established using RSA key exchange) to encrypt messages before sending.
    
    Args:
        sock (socket.socket): The socket object connected to the server.

    Returns:
        None
    """
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

            # Encrypt message and sign with hmac
            encrypted_bytes = crypto_utils.encrypt_with_symmetric_key(plaintext, symmetric_key)
            mac = crypto_utils.create_hmac(encrypted_bytes, symmetric_key)
            hex_payload = (encrypted_bytes + mac).hex()

            # Send to server
            full_message = f"@{to_user}:{hex_payload}"
            sock.send(full_message.encode())

        except Exception as e:
            print(f"[!] Error sending message: {e}")

def authenticate_user(sock):
    """
    Prompts the user for login credentials using `auth.run()`.

    Sends the authenticated username to the server if successful. Allows 3 attempts.

    Args:
        sock (socket.socket): The socket object connected to the server.

    Returns:
        None
    """
    # Give 3 login attempts
    for i in range(3):
        success, message, username = auth.run()
        print(message)
        if success:
            # tell server username
            sock.send(f"@username:{username}".encode())
            break
        if not success and i == 2:
            print("Too many failed login attempts... Exiting app...")
            exit()

def generate_public_private_keys(sock):
    """
    Generates a new RSA key pair and sends the public key to the server.

    Args:
        sock (socket.socket): The socket object connected to the server.

    Returns:
        None
    """
    global private_key
    private_key, public_key = crypto_utils.generate_rsa_keys()
    # tell server public key
    public_key_pem = crypto_utils.serialize_public_key(public_key)
    sock.send(f"@publickey:{public_key_pem.decode()}".encode())

def get_symmetric_key(username, sock):
    """
    Retrieves or establishes a symmetric key with the given user.

    If the key already exists in `symmetric_keys`, it is returned.
    Otherwise, initiates a key exchange and returns the new key.

    Args:
        username (str): The recipient's username.
        sock (socket.socket): The socket object used for key exchange.

    Returns:
        bytes: The symmetric AES key if successful, else None.
    """
    if username in symmetric_keys:
        return symmetric_keys[username]
    
    # If not in dictionary, create it
    sym_key = create_symmetric_key(username, sock)
    symmetric_keys[username] = sym_key
    return sym_key


def create_symmetric_key(username, sock):
    """
    Creates a new AES symmetric key for secure communication with the recipient.

    - Requests the recipient's public key from the server.
    - Encrypts the symmetric key with their public key.
    - Sends the encrypted key to the recipient via the server.
    - Returns the raw symmetric key.

    Args:
        username (str): The recipient's username.
        sock (socket.socket): The socket object used for sending requests.

    Returns:
        bytes or None: The generated symmetric key, or None if key exchange failed.
    """
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
    """
    Receives and decrypts an incoming symmetric key from another user.

    The symmetric key is stored in `symmetric_keys` and will be used
    for subsequent encrypted communication with that user.

    Args:
        msg (str): The full message string starting with '@symkey:' and followed by
                   the sender's username and a hex-encoded encrypted key.

    Returns:
        None
    """
    _, from_user, hex_ecoded_encrypted_key = msg.split(":", 2)
    encrypted_key = bytes.fromhex(hex_ecoded_encrypted_key)
    sym_key = crypto_utils.decrypt_with_private_key(encrypted_key, private_key)
    symmetric_keys[from_user] = sym_key
    # Clear current input line
    sys.stdout.write('\r')         # Return cursor to the beginning
    sys.stdout.write('\033[K')     # Clear the line
    print(f"[✓] Received symmetric key from {from_user}")

if __name__ == "__main__":
    """
    Initializes the client, connects to the server, and starts send/receive threads.
    """
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))

    receive_thread = threading.Thread(target=receive_messages, args=(client,))
    send_thread = threading.Thread(target=send_messages, args=(client,))
    receive_thread.start()
    send_thread.start()
