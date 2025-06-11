# client.py
import socket
import threading
import auth

HOST = '127.0.0.1'
PORT = 12345

def receive_messages(sock):
    while True:
        try:
            msg = sock.recv(1024).decode()
            print(msg)
        except:
            print("[!] Connection closed.")
            break

def send_messages(sock):
    authenticate_user(sock)
    while True:
        msg = input("you: ")
        sock.send(msg.encode())

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

if __name__ == "__main__":
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))

    receive_thread = threading.Thread(target=receive_messages, args=(client,))
    send_thread = threading.Thread(target=send_messages, args=(client,))
    receive_thread.start()
    send_thread.start()
