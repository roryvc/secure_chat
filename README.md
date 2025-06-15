# Secure Private Messaging App

A simple end-to-end encrypted chat application built with Python, using asymmetric (RSA) and symmetric (AES-256) encryption, HMAC-based tamper detection, and password-protected authentication.

## Features

- End-to-end encrypted private messaging (AES-256)
- RSA-based symmetric key exchange
- Secure password storage using bcrypt with salting
- Message tampering detection using HMAC
- User signup and login
- Client-server architecture over TCP sockets

## Requirements

- Python 3.10+
- Packages:
  - cryptography
  - bcrypt

## Getting Started

1. Run the server:
python server.py

2. Start a client in a new terminal window:
python client.py
Repeat for each user.

3. Create accounts and chat
On first run, create a new account.

Use @username: message format to send private messages.

Keys are exchanged automatically before secure communication.

## File Overview

client.py: Client application with user interface, message encryption, key exchange, and HMAC verification.

server.py: Central server that routes encrypted messages and stores public keys.

auth.py: Handles secure user signup/login with bcrypt password hashing.

crypto_utils.py: Contains cryptographic functions (RSA, AES, HMAC).

users.json: Local user database (auto-generated).

## Security Overview

RSA is used to exchange AES symmetric keys between users.

All messages are encrypted with AES-256 and authenticated with HMAC.

Passwords are salted and hashed with bcrypt.

The server never sees plaintext messages or private keys.
