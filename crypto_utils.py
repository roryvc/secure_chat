"""
crypto_utils.py - Cryptographic utilities for secure messaging.

Provides helper functions for RSA key generation, serialization, encryption/decryption
using asymmetric (RSA) and symmetric (AES) cryptography.
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hmac
import os

def generate_rsa_keys():
    """
    Generates a new RSA key pair (2048-bit).

    Returns:
        tuple: A tuple (private_key, public_key) of RSA key objects.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    """
    Serializes a public RSA key to PEM format.

    Args:
        public_key (RSAPublicKey): The RSA public key to serialize.

    Returns:
        bytes: PEM-encoded public key.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(pem_bytes):
    """
    Deserializes a PEM-encoded public RSA key.

    Args:
        pem_bytes (bytes): The PEM-encoded public key.

    Returns:
        RSAPublicKey: The deserialized RSA public key object.
    """
    return serialization.load_pem_public_key(pem_bytes)

def encrypt_with_public_key(data, public_key):
    """
    Encrypts data using an RSA public key with OAEP padding.

    Args:
        data (bytes): The data to encrypt.
        public_key (RSAPublicKey): The RSA public key used for encryption.

    Returns:
        bytes: The encrypted data.
    """
    return public_key.encrypt(
        data,
        asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def decrypt_with_private_key(data, private_key):
    """
    Decrypts data using an RSA private key with OAEP padding.

    Args:
        data (bytes): The encrypted data.
        private_key (RSAPrivateKey): The RSA private key used for decryption.

    Returns:
        bytes: The decrypted data.
    """
    return private_key.decrypt(
        data,
        asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def generate_symmetric_key():
    """
    Generates a random 256-bit AES key.

    Returns:
        bytes: A 32-byte (256-bit) key suitable for AES-256 encryption.
    """
    return os.urandom(32)

def encrypt_with_symmetric_key(plaintext_string, symmetric_key):
    """
    Encrypts a plaintext string using AES-256 in CBC mode with PKCS7 padding.

    Args:
        plaintext_string (str): The plaintext string to encrypt.
        symmetric_key (bytes): A 32-byte AES key.

    Returns:
        bytes: The IV concatenated with the ciphertext.
    """
    # Convert string to bytes
    plaintext_bytes = plaintext_string.encode()

    # Pad plaintext to a multiple of 128 bits (AES block size)
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext_bytes) + padder.finalize()

    # Generate a random 16-byte IV
    iv = os.urandom(16)

    # Create AES cipher in CBC mode
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Return IV + ciphertext (so recipient can decrypt)
    return iv + ciphertext

def decrypt_with_symmetric_key(encrypted_bytes, symmetric_key):
    """
    Decrypts AES-256 encrypted data (IV + ciphertext) using CBC mode and PKCS7 unpadding.

    Args:
        encrypted_bytes (bytes): The encrypted message (IV + ciphertext).
        symmetric_key (bytes): A 32-byte AES key used for decryption.

    Returns:
        str: The decrypted plaintext string.
    """
    iv = encrypted_bytes[:16]
    ciphertext = encrypted_bytes[16:]

    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext_bytes = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext_bytes.decode()

def create_hmac(message_bytes, key):
    """
    Creates a SHA-256 HMAC for the given message using the symmetric key.

    Args:
        message_bytes (bytes): The message to authenticate (usually ciphertext).
        key (bytes): The symmetric key used for HMAC.

    Returns:
        bytes: The HMAC digest.
    """
    return hmac.new(key, message_bytes, digestmod='sha256').digest()

def verify_hmac(message_bytes, key, received_hmac):
    """
    Verifies that the HMAC matches the message and key.

    Args:
        message_bytes (bytes): The original message.
        key (bytes): The symmetric key used for HMAC.
        received_hmac (bytes): The HMAC received along with the message.

    Returns:
        bool: True if HMAC is valid, False otherwise.
    """
    expected = hmac.new(key, message_bytes, digestmod='sha256').digest()
    print(f"Expected HMAC: {expected.hex()}")
    print(f"Received HMAC: {received_hmac.hex()}")
    return hmac.compare_digest(expected, received_hmac)

if __name__ == "__main__":
    # Example use case - test that the functions all work

    # Bob's side
    bob_private_key, bob_public_key = generate_rsa_keys()
    bob_public_pem = serialize_public_key(bob_public_key)

    # Alice's side
    alice_public_key_for_bob = deserialize_public_key(bob_public_pem)
    alice_symmetric_key = generate_symmetric_key()
    encrypted_key = encrypt_with_public_key(alice_symmetric_key, alice_public_key_for_bob)

    # Bob decrypts the symmetric key
    decrypted_key = decrypt_with_private_key(encrypted_key, bob_private_key)

    # Check that both parties have the same symmetric key
    print(f"Original symmetric key: {alice_symmetric_key.hex()}")
    print(f"Decrypted symmetric key: {decrypted_key.hex()}")
    print(f"Keys match: {alice_symmetric_key == decrypted_key}")

    # Alice sends a message encrypted with the symmetric key
    original_message = "Hello Bob, this is Alice!"
    encrypted_message_bytes = encrypt_with_symmetric_key(original_message, alice_symmetric_key)

    # Simulate sending over a network by converting to hex
    hex_encoded_msg = encrypted_message_bytes.hex()
    print(f"Hex-encoded encrypted message: {hex_encoded_msg}")
    # encoded_message = encrypted_message_bytes.encode()
    # print(f"Encoded message: {encoded_message}")

    # Bob receives the message and decodes from hex
    received_bytes = bytes.fromhex(hex_encoded_msg)
    # received_bytes = encoded_message.decode()
    decrypted_message = decrypt_with_symmetric_key(received_bytes, decrypted_key)

    # Check message integrity
    print(f"Decrypted message: {decrypted_message}")
    print(f"Messages match: {original_message == decrypted_message}")
