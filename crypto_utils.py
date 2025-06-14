from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

import os

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(pem_bytes):
    return serialization.load_pem_public_key(pem_bytes)

def encrypt_with_public_key(data, public_key):
    return public_key.encrypt(
        data,
        asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def decrypt_with_private_key(data, private_key):
    return private_key.decrypt(
        data,
        asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def generate_symmetric_key():
    return os.urandom(32)  # 256-bit AES key

def encrypt_with_symmetric_key(plaintext_string, symmetric_key):
    """
    Encrypts a plaintext string using the provided symmetric key (AES-256).
    Returns the encrypted bytes: IV + ciphertext.
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
    Decrypts the given bytes (IV + ciphertext) using the provided symmetric key.
    Returns the original plaintext string.
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

if __name__ == "__main__":
    # ------------------ Simulation ------------------

    # Bob's side
    bob_private_key, bob_public_key = generate_rsa_keys()
    bob_public_pem = serialize_public_key(bob_public_key)

    # Alice's side
    alice_public_key_for_bob = deserialize_public_key(bob_public_pem)
    alice_symmetric_key = generate_symmetric_key()
    encrypted_key = encrypt_with_public_key(alice_symmetric_key, alice_public_key_for_bob)

    # Bob decrypts the symmetric key
    decrypted_key = decrypt_with_private_key(encrypted_key, bob_private_key)

    # ✅ Check that both parties have the same symmetric key
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

    # ✅ Check message integrity
    print(f"Decrypted message: {decrypted_message}")
    print(f"Messages match: {original_message == decrypted_message}")
