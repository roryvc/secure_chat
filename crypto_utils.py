from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os

# --------- Step 1: Bob generates RSA keys ---------
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

# --------- Step 2: Serialize keys for sharing ---------
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def load_public_key(pem_data):
    return serialization.load_pem_public_key(pem_data)

# --------- Step 3: Alice generates symmetric AES key ---------
def generate_symmetric_key():
    return os.urandom(32)  # 256-bit key

# --------- Step 4: Encrypt and decrypt the AES key using RSA ---------
def encrypt_key(symmetric_key, public_key):
    return public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_key(encrypted_key, private_key):
    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


if __name__ == "__main__":
    # ------------------ Simulation ------------------

    # Bob's side
    bob_private_key, bob_public_key = generate_rsa_keys()
    bob_public_pem = serialize_public_key(bob_public_key)

    # Alice's side
    alice_public_key_for_bob = load_public_key(bob_public_pem)
    alice_symmetric_key = generate_symmetric_key()
    encrypted_key = encrypt_key(alice_symmetric_key, alice_public_key_for_bob)

    # Bob decrypts the symmetric key
    decrypted_key = decrypt_key(encrypted_key, bob_private_key)

    # ✅ Check that both parties have the same symmetric key
    print(f"Original symmetric key: {alice_symmetric_key.hex()}")
    print(f"Decrypted symmetric key: {decrypted_key.hex()}")
    print(f"Keys match: {alice_symmetric_key == decrypted_key}")
