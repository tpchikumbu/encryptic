import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.fernet import Fernet
import base64
import os

# Key generation functions
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_private_key(private_key, filename):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, 'wb') as f:
        f.write(pem)

def save_public_key(public_key, filename):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, 'wb') as f:
        f.write(pem)

def load_private_key(filename):
    with open(filename, 'rb') as f:
        pem = f.read()
    private_key = serialization.load_pem_private_key(pem, password=None)
    return private_key

def load_public_key(filename):
    with open(filename, 'rb') as f:
        pem = f.read()
    public_key = serialization.load_pem_public_key(pem)
    return public_key

# Generate and save keys
bob_private_key, bob_public_key = generate_rsa_key_pair()
save_private_key(bob_private_key, 'bob_private_key.pem')
save_public_key(bob_public_key, 'bob_public_key.pem')

# Load Alice's public key (assuming it is saved in 'alice_public_key.pem')
alice_public_key = load_public_key('alice_public_key.pem')

# Diffie-Hellman key exchange
parameters = dh.generate_parameters(generator=2, key_size=2048)
bob_dh_private_key = parameters.generate_private_key()
bob_dh_public_key = bob_dh_private_key.public_key()

# Networking functions
def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))

    try:
        # Receive Alice's public key and send Bob's public key
        alice_public_key_pem = client_socket.recv(1024)
        alice_public_key = serialization.load_pem_public_key(alice_public_key_pem)
        client_socket.sendall(bob_public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

        # Send Bob's DH public key and receive Alice's DH public key
        client_socket.sendall(bob_dh_public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        alice_dh_public_key_pem = client_socket.recv(1024)
        alice_dh_public_key = serialization.load_pem_public_key(alice_dh_public_key_pem)

        # Compute shared key
        bob_shared_key = bob_dh_private_key.exchange(alice_dh_public_key)

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(bob_shared_key)

        # Create a Fernet key for encryption
        fernet_key = base64.urlsafe_b64encode(derived_key[:32])
        cipher = Fernet(fernet_key)

        # Receive and decrypt a message
        encrypted_message = client_socket.recv(1024)
        decrypted_message = cipher.decrypt(encrypted_message)
        print("Decrypted message from Alice:", decrypted_message.decode())

        # Encrypt and send a message
        message = "Hello from Bob"
        encrypted_message = cipher.encrypt(message.encode())
        client_socket.sendall(encrypted_message)

        # Receive and send an image
        encrypted_image_data = client_socket.recv(10240)
        decrypted_image_data = cipher.decrypt(encrypted_image_data)
        with open("received_image.png", "wb") as image_file:
            image_file.write(decrypted_image_data)

        with open("image_to_send.png", "rb") as image_file:
            image_data = image_file.read()
        encrypted_image_data = cipher.encrypt(image_data)
        client_socket.sendall(encrypted_image_data)

    except Exception as e:
        print(f"An error occurred: {e}")

    finally:
        client_socket.close()

# Start the client
client_thread = threading.Thread(target=start_client)
client_thread.start()
client_thread.join()
