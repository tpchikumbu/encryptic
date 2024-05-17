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
alice_private_key, alice_public_key = generate_rsa_key_pair()
save_private_key(alice_private_key, 'alice_private_key.pem')
save_public_key(alice_public_key, 'alice_public_key.pem')

# Load Bob's public key (assuming it is saved in 'bob_public_key.pem')
bob_public_key = load_public_key('bob_public_key.pem')

# Diffie-Hellman key exchange
parameters = dh.generate_parameters(generator=2, key_size=2048)
alice_dh_private_key = parameters.generate_private_key()
alice_dh_public_key = alice_dh_private_key.public_key()

# Networking functions
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(1)
    print("Server started, waiting for connection...")
    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")

    try:
        # Send public key and receive Bob's public key
        conn.sendall(alice_public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        bob_public_key_pem = conn.recv(1024)
        bob_public_key = serialization.load_pem_public_key(bob_public_key_pem)

        # Receive Bob's DH public key and send Alice's DH public key
        bob_dh_public_key_pem = conn.recv(1024)
        bob_dh_public_key = serialization.load_pem_public_key(bob_dh_public_key_pem)
        conn.sendall(alice_dh_public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

        # Compute shared key
        alice_shared_key = alice_dh_private_key.exchange(bob_dh_public_key)

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(alice_shared_key)

        # Create a Fernet key for encryption
        fernet_key = base64.urlsafe_b64encode(derived_key[:32])
        cipher = Fernet(fernet_key)

        # Encrypt and send a message
        message = "Hello from Alice"
        encrypted_message = cipher.encrypt(message.encode())
        conn.sendall(encrypted_message)

        # Receive and decrypt a message
        encrypted_message = conn.recv(1024)
        decrypted_message = cipher.decrypt(encrypted_message)
        print("Decrypted message from Bob:", decrypted_message.decode())

        # Send and receive an image
        with open("image_to_send.png", "rb") as image_file:
            image_data = image_file.read()
        encrypted_image_data = cipher.encrypt(image_data)
        conn.sendall(encrypted_image_data)

        encrypted_image_data = conn.recv(10240)
        decrypted_image_data = cipher.decrypt(encrypted_image_data)
        with open("received_image.png", "wb") as image_file:
            image_file.write(decrypted_image_data)

    except Exception as e:
        print(f"An error occurred: {e}")

    finally:
        conn.close()
        server_socket.close()

# Start the server
server_thread = threading.Thread(target=start_server)
server_thread.start()
server_thread.join()
