import socket
import pickle
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class Client:
    def __init__(self, name):
        self.name = name
        self.client_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.client_public_key = self.client_private_key.public_key()
        self.server_public_key = None
        self.shared_key = None
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self, host, port):
        self.socket.connect((host, port))

    def send_public_key(self):
        self.socket.send(self.client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    def receive_server_public_key(self):
        server_public_key_bytes = self.socket.recv(4096)
        self.server_public_key = serialization.load_pem_public_key(
            server_public_key_bytes,
            backend=default_backend()
        )

    def receive_shared_key(self):
        self.shared_key = self.socket.recv(4096)

    def derive_aes_key(self):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key
            salt=None,
            info=b'',
            backend=default_backend()
        )
        return hkdf.derive(self.shared_key)

    def send_encrypted_message(self, message):
        aes_key = self.derive_aes_key()
        cipher = Cipher(algorithms.AES(aes_key), modes.CTR(b'\x00' * 16), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
        self.socket.send(encrypted_message)

    def receive_encrypted_message(self):
        aes_key = self.derive_aes_key()
        encrypted_message = self.socket.recv(4096)
        cipher = Cipher(algorithms.AES(aes_key), modes.CTR(b'\x00' * 16), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
        return decrypted_message.decode()

    def close_connection(self):
        self.socket.close()

def main():
    alice = Client("Alice")
    alice.connect("localhost", 12345)
    alice.send_public_key()
    alice.receive_server_public_key()
    alice.receive_shared_key()
    message = "Hello from Alice!"
    print("Original Message:", message)
    alice.send_encrypted_message(message)
    received_message = alice.receive_encrypted_message()
    print("Received Message:", received_message)
    alice.close_connection()

if __name__ == "__main__":
    main()
