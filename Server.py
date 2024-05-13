import socket
import pickle
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.clients = []
        self.server_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.server_public_key = self.server_private_key.public_key()
        self.ca_public_key = None
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self):
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        print(f"Server listening on {self.host}:{self.port}")
        #while True:
        #    client_socket, _ = self.socket.accept()
        #    client = ClientConnection(client_socket, self.server_private_key, self.server_public_key)
        #    self.clients.append(client)
        #    client.start()

        # Separate thread for each client connection
        conn_thread = threading.Thread(target=self.thread_client, daemon=True)
        conn_thread.start()
        
        while True:
            cmd = input("Enter 'exit' to close server\n")
            if cmd == "exit":
                print("Closing server")
                self.socket.close()
                print(self.socket)
                return

    def thread_client(self):
        while True:
            try:
                client_socket, _ = self.socket.accept()
            except Exception as e:
                print("Closed socket")
                break
            client = ClientConnection(client_socket, self.server_private_key, self.server_public_key)
            self.clients.append(client)
            client.start()

class ClientConnection:
    def __init__(self, socket, server_private_key, server_public_key):
        self.socket = socket
        self.server_private_key = server_private_key
        self.server_public_key = server_public_key
        self.client_public_key = None
        self.shared_key = None

    def start(self):
        self.exchange_public_keys()
        self.exchange_shared_key()

    def exchange_public_keys(self):
        self.socket.send(self.server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        client_public_key_bytes = self.socket.recv(4096)
        self.client_public_key = serialization.load_pem_public_key(
            client_public_key_bytes,
            backend=default_backend()
        )

    def exchange_shared_key(self):
        shared_key = b'SharedKey'  # Generate a shared key securely, this is just a placeholder
        self.socket.send(shared_key)

def main():
    server = Server("localhost", 12345)
    server.start()

if __name__ == "__main__":
    main()
