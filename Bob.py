import socket
import os
import datetime
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, dh
from cryptography.hazmat.primitives import serialization, hashes, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import zlib

from Alice import alice_public_key
from generate_ca import ca_private_key

# Load CA's public key and certificate
with open("ca_public_key.pem", "rb") as f:
    ca_public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

with open("ca_cert.pem", "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read(), backend=default_backend())

# Generate Bob's private key and certificate
bob_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
bob_public_key = bob_private_key.public_key()

# Create a certificate for Bob signed by the CA
subject = issuer = x509.Name([
    x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, u"US"),
    x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, u"California"),
    x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, u"San Francisco"),
    x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, u"My Company"),
    x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u"Bob"),
])
cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    bob_public_key
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.utcnow()
).not_valid_after(
    datetime.datetime.utcnow() + datetime.timedelta(days=365)
).add_extension(
    x509.SubjectAlternativeName([x509.IPAddress(socket.gethostbyname("localhost"))]),
    critical=False,
).sign(ca_private_key, hashes.SHA256(), default_backend())

bob_cert = cert.public_bytes(serialization.Encoding.PEM)

# Start the server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("localhost", 12345))
server_socket.listen(1)
print("Server listening on localhost:12345")

# Accept a connection from Alice
client_socket, _ = server_socket.accept()

# Exchange certificates and verify
alice_cert_bytes = client_socket.recv(4096)
alice_cert = x509.load_pem_x509_certificate(alice_cert_bytes, backend=default_backend())

# Verify Alice's certificate
try:
    ca_public_key.verify(
        alice_cert.signature,
        alice_cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        alice_cert.signature_hash_algorithm,
    )
except ValueError:
    print("Alice's certificate is not valid!")
    exit(1)

# Send Bob's certificate
client_socket.send(bob_cert)

# Perform Diffie-Hellman key exchange
bob_dh_parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
bob_dh_private_key = bob_dh_parameters.generate_private_key()
bob_dh_public_key = bob_dh_private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
alice_dh_public_key = client_socket.recv(4096)
shared_key = bob_dh_private_key.exchange(serialization.load_pem_public_key(alice_dh_public_key, backend=default_backend()))

# Derive AES key from shared key
hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'',
    backend=default_backend()
)
aes_key = hkdf.derive(shared_key)

# Receive the encrypted message and digest
encrypted_message = client_socket.recv(4096)
print("Received Encrypted Message:", encrypted_message)
encrypted_digest = client_socket.recv(4096)
print("Received Encrypted Digest:", encrypted_digest)

# Decrypt the message
cipher = Cipher(algorithms.AES(aes_key), modes.CBC(b'\x00' * 16), backend=default_backend())
decryptor = cipher.decryptor()
compressed_message = decryptor.update(encrypted_message) + decryptor.finalize()
print("Decrypted (Compressed) Message:", compressed_message)

# Verify the message integrity
message_digest = alice_public_key.decrypt(
    encrypted_digest,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print("Decrypted Digest (SHA-256):", message_digest.hex())

message_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
message_hash.update(compressed_message)
computed_digest = message_hash.finalize()
print("Computed Digest (SHA-256):", computed_digest.hex())

if message_digest != computed_digest:
    print("Message integrity check failed!")
    exit(1)

# Decompress the message
decompressed_message = zlib.decompress(compressed_message)
caption, image_data = decompressed_message.split(b"||")

# Save the image and display the caption
with open("received_image.png", "wb") as f:
    f.write(image_data)
print("Caption:", caption.decode())

# Close the connection
client_socket.close()
server_socket.close()