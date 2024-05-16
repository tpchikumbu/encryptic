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

from Bob import bob_public_key
from generate_ca import ca_private_key

# Load CA's public key and certificate
with open("ca_public_key.pem", "rb") as f:
    ca_public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

with open("ca_cert.pem", "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read(), backend=default_backend())

# Generate Alice's private key and certificate
alice_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
alice_public_key = alice_private_key.public_key()

# Create a certificate for Alice signed by the CA
subject = issuer = x509.Name([
    x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, u"US"),
    x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, u"California"),
    x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, u"San Francisco"),
    x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, u"My Company"),
    x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u"Alice"),
])
cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    alice_public_key
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

alice_cert = cert.public_bytes(serialization.Encoding.PEM)

# Connect to Bob
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(("localhost", 12345))

# Send Alice's certificate
client_socket.send(alice_cert)

# Receive and verify Bob's certificate
bob_cert_bytes = client_socket.recv(4096)
bob_cert = x509.load_pem_x509_certificate(bob_cert_bytes, backend=default_backend())

# Verify Bob's certificate
try:
    ca_public_key.verify(
        bob_cert.signature,
        bob_cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        bob_cert.signature_hash_algorithm,
    )
except ValueError:
    print("Bob's certificate is not valid!")
    exit(1)

# Perform Diffie-Hellman key exchange
alice_dh_parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
alice_dh_private_key = alice_dh_parameters.generate_private_key()
alice_dh_public_key = alice_dh_private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
client_socket.send(alice_dh_public_key)
bob_dh_public_key = client_socket.recv(4096)
shared_key = alice_dh_private_key.exchange(serialization.load_pem_public_key(bob_dh_public_key, backend=default_backend()))

# Derive AES key from shared key
hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'',
    backend=default_backend()
)
aes_key = hkdf.derive(shared_key)

# Load image and caption
image_path = "image.png"
with open(image_path, "rb") as f:
    image_data = f.read()
caption = "This is a beautiful image."

# Compress and hash the message
compressed_message = zlib.compress(caption.encode() + b"||" + image_data)
print("Compressed Message:", compressed_message)
message_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
message_hash.update(compressed_message)
message_digest = message_hash.finalize()
print("Message Digest (SHA-256):", message_digest.hex())

# Encrypt the message
cipher = Cipher(algorithms.AES(aes_key), modes.CBC(b'\x00' * 16), backend=default_backend())
encryptor = cipher.encryptor()
encrypted_message = encryptor.update(compressed_message) + encryptor.finalize()
print("Encrypted Message:", encrypted_message)

# Encrypt the message digest with Bob's public key
encrypted_digest = bob_public_key.encrypt(
    message_digest,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print("Encrypted Digest:", encrypted_digest)

# Send the encrypted message and digest
client_socket.send(encrypted_message)
client_socket.send(encrypted_digest)

print("Original Message:", caption)

# Close the connection
client_socket.close()