import os
import socket
import threading
import rsa
import datetime
import tqdm
from Cryptodome.Cipher import AES

# Server configuration
IP = socket.gethostbyname(socket.gethostname()) # Server hostname
PORT = 4450  # Server port
ADDR = (IP, PORT)  # Server address (IP, Port)
SIZE = 1024  # Buffer size for receiving data
FORMAT = "utf-8"  # Encoding format for messages
BASE_DIR = "server_files"  # Directory to store uploaded files
PASSWORD = "Rosebud26" # Password to access the server

# Ensure base directory exists for file storage
if not os.path.exists(BASE_DIR):
    os.makedirs(BASE_DIR)


# RSA key loading/generation
def load_or_generate_keys():
    # Check if keys already exist
    if os.path.exists("private_key.pem") and os.path.exists("public_key.pem"):
        # Load existing keys
        with open("public_key.pem", "rb") as f:
            public_key = rsa.PublicKey.load_pkcs1(f.read())
        with open("private_key.pem", "rb") as f:
            private_key = rsa.PrivateKey.load_pkcs1(f.read())
        with open("cipher_key.pem", "rb") as f:
            cipher_key = f.read()
        with open("nonce.pem", "rb") as f:
            nonce = f.read()
    else:
        # Generate new keys
        public_key, private_key = rsa.newkeys(2048)
        cipher_key = os.urandom(16)
        nonce = os.urandom(16)
        # Save keys to files
        with open("public_key.pem", "wb") as f:
            f.write(public_key.save_pkcs1("PEM"))
        with open("private_key.pem", "wb") as f:
            f.write(private_key.save_pkcs1("PEM"))
        with open("cipher_key.pem", "wb") as f:
            f.write(cipher_key)
        with open("nonce.pem", "wb") as f:
            f.write(nonce)
    return public_key, private_key, cipher_key, nonce

# Load or generate RSA keys and create AES encryptor and decryptor
public_key, private_key, cipher_key, nonce = load_or_generate_keys()
encryptor = AES.new(cipher_key, AES.MODE_EAX, nonce)
decryptor = AES.new(cipher_key, AES.MODE_EAX, nonce)

with open("server_files\\test\\test.txt", "rb") as file:
    file_data = file.read()
    print(file_data)
    e = encryptor.encrypt(file_data)
    d = decryptor.decrypt(e)
    print(e)
    print(d)
with open("eee.txt", "wb") as file:
    file.write(e)