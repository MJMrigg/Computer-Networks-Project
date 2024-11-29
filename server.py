import os
import socket
import threading
import rsa
import datetime
from analysis_component import *
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

# Function to handle each client connection
def client_handling(conn, addr):
    """
    Handles commands from a single client connection.
    Parameters:
    - conn: socket object for the client connection
    - addr: address of the client (IP, port)
    """
    print(f"NEW CONNECTION: {addr} connected.")
    
    # Prompt client to enter password needed to access the server
    conn.send(rsa.encrypt("Please Enter Passcode".encode(FORMAT), public_key))
    password = conn.recv(SIZE) # password the client entered
    if not password:
        return
    password = rsa.decrypt(password, private_key).decode(FORMAT) # Decrypt it
    if password != PASSWORD: # If it was not the correct PASSWORD, deny the client access to the server
        conn.send(rsa.encrypt("Access Denied. Passcode was incorrect.".encode(FORMAT), public_key))
        conn.close()
        print(f"{addr} was disconnected")
        return

    # Send welcome message to client
    conn.send(rsa.encrypt("Welcome to the server!@".encode(FORMAT), public_key))

    while True:
        try:
           # Receive encrypted data from client
            encrypted_request = conn.recv(SIZE)
            if not encrypted_request:
                break

            # Decrypt the received data
            request = rsa.decrypt(encrypted_request, private_key).decode(FORMAT)
            command, *args = request.split()

            # Determine which command to execute
            if command.lower() == "upload":
                file_upload(conn, args)
            elif command.lower() == "download":
                file_download(conn, args)
            elif command.lower() == "delete":
                file_delete(conn, args, public_key)
            elif command.lower() == "dir":
                directory_list(conn, public_key)
            elif command.lower() == "subfolder":
                subfolder_manager(conn, args, public_key)
            elif command.lower() == "logout":
                break
            elif command.lower() == "ping":
                conn.send(rsa.encrypt("ping".encode(FORMAT), public_key))
            else:
                conn.send(rsa.encrypt("Invalid command".encode(FORMAT), public_key))
        except Exception as e:
            conn.send(rsa.encrypt(f"Error, please try again.\n{e}".encode(FORMAT), public_key))
    # Close the connection when done
    print(f"{addr} disconnected")
    conn.close()

# Function to handle file uploads from client
# Function to handle file uploads from client in chunks
def file_upload(client_socket, args):
    """
    Uploads a file from the client in chunks, allowing for large file transfers.
    Parameters:
    - client_socket: socket object for the client connection
    - args: command arguments containing the filename
    """
    if len(args) < 1:
        client_socket.send(rsa.encrypt("Filename required.".encode(FORMAT), public_key))
        return

    # If the file already exists, ask if they want to override
    filepath = os.path.join(BASE_DIR, args[0])
    if(os.path.exists(filepath)):
        client_socket.send(rsa.encrypt("1@Error: File already exists. Do you want to overide it?".encode(FORMAT), public_key))
        answer = rsa.decrypt(client_socket.recv(SIZE), private_key).decode(FORMAT)
        if(answer[0].lower() == 'y'):
            client_socket.send(rsa.encrypt("0@Overiding File".encode(FORMAT), public_key))
        elif(answer[0].lower() == 'n'):
            # If they don't want to, create a copy of the file by adding a number at the end of it
            # But first, make sure there aren't already copies of the file that already exist
            number = 0
            while(1):
                number += 1
                path = filepath.split(".")[0]
                names = path.split(" (")
                filename = names[0]
                filetype = filepath.split(".")[1]
                newFilename = f"{filename} ({number})"
                filepath = f"{newFilename}.{filetype}"
                if(not(os.path.exists(filepath))):
                    break
            client_socket.send(rsa.encrypt(f"1@Creating copy of file under name {filepath}".encode(FORMAT), public_key))
        else:
           client_socket.send(rsa.encrypt("2@Invalid Response. Canceling Upload".encode(FORMAT), public_key))
           return
    else:
        client_socket.send(rsa.encrypt("0@".encode(FORMAT), public_key))
    # Prepare to receive the file in chunks
    msg = client_socket.recv(SIZE)
    file_size = int(rsa.decrypt(msg, private_key).decode(FORMAT))
    client_socket.send(rsa.encrypt("@".encode(FORMAT), public_key))
    progress = makeTQDM(file_size)
    with open(filepath, 'wb') as file:
        received_size = 0
        received_data = b''
        while received_size < file_size:
            # Determine chunk size (use SIZE or remaining bytes if less than SIZE)
            chunk_size = min(SIZE, file_size - received_size)
            chunk = client_socket.recv(chunk_size)

            if not chunk:  # End of data
                break

            # Write the chunk to the file and update the received size
            received_size += len(chunk)
            received_data += chunk
            progress.update(chunk_size)
        # Decrpyt the data and using AES and write it to the file
        decryptor = AES.new(cipher_key, AES.MODE_EAX, nonce)
        file.write(decryptor.decrypt(received_data))
        del decryptor
        del progress
        
    # Confirm upload success to client
    client_socket.send(rsa.encrypt("File uploaded successfully.".encode(FORMAT), public_key))


# Function to handle file downloads for client
def file_download(client_socket, args):
    """
    Send a file to the client for download.
    Parameters:
    - client_socket: socket object for the client connection
    - args: command arguments containing the filename
    """
    if len(args) < 1:
        client_socket.send(rsa.encrypt("Filename required.".encode(FORMAT), public_key))
        return

    filename = args[0]
    filepath = os.path.join(BASE_DIR, filename)
    filesize = os.path.getsize(filepath)

    # Check if file exists before sending
    if os.path.exists(filepath):
        client_socket.send(rsa.encrypt(f"{filesize}".encode(FORMAT), public_key))  # Send file size
        with open(filepath, 'rb') as file:
            # Use AES to encrypt the file data
            encryptor = AES.new(cipher_key, AES.MODE_EAX, nonce)
            encrypted = encryptor.encrypt(file.read())
            client_socket.sendall(encrypted)
            del encryptor
    else:
        client_socket.send(rsa.encrypt("File not found".encode(FORMAT), public_key))


# Function to handle file deletion requests from client
def file_delete(client_socket, args, key):
    """
    Delete a specified file on the server.
    Parameters:
    - client_socket: socket object for the client connection
    - args: command arguments containing the filename
    """
    if len(args) < 1:
        client_socket.send(rsa.encrypt("Filename required.".encode(FORMAT), key))
        return

    filename = args[0]
    filepath = os.path.join(BASE_DIR, filename)

    # Remove file if it exists
    if os.path.exists(filepath):
        os.remove(filepath)
        client_socket.send(rsa.encrypt("File successfully deleted".encode(FORMAT), key))
    else:
        client_socket.send(rsa.encrypt("File not found".encode(FORMAT), key))


# Function to list directory contents to client
def directory_list(client_socket, key):
    """
    List files in the server's base directory and send to client.
    Parameters:
    - client_socket: socket object for the client connection
    """
    files = os.listdir(BASE_DIR)
    response = "\n".join(files) if files else "No files found"
    client_socket.send(rsa.encrypt(response.encode(FORMAT), key))


# Function to manage subfolders (create or delete)
def subfolder_manager(client_socket, args, key):
    """
    Create or delete a subfolder as requested by the client.
    Parameters:
    - client_socket: socket object for the client connection
    - args: command arguments containing action and path
    """
    if len(args) < 2:
        client_socket.send(rsa.encrypt("Action and path required.".encode(FORMAT), key))
        return

    action, path = args
    full_path = os.path.join(BASE_DIR, path)

    # Create or delete subfolder based on action
    if action == "create":
        os.makedirs(full_path, exist_ok=True)
        client_socket.send(rsa.encrypt("Subfolder created".encode(FORMAT), key))
    elif action == "delete":
        if os.path.exists(full_path):
            os.rmdir(full_path)
            client_socket.send(rsa.encrypt("Subfolder deleted".encode(FORMAT), key))
        else:
            client_socket.send(rsa.encrypt("Subfolder not found".encode(FORMAT), key))
    else:
        client_socket.send(rsa.encrypt("Invalid command".encode(FORMAT), key))


# Function to start the server
def main():
    """
    Initialize and start the server to listen for client connections.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(ADDR)  # Bind server to address
    server_socket.listen()  # Listen for incoming connections
    print(f"Server listening on {ADDR}")

    # Accept new connections indefinitely
    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Connection from {client_address} at {datetime.datetime.now()}")

        # Start a new thread to handle this client's requests
        client_thread = threading.Thread(target=client_handling, args=(client_socket, client_address))
        client_thread.start()

        # Display active connection count
        active_threads = threading.active_count() - 1  # Exclude main thread
        print(f"[ACTIVE CONNECTIONS] {active_threads}")

# main function is called
if __name__ == "__main__":
    main()