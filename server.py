import os
import socket
import threading
import rsa
import datetime

# Server configuration
IP = socket.gethostbyname(socket.gethostname()) # Server hostname
PORT = 4450  # Server port
ADDR = (IP, PORT)  # Server address (IP, Port)
SIZE = 1024  # Buffer size for receiving data
FORMAT = "utf-8"  # Encoding format for messages
BASE_DIR = "./server_files"  # Directory to store uploaded files
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
    else:
        # Generate new keys
        public_key, private_key = rsa.newkeys(2048)
        # Save keys to files
        with open("public_key.pem", "wb") as f:
            f.write(public_key.save_pkcs1("PEM"))
        with open("private_key.pem", "wb") as f:
            f.write(private_key.save_pkcs1("PEM"))
    return public_key, private_key


# Load or generate RSA keys
public_key, private_key = load_or_generate_keys()


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

    try:
        while True:
           # Receive encrypted data from client
            encrypted_request = conn.recv(SIZE)
            if not encrypted_request:
                break

            # Decrypt the received data
            request = rsa.decrypt(encrypted_request, private_key).decode(FORMAT)
            command, *args = request.split()

            # Determine which command to execute
            if command.lower() == "upload":
                file_upload(conn, args, public_key)
            elif command.lower() == "download":
                file_download(conn, args, public_key)
                conn.send(rsa.encrypt('~~~~'.encode(FORMAT), public_key)) 
                # This will send a place holder message so that the connection can remain open
                # Use the the '~' because it is a very rarely used character and not likely to be used again in this code
            elif command.lower() == "delete":
                file_delete(conn, args, public_key)
            elif command.lower() == "dir":
                directory_list(conn, public_key)
            elif command.lower() == "subfolder":
                subfolder_manager(conn, args, public_key)
            elif command.lower() == "logout":
                break
            else:
                conn.send(rsa.encrypt("Invalid command".encode(FORMAT), public_key))
    except Exception as e:
        conn.send(rsa.encrypt(f"Error, please try again.\n{e}".encode(FORMAT), public_key))
    # Close the connection when done
    print(f"{addr} disconnected")
    conn.close()

# Function to handle file uploads from client
# Function to handle file uploads from client in chunks
def file_upload(client_socket, args, key):
    """
    Uploads a file from the client in chunks, allowing for large file transfers.
    Parameters:
    - client_socket: socket object for the client connection
    - args: command arguments containing the filename
    """
    if len(args) < 1:
        client_socket.send(rsa.encrypt("Filename required.".encode(FORMAT), key))
        return

    # Retrieve the filename and expected file size from the client
    filename = args[0]
    file_size = int(rsa.decrypt(client_socket.recv(SIZE), private_key).decode(FORMAT))
    filepath = os.path.join(BASE_DIR, filename)

    # Prepare to receive the file in chunks
    with open(filepath, 'wb') as file:
        received_size = 0
        while received_size < file_size:
            # Determine chunk size (use SIZE or remaining bytes if less than SIZE)
            chunk_size = min(SIZE, file_size - received_size)
            chunk = client_socket.recv(chunk_size).decode(FORMAT)

            if not chunk:  # End of data
                break

            # Write the chunk to the file and update the received size
            file.write(chunk)
            received_size += len(chunk)

    # Confirm upload success to client
    client_socket.send(rsa.encrypt("File uploaded successfully.".encode(FORMAT), key))


# Function to handle file downloads for client
def file_download(client_socket, args, key):
    """
    Send a file to the client for download.
    Parameters:
    - client_socket: socket object for the client connection
    - args: command arguments containing the filename
    """
    if len(args) < 1:
        client_socket.send(rsa.encrypt("Filename required.".encode(FORMAT), key))
        return

    filename = args[0]
    filepath = os.path.join(BASE_DIR, filename)

    # Check if file exists before sending
    if os.path.exists(filepath):
        client_socket.send(rsa.encrypt(f"{os.path.getsize(filepath)}".encode(FORMAT), key))  # Send file size
        with open(filepath, 'rb') as file:
            client_socket.sendall(f"{file.read()}".encode(FORMAT))  # Send file data
    else:
        client_socket.send(rsa.encrypt("File not found".encode(FORMAT), key))


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