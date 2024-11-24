import os
import socket
import rsa
SIZE = 1024
FORMAT = "utf-8"
SERVER_DATA_PATH = "server_data"

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


# FUNCTION: DOWNLOAD
def file_download(client_socket, args):
    """
    Downloads a file from the server in chunks, allowing for large file transfers.
    Parameters:
    - client_socket: socket object for the client connection
    - args: command arguments containing the filename
    """
    def get_download_path():
        import winreg
        """Returns the default downloads path for linux or windows"""
        if os.name == 'nt':
            sub_key = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'
            downloads_guid = '{374DE290-123F-4565-9164-39C4925E467B}'
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub_key) as key:
                location = winreg.QueryValueEx(key, downloads_guid)[0]
            return location
        else:
            return os.path.join(os.path.expanduser('~'), 'downloads')

    # Get the file name from the server
    response = rsa.decrypt(client_socket.recv(SIZE), private_key).decode(FORMAT)
    if(response == 'File not found'):
        print("File not found")
        return
    if(response == 'Filename required'):
        print("Filename required")
        return
    file_size = int(response)
    filename = args[0]

    # Set the path to the client's downloads folder 
    downloads = get_download_path()
    filepath = os.path.join(downloads, filename)
    number = 0
    # Check to see if it already exists in the downloads folder. If it does, at a number at the end
    while(1):
        if(os.path.exists(filepath)):
            number += 1
            filename = filename.split(".")[0]
            filename = filename.split(" (")
            filename = filename[len(filename)-2]
            filename = f"{filename} ({number})"
            filepath = f"{downloads}\{filename}"
        else:
            break
    
    # Prepare to receive the file in chunks
    with open(filepath, 'wb') as file:
        received_size = 0
        received_data = b""
        while received_size < file_size:
            # Determine chunk size (use SIZE or remaining bytes if less than SIZE)
            chunk_size = min(SIZE, file_size - received_size)
            chunk = client_socket.recv(chunk_size)

            if not chunk:  # End of data
                break
            
            received_size += len(chunk) # Update received size
            received_data = received_data + chunk
            print(received_data)
        
        # Write the data to the file and update
        file.write(received_data)

    # Confirm download success to client
    print("File downloaded successfully to downloads folder.")

# FUNCTION: UPLOAD
def file_upload(client_socket, args, key):
    """
    Upload a file to the server
    Parameters:
    - client_socket: socket object for the client connection
    - args: command arguments containing the filename
    """
    if(len(args) < 1):
        return 1
    filename = args[0]
    filepath = os.path.abspath(filename)

    # Check if file exists before sending
    if os.path.exists(filepath):
        client_socket.send(rsa.encrypt(f"{os.path.getsize(filepath)}".encode(FORMAT), key))  # Send file size
        with open(filepath, 'rb') as file:
            client_socket.sendall(f"{file.read()}".encode(FORMAT))  # Send file data
        return 1
    else:
       print("File not found")
       return 0
  
# MAIN FUNCTION
def main():
    IP = input("What is the IP Address of the server you wish to connect to? ")
    PORT = input("What is the port of the server you wish to connect to? ")
    ADDR = (str(IP), int(PORT))
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(ADDR)
    waiting = 1 # Wait for a response
    
    while True: # Multiple communications
        if(waiting == 1): # If the client is waiting for a response, receive and print that response
            data = rsa.decrypt(client.recv(SIZE), private_key).decode(FORMAT)
            data = data.split("@")
            print(data[0])
            if data[0] == "Access Denied. Passcode was incorrect.": # If the client didn't input the correct passcode
                break
        data = input("> ")
        cmd, *args = data.split()

        # Send the server the command
        client.send(rsa.encrypt(data.encode(FORMAT), public_key))
        waiting = 1
        # Certain answers to certain commands require more logic
        if cmd.lower() == "upload":
            # What happens in this function will determine if the client ends up waiting for a response or not
            waiting = file_upload(client, args, public_key)
        elif cmd.lower() == "download":
            file_download(client, args)
            waiting = 0
        elif cmd.lower() == "logout":
            break
    print("Disconnectd from server.")
    client.close()

# main function is called
if __name__ == "__main__":
    main()