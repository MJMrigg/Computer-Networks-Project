import os
import socket
import rsa
SIZE = 1024
FORMAT = "utf-8"
SERVER_DATA_PATH = "server_data"

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

    f = None
    # Get the file name from the server
    file_size = int(client_socket.recv(SIZE).decode(FORMAT))
    filename = args[0]
    downloads = get_download_path()
    filepath = f"{downloads}\{filename}"
    number = 0
    while(1):
        if(os.filepath.exists(filepath)):
            number += 1
            filename = filename.split("(")[0]
            filename = f"{filename}({number})"
            filepath = f"{downloads}\{filename}"
        else:
            break
    
    # Prepare to receive the file in chunks
    with open(f"{filepath}/{filename}", "a") as file:
        received_size = 0
        while received_size < file_size:
            # Determine chunk size (use SIZE or remaining bytes if less than SIZE)
            chunk_size = min(SIZE, file_size - received_size)
            chunk = client_socket.recv(chunk_size)

            if not chunk:  # End of data
                break

            # Write the chunk to the file and update the received size
            file.write(chunk)
            received_size += len(chunk)

    # Confirm download success to client
    print("File downloaded successfully to downloads folder.")

# FUNCTION: UPLOAD
def file_upload(client_socket, args):
    """
    Upload a file to the server
    Parameters:
    - client_socket: socket object for the client connection
    - args: command arguments containing the filename
    """

    filename = args[0]
    filepath = os.path.abspath(filename)

    # Check if file exists before sending
    if os.path.exists(filepath):
        
        with open(filepath, 'rb') as file:
            client_socket.sendall(file.read())  # Send file data
    else:
       print("File not found")
  
# MAIN FUNCTION
def main():
    IP = input("What is the IP Address of the server you wish to connect to? ")
    PORT = input("What is the port of the server you wish to connect to? ")
    ADDR = (str(IP), int(PORT))
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(ADDR)
    # Receive public key from server
    public_key = client.recv(SIZE).decode(FORMAT)
    public_key = int(public_key.split("@")[1])
    client.send(rsa("Ok@I have received your public key").encode(FORMAT), public_key)
    while True: # Multiple communSications
        data = client.recv(SIZE).decode(FORMAT)
        cmd = data.split("@")
        data = input("> ")
        data = data.split(" ").lower()
        cmd = data[0]      
        
        # Determine which command to execute
        if cmd == "upload":
            file_upload(client, data)
        elif cmd == "download":
            file_download(client, data)
        elif cmd == "delete":
            client.send(rsa.encrypt(data.encode(FORMAT), public_key))
        elif cmd == "dir":
            client.send(rsa.encrypt(data.encode(FORMAT), public_key))
        elif cmd == "subfolder":
            client.send(rsa.encrypt(data.encode(FORMAT), public_key))
        elif cmd == "logout":
            client.send(rsa.encrypt(data.encode(FORMAT), public_key))
            break
    print("Disconnectd from server.")
    client.close()

# main function is called
if __name__ == "__main__":
    main()
