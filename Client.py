import os
import socket
import rsa
from Cryptodome.Cipher import AES
from analysis_component import *
SIZE = 1024
FORMAT = "utf-8"

# Encryption/Decryption key loading
keys = [1] # Assume the keys will be sucessfully loaded
def load_keys():
    # Check if keys already exist
    if os.path.exists("private_key.pem") and os.path.exists("public_key.pem") and os.path.exists("cipher_key.pem") and os.path.exists("nonce.pem"):
        # Load existing keys
        with open("public_key.pem", "rb") as f:
            public_key = rsa.PublicKey.load_pkcs1(f.read())
        with open("private_key.pem", "rb") as f:
            private_key = rsa.PrivateKey.load_pkcs1(f.read())
        with open("cipher_key.pem", "rb") as f:
            cipher_key = f.read()
        with open("nonce.pem", "rb") as f:
            nonce = f.read()
        return public_key, private_key, cipher_key, nonce
    else:
        print("Error: One or more Encryption Keys have been deleted from your computer")
        keys[0] = 0
        # Client does not generate their own RSA and AES keys because of the risk of them being different from the Server's


# Load RSA and AES keys
public_key, private_key, cipher_key, nonce = load_keys()

# FUNCTION: DOWNLOAD
def file_download(client_socket, args):
    """
    Downloads a file from the server in chunks, allowing for large file transfers.
    Parameters:
    - client_socket: socket object for the client connection
    - args: command arguments containing the filename
    """

    # Function to get the Downloads path on the client's machine
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
    
    try:
        # See if the file could be retrieved from the server
        response = rsa.decrypt(client_socket.recv(SIZE), private_key).decode(FORMAT)
        if(response == 'File not found'):
            print("File not found")
            return
        if(response == 'Filename required'):
            print("Filename required")
            return
        # If it could, set its path and receive its data
        file_size = int(response)
        name = args[0]
        name = name.split("\\")
        filename = name[len(name)-1]
        # Set the path to the client's Downloads folder 
        downloads = get_download_path()
        filepath = f"{downloads}\{filename}"
        number = 0
        print(f"Downloading {filename}...")
        progress = makeTQDM(file_size)
        # Check to see if the file already exists in the Downloads folder. If it does, add a number at the end
        while(1):
            if(os.path.exists(filepath)):
                number += 1
                filetype = filename.split(".")[1]
                filename = filename.split(".")[0]
                filename = filename.split(" (")
                filename = filename[len(filename)-2]
                filename = f"{filename} ({number}).{filetype}"
                filepath = f"{downloads}\{filename}"
            else:
                break
        # Prepare to receive the file in chunks
        with open(filepath, 'wb') as file:
            received_size = 0
            received_data = b"" # File data
            while received_size < file_size:
                # Determine chunk size (use SIZE or remaining bytes if less than SIZE)
                chunk_size = min(SIZE, file_size - received_size)
                chunk = client_socket.recv(chunk_size)

                if not chunk:  # End of data
                    break
                
                received_size += len(chunk) # Update received size
                received_data = received_data + chunk # Add the data to he received data
                progress.update(chunk_size)
            
            # Decrypt the data using AES and write it to the file
            decryptor = AES.new(cipher_key, AES.MODE_EAX, nonce)
            file.write(decryptor.decrypt(received_data))
            del decryptor
            del progress

        # Confirm download success to client
        print("File Sucessfully Downloaded. You can find it in your Downloads folder.")
    except Exception as e:
        print(f"Error, Please try again.\n{e}")
        return

# FUNCTION: UPLOAD
def file_upload(client_socket, args):
    """
    Upload a file to the server
    Parameters:
    - client_socket: socket object for the client connection
    - args: command arguments containing the filename
    """
    # If the client forgot to specify a name for the file
    if(len(args) < 1):
        return 1
    
    # Make sure the client isn't overiding a file
    override = rsa.decrypt(client_socket.recv(SIZE), private_key).decode(FORMAT)
    override = override.split("@")
    if(override[0] == "1"): # If they were overiding a file, ask if the client hey want to go through with
        print(override[1])
        answer = input("> ")
        client_socket.send(rsa.encrypt(answer.encode(FORMAT), public_key))
        response = rsa.decrypt(client_socket.recv(SIZE), private_key).decode(FORMAT)
        response = response.split("@")
        print(response[1]) # Print the server's response
        if(response[0] == "2"):
            return 0 # If the client submitted an invalid answer, stop the upload process
    elif(override[0] != "0"): # If an error happened
        print(override)
        return 1

    filename = args[0]
    filepath = os.path.abspath(filename)
    filesize = os.path.getsize(filepath)

    # Check if file exists before sending
    if os.path.exists(filepath):
        client_socket.send(rsa.encrypt(f"{filesize}".encode(FORMAT), public_key)) # Send file size
        rsa.decrypt(client_socket.recv(SIZE), private_key).decode(FORMAT) # Receive acknowledgement
        print(f"Uploading {filename}(This may take some time)")
        # Send the file contents
        with open(filepath, 'rb') as file:
            # Encrypt and send File data
            encryptor = AES.new(cipher_key, AES.MODE_EAX, nonce)
            client_socket.sendall(encryptor.encrypt(file.read()))
            del encryptor
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
            waiting = file_upload(client, args)
        elif cmd.lower() == "download":
            file_download(client, args)
            waiting = 0 # In this case, the server's responses will be just the file data, so we will not wait for the server's to send something after the file is downloaded
        elif cmd.lower() == "logout":
            break
    print("Disconnectd from server.")
    client.close()

# If RSA and AES keys were sucessfully loaded, run the main function
if keys[0] == 1:
    if __name__ == "__main__":
        main()
