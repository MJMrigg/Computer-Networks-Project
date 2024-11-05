import socket
import threading
import os
import sys

IP = socket.gethostbyname(socket.gethostname())
PORT = 65432
ADDR = (IP, PORT) # Address
SIZE = 1024 # Size of byte was're receiving
FORMAT = "utf-8" # Encoding and decoding
SERVER_PATH = "server"

# Handle a Client
def handle_client (conn, addr):
    print(f"NEW CONNECTION: {addr} connected.")
    conn.send("OK@WElcome to the server".encode(FORMAT))
    while True:
        data = conn.recv(SIZE).decode(FORMAT)
        data = data.split(" ")
        cmd = data[0]

        send_data = "OK"

        # Task to allow client to logout
        if cmd == "LOGOUT":
            break
        elif cmd == "TASK":
            send_data += "@LOGOUT from the server.\n"
            conn.send(send_data.encode(FORMAT))
        
    print(f"{addr} disconnected")
    conn.close()

def main():
    print("Starting the Sever")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) ## used the IPV4 and TCP connection
    server.bind(ADDR) # Bind the address
    server.listen() # Start listening
    print(f"Server is listening on {IP}: {PORT}")
    while True: # Multithreading
        conn, addr = server.accept() # Accept a connection from a client
        thread = threading.Thread(target = handle_client, args = (conn, addr)) # Assignning a thread to each client
        thread.start()
        # We keep this as an infinite loop to keep the server alive
    
if __name__ == "__main__":
    main()