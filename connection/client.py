# On client side:
import os
import socket
SIZE = 1024
FORMAT = "utf-8"
SERVER_DATA_PATH = "server_data"

def main():
    IP = input("What is the IP Address of the server you wish to connect to? ")
    PORT = input("What is the port of the server you wish to connect to? ")
    ADDR = (str(IP), int(PORT))
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(ADDR)
    while True: # Multiple communSications
        data = client.recv(SIZE).decode(FORMAT)
        cmd = data.split("@")
        msg = cmd[0]
        if msg == "OK":
            print(f"{msg}")
        elif msg == "DISCONNECTED":
            print(f"{msg}")
            break
        data = input("> ")
        data = data.split(" ")
        cmd = data[0]
        print(cmd)
        if cmd == "TASK":
            client.send(cmd.encode(FORMAT))
        elif cmd == "LOGOUT":
            client.send(cmd.encode(FORMAT))
            break
    print("Disconnectd from server.")
    client.close()

if __name__ == "__main__":
    main()