The Socket-Based Networked File Sharing Cloud Server is a program that allows for users to run a server on their own computer that other computers in the same network can connected to and interact with.

Set-Up:
Before starting a server or attempting to connect to an already existing server, your computer must be set up properly first. Your computer must also be a computer with at least Windows 11, as that was what the system was designed for. The steps to set up the computer are as follows:
1.) Install the computing language python on your computer. This will allow your computer to be able to interpret and run the files
Link: https://www.python.org/downloads/
2.) Install the required python libraries. To do this, you must use your computer's command prompt and navigate to wherever you are storing the files for the system and run the following command:
py -m pip install -r requirements.txt

Connecting to an Already Existing Server:
The system allows users to connect to an already existing server within the same network as their computer. To connect to an already existing server, follow the steps below:
1.) Run the Client.py file. 
2.) Type in the server's IP Address and Port Number when prompted to do so. Note, you must have a way of finding this out from the computer where the server is running.
3.) The server will have a passcode to enter. This is for security reasons. You must have a way finding out this password from the person running the server computer.
Possible Explanations for Connection Errors:
1.) Certain security measure's on the server's computer may be preventing you from connecting to it. Ask the server's owner to remove them if possible.
2.) The server is not in the same network as your computer. Ask the server's owner what network the server is connected to, connect to it, and try again
3.) One of the files containing encryption and decryption keys is missing. Ask the server's owner to send you the missing files, as if they are missing, the client will refuse to run.

Client-Server Interactions:
There are numerous interactions that a client can have with a server. All of the interactions are done via typing into the interface. The commands to trigger these interactions are as follows
1.) Upload File - upload filepath/filename
2.) Download File - download filepath/filename
3.) Delete File - delete filepath/filename
4.) Create Subfolder - subfolder create path/name
5.) Delete Subfolder - subfolder delete path/name
6.) View all Directories - dir
7.) Test Connection - ping
8.) Logout - logout

Creating and Running a New Server:
The system allows users to create and run a new server. To do so, run the server.py file. When this happens, the server's IP Address and Port Number will appear on the screen. The user must have a way to communicate this information, along with the passcode to access the server, with all of their potential client.