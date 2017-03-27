# distributedFileServer
 Authenticated, secure, and well optimized Distributed file server for reliable file storage and retrieval 
## Author- Rishabh Hastu

## What's Implemented?
- Optimised and reliable GET
- PUT
- LIST
- Encryption
- Subfolder
- User Authentication
- Multiple Connections
- Time out

* Python Version : 3.5 *
## Program Usage
```
For Distributed File Server

      $ python dfs.py [Folder] [Port]

Folder: Specify the name of folder for the DFS instance. Select from "DFS1","DFS2","DFS3","DFS4"
Port: Specify the port number between 1025 and 65535

For Distributed File CLient

      $ python dfc.py [config file]
      
config file: (optional) Name of the DFC config file
```
## Whats in the progrm?
1. After the user input is taken, sockets are created and user authentication happens

2. The Put function breaks the file (if present) into 8 pieces, encrypts them using ferret library and sends them to the respected servers under the directory of the username. If subfolder is given as an input, the pieces are placed inside the subfolder which is in the username folder.

3. The Get function checks for the optimised way to get the pieces so that they can be used to regenerate the file to get. First, the pieces are checked at the server 1 and server 4. If present, the pieces are forwarded to the client which decrypts them and regerated them into a file under the directory of the user. If  the files are not present, the client will search for the missing piece in the server 2 or 4 depending on which server has the piece. If the required 4 pieces are not given to the client, it doesnt make the file and prints that the file cannot be constructable. If the subfolder is provided, the client will ask for the files inside the subfolder in the server and repeat the same process.

4. The List function will ask for all the pieces from the all the servers, and will check which of the files can be reconstructable and which of the files have a missing piece. The files which are reconstructable are printed as it is, while the files which cannot be reconstructed are printed with [incomplete] in front of it. The subfolder feature allows the client to list the files under the subfolder at each server and prints the files as above.

## HOW TO TEST?:
1. Open the client file in cmd and either pass an argument of the config file to test multiple user connections or dont pass any argument. The client will choose a default config file.
2. Enter the valid PUT, GET, LIST or EXIT command. Any invalid command will not go through.
3. Either put a subfolder name infront of (PUT, GET)filename or LIST command or avoid the subfolder name. The program will handle both the cases
4. If the file is not present, the client will print "FILE NOT FOUND"
5. If the file is present, the client will make the folder of the username and save the file there.
