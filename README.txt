================={Mystic CLI messaging app}=================
A python multi-user, multi-thread chat application supporting global chat, private messaging, group messaging, and file downloads. Messaging takes place over TCP connection, and downloads can be selected under TCP or UDP.

-----------------{Requirements}-----------------
To run this application you should:
    -Run the program on windows (not tested for other operating systems)
    -Use python 3.10 or higher

-----------------{File Structure}-----------------
server.py   - The server side code for handling message routing logic
client.py   - The client side code for interfacing the command line based off server responses
SharedFiles/    - Server folder for storing the downloadable files (created via server.py)
<user>/     - Each users folder to download server files into

-----------------{Usage}-----------------
To run the server, use the command:
python server.py <port>

where
    - <port> : is the port number the server is initiated on. (By default this value is set to port 12000)

The server will:
    - Create a "SharedFiles" folder if it doesn't exist
    - Listen in for incoming clients
    - Print connection/disconnection events to the console
    - Broadcast client and server messages to connected clients



To add Server-Stored files, simply place the files you want to share to clients in the SharedFiles folder.

Optional:
    SERVER_SHARED_FILES sets the directory the server uses for shared files; in __init__ we read os.environ.get('SERVER_SHARED_FILES', 'SharedFiles') and create the folder if it doesn’t exist, otherwise we default to ./SharedFiles.

------------------------------------------
To run the client, use the command:
python client.py <username> <host> <port>

where
    - <username> : is the username you want displayed to all other members of the chat
    - <host> : is the ipv4 address of the server
    - <port> : is the port that routing occurs through (should match the server)

E.g. python client.py JohnDoe62 192.168.1.130 8080

The client will:
    - Connect to the server
    - Create a download folder named after the username
    - Provide a command line interface for chatting with other users

-----------------{Mystic Commands}-----------------
A set of general use commands for the messaging app. Start a command using the keyword "mystic" (Note that mystic commands wont be seen by other users)


GENERAL COMMANDS
----------------
mystic help     - Prints all the commands the user can use
mystic disconnect   - Leave the chat and disconnect from the server gracefully
mystic users    - List all users currently connected to the server
mystic groups   - List all groups currently formed inside the server

MESSAGING
----------------
mystic pm <username> <message>  - Unicast a message to another user (only the sender and recipient can see this message)
mystic broadcast <message>  - Broadcasts a message to everyone but the user (similar to an announcement). Will show in groups too.

mystic create group <group_name>    - Create a new group
mystic join group <group_name>  - Join and existing group or create one if it doesn't exist
mystic leave group              Leave your current group
mystic leave group <name>       Also leaves the group (same affect as the command above)

Notes:
    - Being inside a group means you can no longer see the [GLOBAL] chat (unless broadcast command is used).
    - Group names cannot contain spaces.
    - If joining a non-existent group, it will be created
    - Groups are deleted when the last member leaves
    - Must leave current group before joining another

FILE TRANSFER
-------------
mystic files                    List available files in SharedFiles folder
mystic download <filename>      Download file using TCP (default)
mystic download <filename> tcp  Download file using TCP
mystic download <filename> udp  Download file using UDP

Notes:
    - Files are saved to a folder named after your username
    - TCP is reliable but slower; UDP is faster but may lose packets
    - Filenames with spaces are supported


-----------------{Message Channels}-----------------
Messages are either routed through:
1. GLOBAL CHAT (default)
    - Messages are sent to all users who arent inside a group
    - Global messages are displayed as [GLOBAL] <sending_user>: message

2. PRIVATE MESSAGES:
    - Private messages are sent directly to one recipient client, and only they can see the message
    - Private messages are displayed as [PM] <sending_user>: message

3. BROADCASTS:
    - Broadcasted messages are sent to ALL users (but the person executing the command), regardless of whether they're in global chat or a group chat.
    - Broadcasted messages are displayed as [BROADCAST] <sending_user>: message

4. GROUP CHAT
    - Messages sent to all members in a group
    - Users in group chats cannot see the global chat
    - Group messages are displayed as [<group_name>] <sending_user: message

Server messages are shown as [SERVER] message. These messages inform what operations have occured on the server, and what operations aren't permitted.

-----------------{Structure and Additional Details}-----------------
Architecture:
    - Server utilizes threading, one thread is set per connected client
    - All messages sent use TCP sockets for all client connection and messaging.
    - Client uses two seperate threads for sending and receiving, and an additional temporary thread is spawned for UDP download.
    - Clients and groups stored in class-level lists

Connection handling:
    - When a client connects to the server, the IP and port of the incoming client is printed
    - Welcome message is sent from the server using the server_message() method
    - server announces when someone joins or leaves
    - unexpected disconnects are handled gracefully using try except branches
    - Duplicate names are rejected by the server

Protocol: 
    - Messages are encoded as UTF-8 strings
    - Messages are sent with a prefix between client and server, with tags such as [SERVER], [GLOBAL], [PM] etc to denote the message type.
    - File transfers use markers such that:
        TCP: [FILE_START]filename, size [FILE_START_END] ... data ... [FILE_END]size[FILE_END_END]
        UDP: [UDP_FILE_START]filename, size, port[UDP_FILE_START_END]
    to validate file integrity.

Buffer Handling:
    - Incoming data during download is put in a receive Buffer
    - Incoming TCP bytes are accumulated across recv() calls, ensuring the full markers [FILE_START] is present. (i.e. preventing cases such as "[FILE_ST" being misdecoded as text chat)

File Transfers:
    - TCP: Reliable data transfer, using start / end markers to recognize file transfer.
    - UDP: Server creates temporary socket informing client over TCP, client sends UDP_READY indicating its ready to recieve UDP packets
        - Additionally utilizes 4-byte starting sequence to sort data into correct order.
    
    - Downloads are stored in a folder named after the clients username
    - File size is transmitted as part of both download options, and is used during integrity checks.


