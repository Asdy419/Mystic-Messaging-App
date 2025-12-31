import socket
from threading import Thread
import os


class Server:
    clients = []
    groups = []

    def __init__(self, HOST, PORT):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((HOST, PORT))
        self.socket.listen(10)
        self.shared_files_path = os.environ.get('SERVER_SHARED_FILES', 'SharedFiles')
        
        # Create SharedFiles folder if it doesn't exist
        if not os.path.exists(self.shared_files_path):
            os.makedirs(self.shared_files_path)
        
        print("Waiting for client connection...")

    # HELPERS
    def __in_any_group(self, client_name: str) -> bool:
        return any(client_name in g["members"] for g in Server.groups)

    def __get_client_group(self, client_name: str) -> str | None:
        """Return the group name the client is in, or None."""
        for g in Server.groups:
            if client_name in g['members']:
                return g['group_name']
        return None

    def __get_client_by_name(self, client_name: str):
        """Find a client dict by name."""
        return next((c for c in Server.clients if c['client_name'] == client_name), None)

    def __get_group_by_name(self, group_name: str):
        """Find a group dict by name."""
        return next((g for g in Server.groups if g['group_name'] == group_name), None)

    def server_message(self, message, exclude_client=None, target_client=None):
        """Send a server message to clients."""
        formatted = f"[SERVER] {message}"

        if target_client:
            try:
                target_client['client_socket'].send(formatted.encode())
            except:
                pass
            return

        for client in Server.clients:
            if exclude_client is None or client['client_name'] != exclude_client:
                try:
                    client['client_socket'].send(formatted.encode())
                except:
                    pass

    def listen(self):
        while True:
            client_socket, address = self.socket.accept()
            # REQUIREMENT: Print where connection is coming from (IP address and port)
            print(f"Connection from {address[0]}:{address[1]}")

            client_name = client_socket.recv(1024).decode()
            
            # Check for duplicate username
            if self.__get_client_by_name(client_name):
                reject_msg = f"[SERVER] Username '{client_name}' is already taken. Please reconnect with a different name."
                try:
                    client_socket.send(reject_msg.encode())
                    client_socket.close()
                except:
                    pass
                print(f"Rejected duplicate username: {client_name}")
                continue
            
            client = {'client_name': client_name, 'client_socket': client_socket}

            Server.clients.append(client)

            # Send welcome message over network (requirement)
            welcome_msg = f"[SERVER] Welcome to the Mystic chat room, {client_name}! Type 'mystic help' for commands."
            client_socket.send(welcome_msg.encode())

            self.server_message(f"{client_name} has joined", exclude_client=client_name)

            Thread(target=self.__incoming_client, args=(client,)).start()

    def __parse_mystic_command(self, client, command):
        """
        Parse mystic commands from message.
        Returns True if command was handled, False if regular message.
        """
        parts = command.split()
        if "mystic" not in parts:
            return False

        match parts[1:]:
            case []:
                self.server_message("Did you mean to enter a command? Type \"mystic help\" for commands.",
                                    target_client=client)
                return True

            case ["disconnect"]:
                print("Disconnect")
                return "DISCONNECT"

            case ["help"]:
                self.__handle_help(client)
                return True

            # ADDITION: broadcast command for assignment requirement
            case ["broadcast"]:
                self.server_message("Usage: mystic broadcast <message>", target_client=client)
                return True

            case ["broadcast", *message_parts]:
                message = " ".join(message_parts)
                self.__handle_broadcast(client, message=message)
                return True

            case ["pm"]:
                self.server_message("Usage: mystic pm <user> <message>", target_client=client)
                return True

            case ["pm", user]:
                self.server_message("Usage: mystic pm <user> <message>", target_client=client)
                return True

            case ["pm", user, *message_parts]:
                message = " ".join(message_parts)
                self.__handle_pm(client, target=user, message=message)
                return True

            case ["create", "group"]:
                self.server_message("Usage: mystic create group <name>", target_client=client)
                return True

            case ["create", "group", group_name]:
                self.__handle_create_group(client, group_name)
                return True

            case ["create", "group", *rest]:
                self.server_message("Group name cannot contain spaces.", target_client=client)
                return True

            case ["join", "group"]:
                self.server_message("Usage: mystic join group <name>", target_client=client)
                return True

            case ["join", "group", group_name]:
                self.__handle_join_group(client, group_name)
                return True

            case ["join", "group", *rest]:
                self.server_message("Group name cannot contain spaces.", target_client=client)
                return True

            case ["leave", "group"]:
                client_group = self.__get_client_group(client['client_name'])
                if client_group:
                    self.__handle_leave_group(client, client_group)
                else:
                    self.server_message("You're not in any group!", target_client=client)
                return True

            case ["leave", "group", group_name]:
                self.__handle_leave_group(client, group_name)
                return True

            case ["leave", "group", *rest]:
                self.server_message("Group name cannot contain spaces.", target_client=client)
                return True

            case ["groups"]:
                self.__handle_list_groups(client)
                return True

            case ["users"]:
                self.__handle_list_users(client)
                return True

            # File download commands
            case ["files"]:
                self.__handle_list_files(client)
                return True

            case ["download"]:
                self.server_message("Usage: mystic download <filename> [tcp|udp]", target_client=client)
                return True

            case ["download", filename]:
                self.__handle_download(client, filename, "tcp")
                return True

            case ["download", filename, protocol] if protocol.lower() in ["tcp", "udp"]:
                self.__handle_download(client, filename, protocol.lower())
                return True

            case ["download", *rest]:
                # Handle filenames with spaces - last arg might be protocol
                if rest[-1].lower() in ["tcp", "udp"]:
                    filename = " ".join(rest[:-1])
                    protocol = rest[-1].lower()
                else:
                    filename = " ".join(rest)
                    protocol = "tcp"
                self.__handle_download(client, filename, protocol)
                return True

            case _:
                self.server_message("Command not recognized. Type \"mystic help\" for commands.",
                                    target_client=client)
                return True

    def __handle_help(self, client):
        """Send help message to client."""
        help_text = """--- Mystic Commands ---
mystic help - Show this help message
mystic disconnect - Leave the chat
mystic pm <user> <message> - Send a private message to a user (unicast)
mystic broadcast <message> - Broadcast message to all users
mystic create group <name> - Create a new group
mystic join group <name> - Join a group
mystic leave group - Leave your current group
mystic leave group <name> - Leave a specific group
mystic groups - List all groups
mystic users - List all online users
mystic files - Access shared files folder
mystic download <filename> [tcp|udp] - Download a file (default: tcp)"""
        self.server_message(help_text, target_client=client)

    def __handle_pm(self, client, target, message):
        """Send a private message to another user."""
        client_name = client['client_name']

        # Can't PM yourself
        if target == client_name:
            self.server_message("You can't send a PM to yourself!", target_client=client)
            return

        # Find target user
        target_client = self.__get_client_by_name(target)

        if not target_client:
            self.server_message(f"User '{target}' not found. Use 'mystic users' to see online users.", target_client=client)
            return

        # Send the PM to target
        pm_message = f"[PM] {client_name}: {message}"
        try:
            target_client['client_socket'].send(pm_message.encode())
        except:
            self.server_message(f"Failed to send PM to {target}.", target_client=client)
            return

        # Confirm to sender
        self.server_message(f"PM sent to {target}.", target_client=client)

    # ADDITION: broadcast handler for assignment requirement
    def __handle_broadcast(self, client, message):
        """Broadcast message to all other clients."""
        client_name = client['client_name']
        broadcast_msg = f"[BROADCAST] {client_name}: {message}"
        
        for c in Server.clients:
            if c['client_name'] != client_name:
                try:
                    c['client_socket'].send(broadcast_msg.encode())
                except:
                    pass

    def __handle_create_group(self, client, group_name):
        """Create a new group."""
        client_name = client['client_name']

        if not group_name:
            self.server_message("Usage: mystic create group <name>", target_client=client)
            return

        # Check if group already exists
        if self.__get_group_by_name(group_name):
            self.server_message("Group already exists! Try a new group name.", target_client=client)
            return

        # Check if user is already in a group
        current_group = self.__get_client_group(client_name)
        if current_group:
            self.server_message(f"You're already in '{current_group}'. Leave it first with 'mystic leave group'.",
                                target_client=client)
            return

        group = {'group_name': group_name, 'members': [client_name]}
        Server.groups.append(group)
        print(Server.groups)

        self.server_message(f"{client_name} has created the group {group_name}!")
        self.server_message(f"You are now chatting in {group_name}. Use 'mystic leave group' to leave.",
                            target_client=client)

    def __handle_join_group(self, client, group_name):
        """Join an existing group."""
        client_name = client['client_name']

        if not group_name:
            self.server_message("Usage: mystic join group <name>", target_client=client)
            return

        # Check if user is already in a group
        current_group = self.__get_client_group(client_name)
        if current_group:
            if current_group == group_name:
                self.server_message(f"You're already in {group_name}!", target_client=client)
            else:
                self.server_message(f"You're already in '{current_group}'. Leave it first with 'mystic leave group'.",
                                    target_client=client)
            return

        # Find the group
        group = self.__get_group_by_name(group_name)

        if group:
            # Add user to group
            group['members'].append(client_name)

            # Notify the user
            self.server_message(f"You are now chatting in {group_name}. Use 'mystic leave group' to leave.",
                                target_client=client)

            # Notify other group members
            for member_name in group['members']:
                if member_name != client_name:
                    member = self.__get_client_by_name(member_name)
                    if member:
                        self.server_message(f"{client_name} has joined {group_name}!", target_client=member)
        else:
            # REQUIREMENT: If group doesn't exist, create it
            self.server_message(f"'{group_name}' doesn't exist! Creating it now...", target_client=client)
            self.__handle_create_group(client, group_name)

    def __handle_leave_group(self, client, group_name):
        """Leave a group."""
        client_name = client['client_name']

        if not group_name:
            self.server_message("Usage: mystic leave group <name>", target_client=client)
            return

        # Find the group
        group = self.__get_group_by_name(group_name)

        if not group:
            self.server_message(f"Group '{group_name}' doesn't exist!", target_client=client)
            return

        # Check if user is in the group
        if client_name not in group['members']:
            self.server_message(f"You're not in '{group_name}'!", target_client=client)
            return

        # Remove user from group
        group['members'].remove(client_name)

        # Notify the user
        self.server_message(f"You have left {group_name}. You're now in global chat.", target_client=client)

        # Notify remaining group members
        for member_name in group['members']:
            member = self.__get_client_by_name(member_name)
            if member:
                self.server_message(f"{client_name} has left {group_name}.", target_client=member)

        # Delete group if empty
        if not group['members']:
            Server.groups.remove(group)
            self.server_message(f"Group '{group_name}' has been deleted (no members left).")
            print(f"Group '{group_name}' deleted.")

    def __handle_list_groups(self, client):
        """List all available groups."""
        if not Server.groups:
            self.server_message("No groups exist yet.", target_client=client)
        else:
            group_info = [f"{g['group_name']} ({len(g['members'])} members)" for g in Server.groups]
            self.server_message(f"Groups: {', '.join(group_info)}", target_client=client)

    def __handle_list_users(self, client):
        """List all online users."""
        if not Server.clients:
            self.server_message("No users online.", target_client=client)
        else:
            user_names = [c['client_name'] for c in Server.clients]
            self.server_message(f"Online users: {', '.join(user_names)}", target_client=client)

    def __handle_list_files(self, client):
        """List files in the SharedFiles folder."""
        try:
            files = os.listdir(self.shared_files_path)
            # Filter to only include files (not directories)
            files = [f for f in files if os.path.isfile(os.path.join(self.shared_files_path, f))]

            if not files:
                self.server_message("Successfully accessed SharedFiles folder. 0 files available.", target_client=client)
                return

            # Build complete file list as single message to avoid TCP combining issues
            file_lines = [f"Successfully accessed SharedFiles folder. {len(files)} file(s) available:"]
            for i, filename in enumerate(files, 1):
                filepath = os.path.join(self.shared_files_path, filename)
                size = os.path.getsize(filepath)
                file_lines.append(f"  {i}. {filename} ({size} bytes)")
            
            self.server_message("\n".join(file_lines), target_client=client)

        except Exception as e:
            self.server_message(f"Error accessing SharedFiles folder: {e}", target_client=client)

    def __handle_download(self, client, filename, protocol):
        """Handle file download request."""
        client_name = client['client_name']
        filepath = os.path.join(self.shared_files_path, filename)

        # Check if file exists
        if not os.path.isfile(filepath):
            self.server_message(f"File '{filename}' not found in SharedFiles.", target_client=client)
            return

        file_size = os.path.getsize(filepath)

        if protocol == "tcp":
            self.__send_file_tcp(client, filename, filepath, file_size)
        else:
            self.__send_file_udp(client, filename, filepath, file_size)

    def __send_file_tcp(self, client, filename, filepath, file_size):
        """Send file over TCP."""
        client_socket = client['client_socket']
        client_name = client['client_name']

        try:
            # Send file transfer header
            header = f"[FILE_START]{filename}|{file_size}[FILE_START_END]"
            client_socket.send(header.encode())

            import time
            time.sleep(0.1)

            # Send file data in chunks
            with open(filepath, 'rb') as f:
                bytes_sent = 0
                while bytes_sent < file_size:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                    client_socket.send(chunk)
                    bytes_sent += len(chunk)

            time.sleep(0.1)

            # Send end marker
            end_marker = f"[FILE_END]{file_size}[FILE_END_END]"
            client_socket.send(end_marker.encode())

            print(f"File '{filename}' ({file_size} bytes) sent to {client_name} via TCP")

        except Exception as e:
            self.server_message(f"Error sending file: {e}", target_client=client)

    def __send_file_udp(self, client, filename, filepath, file_size):
        """Send file over UDP."""
        client_name = client['client_name']
        client_socket = client['client_socket']

        try:
            # Create UDP socket
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_socket.bind(('', 0))
            udp_port = udp_socket.getsockname()[1]

            # Tell client to prepare for UDP transfer
            header = f"[UDP_FILE_START]{filename}|{file_size}|{udp_port}[UDP_FILE_START_END]"
            client_socket.send(header.encode())

            import time
            time.sleep(0.2)

            # Wait for client's UDP ready signal
            udp_socket.settimeout(5.0)
            data, client_addr = udp_socket.recvfrom(1024)

            if data.decode() != "UDP_READY":
                self.server_message("UDP handshake failed.", target_client=client)
                udp_socket.close()
                return

            # Send file data in chunks via UDP
            chunk_size = 1024
            sequence = 0

            with open(filepath, 'rb') as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    # Prepend sequence number (4 bytes)
                    packet = sequence.to_bytes(4, 'big') + chunk
                    udp_socket.sendto(packet, client_addr)
                    sequence += 1
                    time.sleep(0.001)

            # Send end marker via UDP
            end_packet = sequence.to_bytes(4, 'big') + b"[UDP_FILE_END]"
            udp_socket.sendto(end_packet, client_addr)

            time.sleep(0.1)

            # Send confirmation over TCP
            end_marker = f"[FILE_END]{file_size}[FILE_END_END]"
            client_socket.send(end_marker.encode())

            print(f"File '{filename}' ({file_size} bytes) sent to {client_name} via UDP")

            udp_socket.close()

        except socket.timeout:
            self.server_message("UDP transfer timed out. Client did not respond.", target_client=client)
        except Exception as e:
            self.server_message(f"Error sending file via UDP: {e}", target_client=client)

    def __incoming_client(self, client):
        client_name = client['client_name']
        client_socket = client['client_socket']

        while True:
            try:
                client_message = client_socket.recv(1024).decode()
            except (ConnectionResetError, OSError):
                client_message = ""

            if not client_message.strip():
                self.__handle_disconnect(client)
                break

            # Check for mystic commands
            command_result = self.__parse_mystic_command(client, client_message)

            if command_result == "DISCONNECT":
                self.__handle_disconnect(client)
                break
            elif command_result:
                continue

            # Regular message - route to appropriate channel
            client_group = self.__get_client_group(client_name)

            if client_group:
                self.__broadcast_group_message(client_name, client_group, f"[GROUP:{client_group}] {client_name}: {client_message}")
            else:
                self.__broadcast_global_message(client_name, f"[GLOBAL] {client_name}: {client_message}")

    def __handle_disconnect(self, client):
        client_name = client['client_name']
        client_socket = client['client_socket']

        if client in Server.clients:
            Server.clients.remove(client)

        # Remove client from any groups they're in
        for group in Server.groups[:]:
            if client_name in group['members']:
                group['members'].remove(client_name)

                # Notify remaining members
                for member_name in group['members']:
                    member = self.__get_client_by_name(member_name)
                    if member:
                        self.server_message(f"{client_name} has left {group['group_name']}.", target_client=member)

                # Delete group if empty
                if not group['members']:
                    Server.groups.remove(group)
                    print(f"Group '{group['group_name']}' deleted (no members left).")

        self.server_message(f"{client_name} has left", exclude_client=client_name)

        try:
            client_socket.send("[SERVER] You have left the chat. Goodbye!".encode())
            client_socket.shutdown(socket.SHUT_RDWR)
        except:
            pass

        client_socket.close()
        print(f"{client_name} disconnected.")

    def __broadcast_global_message(self, sender_name, client_message):
        """Broadcast global message to users not in groups."""
        for client in Server.clients:
            client_name = client['client_name']
            if client_name != sender_name and not self.__in_any_group(client_name):
                try:
                    client['client_socket'].send(client_message.encode())
                except:
                    pass

    def __broadcast_group_message(self, sender_name, group_name, client_message):
        """Broadcast a message to all members of a specific group except the sender."""
        group = self.__get_group_by_name(group_name)
        if not group:
            return

        for client in Server.clients:
            if client['client_name'] != sender_name and client['client_name'] in group['members']:
                try:
                    client['client_socket'].send(client_message.encode())
                except:
                    pass


if __name__ == '__main__':
    import sys

    port = 12000

    if len(sys.argv) >= 2:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print("Invalid port number. Using default port 12000.")

    server = Server('0.0.0.0', port)
    server.listen()