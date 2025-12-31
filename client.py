import socket
from threading import Thread, Event
import sys
import time
import os
import struct


class Client:
    def __init__(self, username, HOST, PORT):
        # TCP socket
        self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_socket.connect((HOST, PORT))
        
        self.name = username
        self.host = HOST
        self.port = PORT
        self.terminate_client = Event()
        self.terminate_client.clear()
        self.state = '[GLOBAL]'
        self.at_prompt = False
        
        # File transfer state
        self.receiving_file = False
        self.file_buffer = bytearray()
        self.expected_file_size = 0
        self.current_filename = ""
        
        # Buffer for handling marker splitting
        self.recv_buffer = b""

        # Create download folder for this user
        self.download_folder = self.name
        if not os.path.exists(self.download_folder):
            os.makedirs(self.download_folder)

        self.connect_to_server()

    def connect_to_server(self):
        # Send username via TCP
        self.tcp_socket.send(self.name.encode())
        
        # Start receive thread
        Thread(target=self.receive_tcp_message, daemon=True).start()
        
        self.send_message()

    # End daemon threads
    def cleanup(self):
        self.terminate_client.set()
        try:
            self.tcp_socket.close()
        except:
            pass
        sys.exit(0)

    #---------------------------{SENDING}---------------------------------
    def send_message(self):
        try:
            while not self.terminate_client.is_set():
                self.print_prompt()
                self.at_prompt = True

                client_input = input()
                self.at_prompt = False

                if self.terminate_client.is_set():
                    break

                if not client_input.strip():
                    continue

                if client_input.startswith("mystic"):
                    codes = self.mystic_commands(client_input)

                    if codes == "TERMINATE":
                        break
                    time.sleep(0.15)
                    continue

                # Send regular message via TCP
                try:
                    self.tcp_socket.send(client_input.encode())
                except (BrokenPipeError, OSError):
                    print("\nDisconnected from server.")
                    break

        except EOFError:
            pass
        finally:
            self.cleanup()

    # Sends mystic command to the server to process
    def mystic_commands(self, client_input):
        commands = client_input.split()

        match commands[1:]:  # Skip "mystic"
            case []:
                self.tcp_socket.send(client_input.encode())

            case ["disconnect"]:
                self.terminate_client.set()
                try:
                    self.tcp_socket.send(client_input.encode())
                except (BrokenPipeError, OSError):
                    pass
                time.sleep(0.5)
                return "TERMINATE"

            case _:
                # Send all commands via TCP
                self.tcp_socket.send(client_input.encode())

    #---------------------------{RECEIVING}---------------------------------
    def receive_tcp_message(self):
        """Main TCP receive loop - accumulates data in buffer and processes complete messages."""
        while not self.terminate_client.is_set():
            try:
                chunk = self.tcp_socket.recv(8192)

                if not chunk:
                    print("\n\033[1;33;40mServer disconnected, press enter to continue.\033[0m")
                    self.terminate_client.set()
                    break

                self.recv_buffer += chunk
                self.__process_buffer()

            except (ConnectionResetError, OSError):
                if not self.terminate_client.is_set():
                    print("\n\033[1;33;40mDisconnected from the server. See you soon!\033[0m")
                self.terminate_client.set()
                break

    def __process_buffer(self):
        """Process complete messages from the buffer, handling marker splitting."""
        
        while True:
            if self.receiving_file:
                if not self.__process_file_data():
                    return
                continue
            # TCP download
            if b"[FILE_START]" in self.recv_buffer:
                if not self.__process_file_start():
                    return
                continue
            # UDP download
            if b"[UDP_FILE_START]" in self.recv_buffer:
                if not self.__process_udp_file_start():
                    return
                continue
            # Text messages / Partial marker detection
            if self.recv_buffer:
                partial_markers = [b"[FILE_", b"[UDP_F"]
                
                keep_from = len(self.recv_buffer)
                for marker in partial_markers:
                    for i in range(1, len(marker)+1):
                        if self.recv_buffer.endswith(marker[:i]):
                            keep_from = min(keep_from, len(self.recv_buffer) - i)
                            break
                
                if keep_from > 0:
                    text_data = self.recv_buffer[:keep_from]
                    self.recv_buffer = self.recv_buffer[keep_from:]
                    
                    try:
                        text = text_data.decode()
                        self.__process_text_message(text)
                    except UnicodeDecodeError:
                        pass
                
            return

    def __process_text_message(self, message):
        """Display incoming messages and user prompt box"""
        if not message.strip():
            return
        
        print("\r\033[K", end="")
        self.display_message(message)
        
        if not self.terminate_client.is_set() and self.at_prompt:
            self.print_prompt()

    #---------------------------{FILE TRANSFER}---------------------------------
    def __process_file_start(self):
        """Process TCP file start marker from buffer."""
        start_marker = b"[FILE_START]"
        end_marker = b"[FILE_START_END]"
        
        start_pos = self.recv_buffer.find(start_marker)
        end_pos = self.recv_buffer.find(end_marker)
        
        # footer hasn't arrived yet
        if end_pos == -1:
            # Indicates text message before header, process and print text message
            if start_pos > 0:
                text_before = self.recv_buffer[:start_pos]
                try:
                    self.__process_text_message(text_before.decode())
                except UnicodeDecodeError:
                    pass
                self.recv_buffer = self.recv_buffer[start_pos:] # Cut off everything before the header
            return False
        
        # Decode any messages before the file
        if start_pos > 0:
            text_before = self.recv_buffer[:start_pos]
            try:
                self.__process_text_message(text_before.decode())
            except UnicodeDecodeError:
                pass
        
        try:
            # Extract metadata
            info_start = start_pos + len(start_marker)
            file_info = self.recv_buffer[info_start:end_pos].decode()
            
            # Extract file_size and name 
            parts = file_info.split("|")
            self.current_filename = parts[0]
            self.expected_file_size = int(parts[1])
            self.file_buffer = bytearray()
            self.receiving_file = True
            
            print(f"\r\033[K\033[1;33;40m[SERVER]\033[0m Starting download: {self.current_filename} ({self.expected_file_size} bytes) via TCP...")
            
            # Set position of start of data
            self.recv_buffer = self.recv_buffer[end_pos + len(end_marker):]
            return True
            
        except Exception as e:
            print(f"\033[1;31;40mError parsing file header: {e}\033[0m")
            self.recv_buffer = self.recv_buffer[end_pos + len(end_marker):]
            return True

    def __process_udp_file_start(self):
        """Process UDP file start marker from buffer. (Same logic as __process_file_start())"""
        start_marker = b"[UDP_FILE_START]"
        end_marker = b"[UDP_FILE_START_END]"
        
        start_pos = self.recv_buffer.find(start_marker)
        end_pos = self.recv_buffer.find(end_marker)
        
        if end_pos == -1:
            if start_pos > 0:
                text_before = self.recv_buffer[:start_pos]
                try:
                    self.__process_text_message(text_before.decode())
                except UnicodeDecodeError:
                    pass
                self.recv_buffer = self.recv_buffer[start_pos:]
            return False
        
        if start_pos > 0:
            text_before = self.recv_buffer[:start_pos]
            try:
                self.__process_text_message(text_before.decode())
            except UnicodeDecodeError:
                pass
        
        try:
            info_start = start_pos + len(start_marker)
            file_info = self.recv_buffer[info_start:end_pos].decode()
            
            # Extract file size and udp port
            parts = file_info.split("|")
            self.current_filename = parts[0]
            self.expected_file_size = int(parts[1])
            server_udp_port = int(parts[2])
            
            print(f"\r\033[K\033[1;33;40m[SERVER]\033[0m Starting download: {self.current_filename} ({self.expected_file_size} bytes) via UDP...")
            
            self.recv_buffer = self.recv_buffer[end_pos + len(end_marker):]
            
            Thread(target=self.__receive_file_udp, args=(server_udp_port,), daemon=True).start()
            return True
            
        except Exception as e:
            print(f"\033[1;31;40mError parsing UDP file header: {e}\033[0m")
            self.recv_buffer = self.recv_buffer[end_pos + len(end_marker):]
            return True

    def __process_file_data(self):
        """Process file data from buffer, looking for end marker."""
        end_marker = b"[FILE_END]"
        end_end_marker = b"[FILE_END_END]"
        
        end_pos = self.recv_buffer.find(end_marker)
        
        # No footer found
        if end_pos != -1:
            file_data = self.recv_buffer[:end_pos]
            self.file_buffer.extend(file_data)
            
            end_end_pos = self.recv_buffer.find(end_end_marker)
            
            if end_end_pos != -1:
                self.recv_buffer = self.recv_buffer[end_end_pos + len(end_end_marker):]
                self.__save_file()
                return True
            else:
                self.recv_buffer = self.recv_buffer[end_pos:]
                return False
        
        marker_max_len = 30
        
        # Transfer bytes from recv buffer into file buffer
        if len(self.recv_buffer) > marker_max_len:
            safe_length = len(self.recv_buffer) - marker_max_len
            self.file_buffer.extend(self.recv_buffer[:safe_length])
            self.recv_buffer = self.recv_buffer[safe_length:]
        
        return False

    def __receive_file_udp(self, server_port):
        """Receive file via UDP with reliability (ACKs)."""
        try:
            file_udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            file_udp_socket.bind(('', 0))
            file_udp_socket.settimeout(10.0)

            # Send ready signal to server
            file_udp_socket.sendto(b"UDP_READY", (self.host, server_port))

            packets = {}

            while True:
                try:
                    data, addr = file_udp_socket.recvfrom(2048)

                    # Extract sequence number (first 4 bytes)
                    seq_num = struct.unpack('!I', data[:4])[0]
                    payload = data[4:]

                    # Check for end marker
                    if payload == b"[UDP_FILE_END]":
                        break

                    # Store packet
                    packets[seq_num] = payload
                    
                    # Send ACK
                    ack_packet = struct.pack('!I', seq_num)
                    file_udp_socket.sendto(ack_packet, addr)

                except socket.timeout:
                    break

            file_udp_socket.close()

            # Reassemble file in order
            self.file_buffer = bytearray()
            for i in sorted(packets.keys()):
                self.file_buffer.extend(packets[i])

            self.__save_file_udp()

        except Exception as e:
            print(f"\033[1;31;40mUDP transfer error: {e}\033[0m")

    def __save_file(self):
        """Save the received file (TCP)."""
        self.receiving_file = False

        if len(self.file_buffer) == 0:
            print(f"\033[1;31;40mNo data received for file.\033[0m")
            self.__reset_file_state()
            return

        filepath = os.path.join(self.download_folder, self.current_filename)

        try:
            with open(filepath, 'wb') as f:
                f.write(self.file_buffer)

            actual_size = len(self.file_buffer)
            status = "✓" if actual_size == self.expected_file_size else f"⚠ expected {self.expected_file_size}"
            print(f"\033[1;32;40m[DOWNLOAD COMPLETE]\033[0m {self.current_filename} saved to {filepath} ({actual_size} bytes) {status}")

        except Exception as e:
            print(f"\033[1;31;40mError saving file: {e}\033[0m")

        self.__reset_file_state()

        if self.at_prompt:
            self.print_prompt()

    def __save_file_udp(self):
        """Save the received file (UDP) (separate method to avoid conflicts)."""
        if len(self.file_buffer) == 0:
            print(f"\033[1;31;40mNo data received for file.\033[0m")
            return

        filepath = os.path.join(self.download_folder, self.current_filename)

        try:
            with open(filepath, 'wb') as f:
                f.write(self.file_buffer)

            actual_size = len(self.file_buffer)
            status = "✓" if actual_size == self.expected_file_size else f"⚠ expected {self.expected_file_size}"
            print(f"\r\033[K\033[1;32;40m[DOWNLOAD COMPLETE]\033[0m {self.current_filename} saved to {filepath} ({actual_size} bytes) {status}")

        except Exception as e:
            print(f"\033[1;31;40mError saving file: {e}\033[0m")

        # Reset only the file-related state used by UDP
        self.file_buffer = bytearray()
        self.current_filename = ""
        self.expected_file_size = 0

        if self.at_prompt:
            self.print_prompt()

    def __reset_file_state(self):
        """Reset file transfer state variables."""
        self.file_buffer = bytearray()
        self.current_filename = ""
        self.expected_file_size = 0
        self.receiving_file = False

    #---------------------------{DISPLAY}---------------------------------
    def print_prompt(self):
        """Print the input prompt with current state."""
        if self.state == '[GLOBAL]':
            state_color = "\033[1;35;40m"  # Magenta for global
        else:
            state_color = "\033[1;32;40m"  # Green for groups
        
        print(state_color + self.state + "\033[0m" + " " + "\033[1;36;40m" + self.name + ":" + "\033[0m" + " ", end="", flush=True)

    def __update_state(self, content):
        """Update the client state based on server message content."""
        if content.startswith("You are now chatting in "):
            group_name = content[24:].split(".")[0]
            self.state = f"[{group_name}]"
        elif "You have left" in content and "You're now in global chat" in content:
            self.state = "[GLOBAL]"

    def display_message(self, message):
        """Format and display a message based on its type."""
        
        if message.startswith("[SERVER]"):
            content = message[8:].strip()
            print("\033[1;33;40m[SERVER]\033[0m " + content)
            self.__update_state(content)

        elif message.startswith("[GLOBAL]"):
            content = message[8:].strip()
            if ": " in content:
                username, msg = content.split(": ", 1)
                print("\033[1;35;40m[GLOBAL]\033[0m \033[1;32;40m" + username + ":\033[0m " + msg)
            else:
                print("\033[1;35;40m[GLOBAL]\033[0m " + content)

        elif message.startswith("[GROUP:"):
            try:
                bracket_end = message.index("]")
                group_name = message[7:bracket_end]
                content = message[bracket_end + 1:].strip()
                if ": " in content:
                    username, msg = content.split(": ", 1)
                    print("\033[1;35;40m[" + group_name + "]\033[0m \033[1;31;40m" + username + ":\033[0m " + msg)
                else:
                    print("\033[1;35;40m[" + group_name + "]\033[0m " + content)
            except ValueError:
                print(message)

        elif message.startswith("[PM]"):
            content = message[4:].strip()
            if ": " in content:
                username, msg = content.split(": ", 1)
                print("\033[1;36;40m[PM]\033[0m \033[1;34;40m" + username + ":\033[0m " + msg)
            else:
                print("\033[1;36;40m[PM]\033[0m " + content)

        elif message.startswith("[BROADCAST]"):
            content = message[11:].strip()
            if ": " in content:
                username, msg = content.split(": ", 1)
                print("\033[1;35;40m[BROADCAST]\033[0m \033[1;32;40m" + username + ":\033[0m " + msg)
            else:
                print("\033[1;35;40m[BROADCAST]\033[0m " + content)

        else:
            print(message)


if __name__ == '__main__':
    if len(sys.argv) < 4:
        print("Usage: python client.py [username] [hostname] [port]")
        print("Example: python client.py John 127.0.0.1 12000")
        sys.exit(1)

    username = sys.argv[1]
    hostname = sys.argv[2]

    try:
        port = int(sys.argv[3])
    except ValueError:
        print("Invalid port number.")
        sys.exit(1)

    try:
        Client(username, hostname, port)
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
    except ConnectionRefusedError:
        print("Could not connect to server.")
        sys.exit(1)