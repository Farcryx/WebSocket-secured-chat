import socket
import threading
from read_credentials import load_server_credentials

def client_init() -> tuple[socket.socket, str, int]:
    """
    Initializes the client by creating a socket and connecting to the server.
    Returns:
        socket.socket: The initialized client socket.
    """
    print("Initializing client...")

    # socket.AF_INET, socket.SOCK_DGRAM is used for UDP sockets
    client =  socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        client.bind(('localhost', 0))  # Bind to an ephemeral port
        client_address, client_port = client.getsockname()
        print(f"Client initialized and connected to {client_address}:{client_port}")
        # Load server credentials from a JSON file
        address, port = load_server_credentials()
        print(f"Server at {address}:{port}")
        return client, address, port
    except Exception as e:
        print(f"Error initializing client: {e}")
        exit("Failed to initialize client.")

def send_message(client_socket: socket.socket, message: str, server_address: str, server_port: int) -> None:
    """
    Sends a message to the server.
    Args:
        client_socket (socket.socket): The client socket.
        message (str): The message to send.
    """
    server_address = (server_address, server_port)
    message_encrypted = str(message).encode()
    client_socket.sendto(message_encrypted, server_address)

def receive_message() -> None:
    """
    Receives a message from the server and displays it.
    """
    while True:
        try:
            # Receive data from the server (1024 bytes buffer size)
            data = client_socket.recvfrom(1024)[0]
            print(f"{data.decode()}")
        except KeyboardInterrupt:
            print("Client shutting down...")
            break
        except Exception as e:
            print(f"Error receiving message: {e}")
            print("Client shutting down...")
            break
    # Close the socket when done
    client_socket.close()

if __name__ == "__main__":
    # Initialize the client with server IP and port
    client_socket, server_address, server_port = client_init()
    
    # Start a thread to receive messages from the server
    receive_thread = threading.Thread(target=receive_message)
    receive_thread.start()
    
    # Main loop to send messages
    init = True
    while True:
        try:
            if init:
                greeting = input("Do you want to greet the server? (y/n): ")
                if greeting.lower() == 'y':
                    message = "${GREETING_TAG}"
                    send_message(client_socket, message, server_address, server_port)
                    print("Greeting sent to server.\nJoining the chat...\nYou can start sending messages now.")
                    print("- " * 30)
                    init = False
                else:
                    exit("Client shutting down...")
            message = input()
            send_message(client_socket, message, server_address, server_port)
        except KeyboardInterrupt:
            print("Client shutting down...")
            break
    
    client_socket.close()