import socket
from read_credentials import load_server_credentials
from sign_ip_in import sign_up, sign_in
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from AuthenticationManager import AuthenticationManager
import logging
from rich.logging import RichHandler
from rich.console import Console

# Create a rich console
console = Console()

# Set up logging with rich
logging.basicConfig(
    level=logging.DEBUG,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(console=console, rich_tracebacks=True)]
)

# Create a logger
logger = logging.getLogger("server_logger")

# Initialize the authentication manager
auth_manager = AuthenticationManager()

def server_init() -> socket.socket:
    """
    Initializes the server by creating a socket and binding it to a port.
    Returns:
        socket.socket: The initialized server socket.
    """
    print("Initializing server...")

    # Load server credentials from a JSON file
    address, port = load_server_credentials()

    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Bind the server socket to the specified address and port
        server.bind((address, port))
        logger.info(f"Server initialized and connected to {address}:{port}")
        return server
    except Exception as e:
        logger.critical(f"Error initializing server: {e}")
        exit("Failed to initialize server.")

# Initialize the server socket
server_socket = server_init()

def format_message(message: str, sender: str=None) -> str:
    """
    Formats the message for display.
    Args:
        sender (str): The sender of the message.
        message (str): The message content.
    """
    if sender:
        username = auth_manager.get_username(sender)
        logger.debug(f"<From {username if username != 'Unknown' else f'{sender[0]}:{sender[1]}'}> {message}")
        return f"<From {username if username != 'Unknown' else f'{sender[0]}:{sender[1]}'}> {message}"
    else:
        logger.debug(f"<From Server> {message}")
        return f"<From Server> {message}"

def handle_signup_request(sender: str, username: str, password: str) -> None:
    """Handles the signup request from a client."""
    message = sign_up(username, password)
    server_socket.sendto(format_message(message).encode(), sender)

def handle_signin_request(sender: str, username: str, password: str) -> None:
    """Handles the signin request from a client."""
    flag, message = sign_in(username, password)
    if flag == True:
        auth_manager.add_authenticated_client(sender, username, None) # Added because it's needed for the future auth
        # auth_manager.log_client(sender)
    server_socket.sendto(format_message(message).encode(), sender)

def handle_connection_request(sender: str, client_public_key: str, prime: str, generator: str) -> None:
    """Handles the connection request from a client."""
    message = auth_manager.init_connection_for_client(sender, client_public_key, prime, generator)
    server_socket.sendto(format_message(message).encode(), sender)

def handle_authentication_request(sender: str, nonce: str, encrypted: str, tag: str) -> None:
    """Handles the authentication request from a client."""
    # Handle the authentication request
    if sender in auth_manager.no_auth_clients:
        # Extract the nonce and encrypted data from the request
        nonce = int(nonce, 16)
        encrypted = bytes.fromhex(encrypted)
        tag = bytes.fromhex(tag)

        decrypted_session_key = auth_manager.decrypt_AES(nonce, encrypted, tag)

        session_key = auth_manager.get_session_key(sender, decrypted_session_key)

        # Verify the session key
        if decrypted_session_key != session_key.to_bytes((session_key.bit_length() + 7) // 8, 'big'):
            print(format_message(f"Client {sender} authentication failed"))
            return

        # Add the authenticated client to the list of clients
        auth_manager.add_authenticated_client(sender, username, decrypted_session_key.hex())
        print(format_message(f"Client {sender} authenticated successfully"))
    else:
        print(format_message(f"Client {sender} not found in unauthenticated clients"))

while True:
    try:
        data, sender = server_socket.recvfrom(1024)
        data_received = data.decode()

        # For debugging purposes
        format_message(f"Received data from {sender}: {data}")

        parts = data_received.split(":")
        tag = parts[0] if len(parts) > 0 else None
        username = parts[1] if len(parts) > 1 else None
        password = parts[2] if len(parts) > 2 else None
        encrypted = parts[3] if len(parts) > 3 else None

        if tag == "${CONNECT_TAG}":
            handle_connection_request(sender, username, password, encrypted)
        elif tag == "${AUTH_TAG}":
            # Handle the authentication request
            handle_authentication_request(sender, username, password, encrypted)

        # TODO: signup, signin and sending messages are not encrypted yet
        elif tag == "${SIGNUP_TAG}":
            handle_signup_request(sender, username, password)
        elif tag == "${SIGNIN_TAG}":
            handle_signin_request(sender, username, password)
        elif tag == "GREETING_FROM_CLIENT":
            # Handle the greeting from the client
            message = format_message(f"Client {sender} connected")
            print(message)
            server_socket.sendto(message.encode(), sender)
        else:
            message_formatted = format_message(data_received, sender)
            print(message_formatted)
            # Broadcast the message to all clients except the sender
            for client in auth_manager.list_of_clients:
                if (client != sender) and (auth_manager.get_client_logged(sender)):
                    logger.debug(f"Sending plain message to client {client}")
                    server_socket.sendto(message_formatted.encode(), client)

    except Exception as e:
        logger.exception(format_message(f"An error occurred: {e}"))
    except KeyboardInterrupt:
        print("\nServer shutting down...")
        break