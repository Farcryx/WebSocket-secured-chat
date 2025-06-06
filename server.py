import socket
from read_credentials import load_server_credentials
from sign_ip_in import sign_up, sign_in
from Crypto.Util.Padding import unpad
from console_logger import logger
from AuthenticationManager import AuthenticationManager
from encryption_module import EncryptionModule

auth_manager = AuthenticationManager(logger)

def initialize_server() -> socket.socket:
    """
    Initializes the server by creating a socket and binding it to a port.
    Returns:
        socket.socket: The initialized server socket.
    """
    logger.info("Initializing server...")

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

def format_message(message: str, sender=None, dm_flag: bool=False) -> str:
    """
    Formats the message for display.
    Args:
        sender (tuple): The sender's address and port.
        message (str): The message content.
    """
    if sender:
        username = auth_manager.list_of_clients.get(sender, {}).get("username", "Unknown")
        logger.debug(f"<{"DM " if dm_flag else ""}From {username if username != 'Unknown' else f'{sender[0]}:{sender[1]}'}> {message}")
        return f"<{"DM " if dm_flag else ""}From {username if username != 'Unknown' else f'{sender[0]}:{sender[1]}'}> {message}"
    else:
        logger.debug(f"<From Server> {message}")
        return f"<From Server> {message}"

def handle_signup_request(server_socket: socket.socket, sender: str, username: str, password: str) -> None:
    """Handles the signup request from a client."""
    message = sign_up(username, password)
    server_socket.sendto(format_message(message).encode(), sender)

def handle_signin_request(server_socket, sender: str, username: str, password: str) -> None:
    """Handles the signin request from a client."""
    if auth_manager.check_if_username_logged(username):
        message = f"SIGNIN_FAIL: User {username} is already logged in."
        logger.warning(f"{sender} tried to sign in with an already logged in username {username}.")
        server_socket.sendto(format_message(message).encode(), sender)
        return
    flag, message = sign_in(username, password)
    if flag:
        auth_manager.signin_client(sender, username)
        logger.info(f"User {username} signed in successfully.")
    server_socket.sendto(format_message(message).encode(), sender)

def handle_connection_request(server_socket: socket.socket, sender: str, client_public_key: str, prime: str, generator: str) -> None:
    """Handles the connection request from a client. Generate session key and send it back."""
    message = auth_manager.init_connection_for_client(sender, client_public_key, prime, generator)
    server_socket.sendto(format_message(message).encode(), sender)

def handle_authentication_request(server_socket, sender, nonce, encrypted, tag):
    """Handles the authentication request from a client."""
    if sender in auth_manager.list_of_clients:
        session_key = auth_manager.get_session_key(sender)
        decrypted_session_key = EncryptionModule.decrypt_AES(session_key, nonce, encrypted, tag)
        if session_key.upper() == decrypted_session_key.upper():
            auth_manager.set_authenticated_client(sender)
            message = "Connected to the server successfully."
            logger.info(f"Authentication status for {sender}: {message}")
        else:
            # message = "Authentication failed."
            logger.warning(f"Authentication failed for {sender}. Decrypted session key: {decrypted_session_key} does not match the expected session key {session_key}.")
        # server_socket.sendto(format_message(message).encode(), sender)

def process_client_message(server_socket: socket.socket, data: str, sender: str) -> None:
    """Processes incoming messages from clients."""
    logger.info(f"Received from {sender}: {data}")
    parts = data.split(":")
    tag = parts[0] if len(parts) > 0 else None
    username = parts[1] if len(parts) > 1 else None
    password = parts[2] if len(parts) > 2 else None
    encrypted = parts[3] if len(parts) > 3 else None

    if sender in auth_manager.list_of_clients:
        if auth_manager.list_of_clients[sender].get("logged") and auth_manager.list_of_clients[sender].get("authenticated"):
            if tag == "GREETING_FROM_CLIENT":
                server_socket.sendto(format_message("Hello from server!").encode(), sender)
            else:
                if tag == "${DM_TAG}":
                    logger.info(f"Searching for address of recipient {username} for DM_TAG.")
                    recipient_address = auth_manager.get_sender_by_username(username)
                    logger.info(f"Receipient address for DM_TAG: {recipient_address}")
                    if recipient_address is not None:
                        # Log the name of the recipient and flag if they are logged in
                        logger.info(f"DM_TAG: Recipient {username} exists and is logged in: {auth_manager.list_of_clients[recipient_address].get('logged')}")
                        if auth_manager.list_of_clients[recipient_address].get("logged"):
                            auth_manager.set_dm_recipient(sender, username)
                            server_socket.sendto(format_message(f"DM_OK").encode(), sender)
                        else:
                            logger.warning(f"DM_FAIL: Recipient {username} does not exist or is not logged in.")
                            server_socket.sendto(format_message(f"DM_FAIL: Recipient {username} does not exist or is not logged in.").encode(), sender)
                    else:
                        logger.warning(f"DM_FAIL: Recipient {username} does not exist or is not logged in. Address: {recipient_address}")
                        server_socket.sendto(format_message(f"DM_FAIL: Recipient {username} does not exist or is not logged in.").encode(), sender)
                        
                else:
                    plaintext = EncryptionModule.decrypt_AES(
                    auth_manager.get_session_key(sender), nonce=tag, ciphertext=username, tag=password, message_flag=True)
                    message_formatted = format_message(plaintext, sender)
                    if sender in auth_manager.list_of_clients:
                        for client in auth_manager.list_of_clients:
                            if client != sender and auth_manager.list_of_clients[client].get("logged"):
                                server_socket.sendto((auth_manager.encrypt_message(client, message_formatted)).encode(), client)
        elif not auth_manager.list_of_clients[sender].get("logged") and not auth_manager.list_of_clients[sender].get("authenticated") and tag == "${AUTH_TAG}":
            handle_authentication_request(server_socket, sender, username, password, encrypted)
        elif not auth_manager.list_of_clients[sender].get("logged") and auth_manager.list_of_clients[sender].get("authenticated"):
            plaintext = EncryptionModule.decrypt_AES(
            auth_manager.get_session_key(sender), nonce=username, ciphertext=password, tag=encrypted, message_flag=True)
            plaintext = plaintext
            if plaintext is None:
                logger.error(f"Decryption failed for {sender}.")
                return
            else:
                logger.info(f"Decrypted plaintext for {sender}: {plaintext}")
                plaintext = plaintext.split(":")
                username = plaintext[0] if len(plaintext) > 0 else None
                password = plaintext[1] if len(plaintext) > 1 else None
            
            if tag == "${SIGNUP_TAG}":
                handle_signup_request(server_socket, sender, username, password)
            elif tag == "${SIGNIN_TAG}":
                handle_signin_request(server_socket, sender, username, password)
            else:
                logger.warning(f"Unknown tag received from not logged but authenticated client {sender}: {tag}")
        else:
            logger.warning(f"Unknown tag received from authenticated client: {sender}: {tag}")
    elif sender not in auth_manager.list_of_clients and tag == "${CONNECT_TAG}":
        handle_connection_request(server_socket, sender, username, password, encrypted)
    else:
        logger.warning(f"Unknown tag received from client new client {sender}: {tag}")
        server_socket.sendto(format_message(f"Unknown tag received from client new client {sender}: {tag}").encode(), sender)

def main() -> None:
    server_socket = initialize_server()
    while True:
        try:
            data, sender = server_socket.recvfrom(1024)
            logger.info(f"Debugging bytes data from {sender}: {data}")
            try:
                logger.info(f"Debugging hex data from {sender}: {data.decode()}")
                process_client_message(server_socket, data.decode(), sender)
            except UnicodeDecodeError:
                logger.error(f"Failed to decode data from {sender}: {data}")
                continue
            except Exception as e:
                logger.exception(f"An error occurred while processing message from {sender}: {e}")
                continue

        except KeyboardInterrupt:
            logger.info("Server shutting down...")
            server_socket.close()
            break
        except Exception as e:
            logger.exception(f"An error occurred: {e}")
            server_socket.close()
            break