import socket
from read_credentials import load_server_credentials
# from sign_ip_in import sign_up, sign_in
# from Crypto.Util.Padding import unpad
from console_logger import logger
# from AuthenticationManager import AuthenticationManager
from encryption_module import EncryptionModule
import requests
import endpoints

# auth_manager = AuthenticationManager(logger)

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

def format_message(message: str, sender=None, dm_flag: bool = False) -> str:
    """
    Formats the message for display.
    Args:
        sender (tuple): The sender's address and port.
        message (str): The message content.
    """
    if sender:
        serialized_sender = serialize_sender(sender)
        username = endpoints.get_username(serialized_sender)
        logger.debug(f"<{'DM ' if dm_flag else ''}From {username if username != 'Unknown' else serialized_sender}> {message}")
        return f"<{'DM ' if dm_flag else ''}From {username if username != 'Unknown' else serialized_sender}> {message}"
    else:
        logger.debug(f"<From Server> {message}")
        return f"<From Server> {message}"

def serialize_sender(sender: tuple) -> str:
    """Converts the sender tuple to a string format."""
    sender_str = str(sender)
    client_tuple = tuple(sender_str.strip("()").replace("'", "").split(", "))
    client_tuple = (client_tuple[0], int(client_tuple[1]))  # Convert port to int
    logger.debug(f"Serializing sender: {sender} to {client_tuple[0]}:{client_tuple[1]}")
    return f"{client_tuple[0]}:{client_tuple[1]}"

def handle_signup_request(server_socket: socket.socket, sender: str, username: str, password: str) -> None:
    """Handles the signup request by delegating to the authentication microservice."""
    url = "http://authentication:5001/signup"  # Replace with the actual URL of the authentication microservice
    payload = {
        "username": username,
        "password": password
    }
    try:
        response = requests.post(url, json=payload)
        response_data = response.json()
        message = response_data.get('message', 'Error: No response from authentication service.')
    except Exception as e:
        logger.error(f"Error communicating with authentication service: {e}")
        message = "Error: Unable to process signup request."
    # msg = message.split()
    msg = len(message)
    logger.debug(f"Message from signup service: \n{message}, {msg}")
    server_socket.sendto(format_message(message).encode(), sender)

def handle_signin_request(server_socket, sender: str, username: str, password: str) -> None:
    """Handles the signin request by delegating to the authentication microservice."""
    url = "http://authentication:5001/signin"  # Replace with the actual URL of the authentication microservice
    payload = {
        "sender": str(sender),
        "username": username,
        "password": password
    }
    try:
        logger.debug(f"Payload for /signin: {payload}")
        response = requests.post(url, json=payload)
        response_data = response.json()
        message = response_data.get('message', 'Error: No response from authentication service.')
    except Exception as e:
        logger.error(f"SIGNIN_FAIL: Error communicating with authentication service: {e}")
        message = "SIGNIN_FAIL: Unable to process signin request."
    logger.debug(f"Message from signin service: \n{message}")
    server_socket.sendto(format_message(message).encode(), sender)

def handle_connection_request(server_socket: socket.socket, sender: str, client_public_key: str, prime: str, generator: str) -> None:
    """Handles the connection request by delegating to the authentication microservice."""
    url = "http://authentication:5001/connection"  # Replace with the actual URL of the authentication microservice
    payload = {
        "sender": str(sender),
        "client_public_key": client_public_key,
        "prime": prime,
        "generator": generator
    }
    try:
        logger.debug(f"Payload sent to /connection: {payload}")
        response = requests.post(url, json=payload)
        response_data = response.json()
        message = response_data.get('message', 'Error: No response from authentication service.')
    except Exception as e:
        logger.error(f"Error communicating with authentication service: {e}")
        message = "Error: Unable to process connection request."
    logger.debug(f"Message from connection service: {message}")
    server_socket.sendto(format_message(message).encode(), sender)

def handle_authentication_request(server_socket, sender, nonce, encrypted, tag):
    """Handles the authentication request by delegating to the authentication microservice."""
    url = "http://authentication:5001/authenticate"  # Replace with the actual URL of the authentication microservice
    payload = {
        "sender": str(sender),
        "nonce": nonce,
        "encrypted": encrypted,
        "tag": tag
    }
    try:
        logger.debug(f"Payload sent to /authenticate: {payload}")
        response = requests.post(url, json=payload)
        response_data = response.json()
        message = response_data.get('message', 'Error: No response from authentication service.')
    except Exception as e:
        logger.error(f"Error communicating with authentication service: {e}")
        message = "Error: Unable to process authentication request."
    logger.debug(f"Message from authentication service: {message}")
    # server_socket.sendto(format_message(message).encode(), sender)

def encrypt_message(sender: str, message: str) -> str | None:
        """
        Encrypts the message using the session key of the client.
        Args:
            sender (str): The identifier of the client.
            message (str): The message to encrypt.
        Returns:
            str: The encrypted message.
        """
        session_key = endpoints.get_session_key(sender)
        nonce = endpoints.get_nonce(sender)
        ciphertext, tag = EncryptionModule.encrypt_AES(
            session_key, str(nonce), message
        )
        return f"{nonce}:{ciphertext}:{tag}"

def process_client_message(server_socket: socket.socket, data: str, sender: str) -> None:
    """Processes incoming messages from clients."""
    logger.info(f"Received from {sender}: {data}")
    parts = data.split(":")
    tag = parts[0] if len(parts) > 0 else None
    username = parts[1] if len(parts) > 1 else None
    password = parts[2] if len(parts) > 2 else None
    encrypted = parts[3] if len(parts) > 3 else None

    temp_list_of_clients = endpoints.get_clients()
    logger.debug(f"Handling tag {tag} from {sender}")
    logger.debug(f"Current temp_list_of_clients: {temp_list_of_clients}")

    if str(sender) in temp_list_of_clients:
        if temp_list_of_clients[str(sender)].get("logged") and temp_list_of_clients[str(sender)].get("authenticated"):
            if tag == "GREETING_FROM_CLIENT":
                server_socket.sendto(format_message("Hello from server!").encode(), sender)
            else:
                if tag == "${DM_TAG}":
                    logger.info(f"Searching for address of recipient {username} for DM_TAG.")
                    recipient_address = endpoints.get_sender_by_username(username)
                    logger.info(f"Receipient address for DM_TAG: {recipient_address}")
                    if recipient_address is not None:
                        # Log the name of the recipient and flag if they are logged in
                        logger.info(f"DM_TAG: Recipient {username} exists and is logged in: {temp_list_of_clients[recipient_address].get('logged')}")
                        if temp_list_of_clients[recipient_address].get("logged"):
                            endpoints.set_dm_recipient(str(sender), username)
                            server_socket.sendto(format_message(f"DM_OK").encode(), sender)
                        else:
                            logger.warning(f"DM_FAIL: Recipient {username} does not exist or is not logged in.")
                            server_socket.sendto(format_message(f"DM_FAIL: Recipient {username} does not exist or is not logged in.").encode(), sender)
                    else:
                        logger.warning(f"DM_FAIL: Recipient {username} does not exist or is not logged in. Address: {recipient_address}")
                        server_socket.sendto(format_message(f"DM_FAIL: Recipient {username} does not exist or is not logged in.").encode(), sender)
                        
                else:
                    plaintext = EncryptionModule.decrypt_AES(
                    endpoints.get_session_key(sender), nonce=tag, ciphertext=username, tag=password, message_flag=True)
                    # message_formatted = format_message(plaintext, sender)
                    if str(sender) in temp_list_of_clients:
                        if temp_list_of_clients[str(sender)].get("dm_recipient") != "Unknown":
                            # If the sender has a DM recipient set, send the message only to that recipient
                            recipient_address = temp_list_of_clients[str(sender)].get("dm_recipient")
                            logger.info(f"DM recipient for {sender} is {recipient_address}. Sending message to recipient.")
                            if recipient_address in temp_list_of_clients and temp_list_of_clients[recipient_address].get("logged"):
                                message_formatted = format_message(plaintext, sender, True)
                                recipient_str = str(recipient_address)
                                recipient_tuple = tuple(recipient_str.strip("()").replace("'", "").split(", "))
                                recipient_tuple = (recipient_tuple[0], int(recipient_tuple[1]))
                                server_socket.sendto((encrypt_message(recipient_address, message_formatted)).encode(), recipient_tuple)
                            else:
                                logger.warning(f"DM recipient {recipient_address} is not logged in or does not exist.")
                        else:
                            # Broadcast the message to all clients except the sender
                            message_formatted = format_message(plaintext, sender)
                            for client in temp_list_of_clients:
                                if str(client) != str(sender) and temp_list_of_clients[client].get("logged"):
                                    # client from str to tuple
                                    print(f"Client str to tuple: {client}, {type(client)}")
                                    client_tuple = tuple(client.strip("()").replace("'", "").split(", "))
                                    client_tuple = (client_tuple[0], int(client_tuple[1]))  # Convert port to int
                                    print(f"Client tuple: {client_tuple}, {type(client_tuple)}")
                                    server_socket.sendto((encrypt_message(client, message_formatted)).encode(), client_tuple)
        elif not temp_list_of_clients[str(sender)].get("logged") and not temp_list_of_clients[str(sender)].get("authenticated") and tag == "${AUTH_TAG}":
            handle_authentication_request(server_socket, sender, username, password, encrypted)
        elif not temp_list_of_clients[str(sender)].get("logged") and temp_list_of_clients[str(sender)].get("authenticated"):
            plaintext = EncryptionModule.decrypt_AES(
            endpoints.get_session_key(sender), nonce=username, ciphertext=password, tag=encrypted, message_flag=True)
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
    elif sender not in temp_list_of_clients and tag == "${CONNECT_TAG}":
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