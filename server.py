import socket
from read_credentials import load_server_credentials
from dh import generate_public_key
from sign_ip_in import sign_up, sign_in

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
        print(f"Server initialized and connected to {address}:{port}")
        return server
    except Exception as e:
        print(f"Error initializing server: {e}")
        exit("Failed to initialize server.")

def format_message(message: str, sender: str=None) -> str:
    """
    Formats the message for display.
    Args:
        sender (str): The sender of the message.
        message (str): The message content.
    """
    return f"<From {f'{sender[0]}:{sender[1]}' if sender else 'Server'}> {message}"

if __name__ == "__main__":
    # Initialize the server
    server_socket = server_init()
    list_of_clients = [] # List to keep track of connected clients
    print("- " * 30)
    i = 3

    if i == 0:
        username = "admin123"
        password = "123"
        # Test to write hashed credentials
        hashed_password = hash.sha256(password.encode()).hexdigest()
        sign_up(username, hashed_password)
        # Test to read hashed credentials
        # username, hashed_password = read_credentials()
        print(f"Username: {username}, Hashed Password: {hashed_password}")
    
    if i == 2:
        # Test to generate Diffie-Hellman public key
        for i in range(1):
            private_key, public_key = generate_public_key()
            # print(f"Private Key: {private_key}, \nPublic Key: {public_key}")
            # Print splitted hexadecimal public and private key
            public_key_hex = hex(public_key)[2:]
            public_key_hex = " ".join(public_key_hex[i:i+8] for i in range(0, len(public_key_hex), 8))
            print(f"Public Key: {public_key_hex.upper()}")
            private_key_hex = hex(private_key)[2:]
            private_key_hex = " ".join(private_key_hex[i:i+8] for i in range(0, len(private_key_hex), 8))
            print(f"Private Key: {private_key_hex.upper()}")

    while i == 1:
        try:
            # Receive data from clients (1024 bytes buffer size)
            data, sender = server_socket.recvfrom(1024)
            data_received = data.decode()

            # Split the received data into components
            parts = data_received.split(":")
            tag = parts[0] if len(parts) > 0 else None
            username = parts[1] if len(parts) > 1 else None
            password = parts[2] if len(parts) > 2 else None

            # if data_received != "${GREETING_TAG}":
            # if data_received != "GREETING_FROM_CLIENT":
            #     message_formatted = format_message(data_received, sender)
            #     print(message_formatted)
            #     # Broadcast the message to all clients except the sender
            #     for client in list_of_clients:
            #         if client != sender:
            #             server_socket.sendto(message_formatted.encode(), client)

            # Handle the connection request
            if tag == "${CONNECT_TAG}" or tag == "${GREETING_FROM_CLIENT}":
                list_of_clients.append(sender)
                print(format_message(f"New client {sender} connected"))
                pass
            # Handle the sign-up request
            elif tag == "${SIGNUP_TAG}":
                message = sign_up(username, password)
                server_socket.sendto(format_message(message).encode(), sender)
            # Handle the sign-in request
            elif tag == "${SIGNIN_TAG}":
                message = sign_in(username, password)
                server_socket.sendto(format_message(message).encode(), sender)
            # Handle the message from the client
            else:
                message_formatted = format_message(data_received, sender)
                print(message_formatted)
                # Broadcast the message to all clients except the sender
                for client in list_of_clients:
                    if client != sender:
                        server_socket.sendto(message_formatted.encode(), client)

        except Exception as e:
            print(format_message("An error occurred."))
                
        except KeyboardInterrupt:
            print("\nServer shutting down...")
            break
    server_socket.close() # Close the socket when done