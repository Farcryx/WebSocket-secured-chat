import socket
import threading
from read_credentials import load_server_credentials
from Crypto.Cipher import AES

private_key = hex(706)[2:]
public_key = hex(5270271518858497243038876548087803844445764591868474997634)[2:]

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

# Initialize the client with server IP and port
client_socket, server_address, server_port = client_init()

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

def handle_server_response(response: str, private_key: int) -> None:
    """
    Handles the server's response during the Diffie-Hellman key exchange.
    Args:
        response (str): The server's response message.
        private_key (int): The client's private key.
    """
    try:
        # Parse the server's response
        parts = response.split(":")
        server_public_key = int(parts[0], 16)
        prime = int(parts[1], 16)
        generator = int(parts[2], 16)
        nonce = int(parts[3], 16)
        ciphertext = bytes.fromhex(parts[4])
        tag = bytes.fromhex(parts[5])
        
        # Calculate the shared session key
        session_key = pow(server_public_key, private_key, prime)
        session_key_bytes = session_key.to_bytes((session_key.bit_length() + 7) // 8, 'big')
        nonce_bytes = nonce.to_bytes((nonce.bit_length() + 7) // 8, 'big')
        
        # Decrypt the session key using AES-GCM
        cipher = AES.new(session_key_bytes, AES.MODE_GCM, nonce=nonce_bytes)
        decrypted_session_key = cipher.decrypt_and_verify(ciphertext, tag)
        
        # Verify the session key
        if decrypted_session_key != session_key_bytes:
            raise ValueError("Session key verification failed.")
        
        print(f"Session key successfully established. {decrypted_session_key.hex().upper()}")
        message = decrypted_session_key.hex().upper()

        #cipher
        cipher = AES.new(decrypted_session_key, AES.MODE_GCM, nonce=nonce_bytes)
        ciphertext, tag = cipher.encrypt_and_digest(message.encode())
        message = "${AUTH_TAG}:" + f"{hex(nonce)[2:].upper()}:{ciphertext.hex().upper()}:{tag.hex().upper()}"
        print(message)
        send_message(client_socket, message, server_address, server_port)
    except Exception as e:
        print(f"Error handling server response: {e}")


def receive_message() -> None:
    """
    Receives a message from the server and displays it.
    """
    while True:
        try:
            # Receive data from the server (1024 bytes buffer size)
            data = client_socket.recvfrom(1024)[0]
            print(f"{data.decode()}")
            if data.decode().startswith("<From Server> ${CONNECT_TAG}:"):
                # Handle the server's response for the Diffie-Hellman key exchange
                print("Received server response for Diffie-Hellman key exchange.")
                # Extract the server's public key and other parameters
                handle_server_response(data.decode()[29:], int(private_key, 16))
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
    # Start a thread to receive messages from the server
    receive_thread = threading.Thread(target=receive_message)
    receive_thread.start()
    # Main loop to send messages
    init = True
    while True:
        try:
            if init:
                # greeting = input("Do you want to autheticate to the server? (y/n): ")
                greeting = 'y'
                if greeting.lower() == 'y':
                    # public_key = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6"
                    # message = str("${CONNECT_TAG}:" + public_key)
                    message = str(public_key)
                    send_message(client_socket, message, server_address, server_port)
                    
                    print("Connected to the server.")
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