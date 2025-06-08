import socket
import threading
from read_credentials import load_server_credentials
from Crypto.Cipher import AES
import hashlib as hash
import base64
from encryption_module import EncryptionModule

private_key = 238914750585962230822924015716655039632
public_key = 64
prime = 73

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

def decrypt_AES(session_key: str, nonce: str, ciphertext: str, tag: str) -> str:
    """
    Decrypts the AES-encrypted session key using the provided nonce and tag.
    Args:
        session_key (str): The session key for decryption (base64 encoded).
        nonce (str): The nonce used for encryption (base64 encoded).
        ciphertext (str): The encrypted data (base64 encoded).
        tag (str): The authentication tag (base64 encoded).
    Returns:
        str: The decrypted session key.
    """
    try:
        return EncryptionModule.decrypt_AES(session_key, nonce, ciphertext, tag)
    except ValueError as e:
        print(f"Decryption failed: {e}")
        raise ValueError("Decryption failed. Invalid session key or nonce.")
    except Exception as e:
        print(f"Error during decryption: {e}")
        raise ValueError("Decryption error. Invalid session key or nonce.")

def handle_server_response(response: str) -> None:
    """
    Handles the server's response during the Diffie-Hellman key exchange.
    Args:
        response (str): The server's response message.
        private_key (int): The client's private key.
    """
    # Parse the server's response
    parts = response.split(":")
    server_public_key = int(parts[0], 16)
    nonce = parts[1]
    ciphertext = parts[2]
    tag = parts[3]

    print(f"""
          Server public key: {server_public_key}
          Nonce: {nonce}
          Ciphertext: {ciphertext}
          Tag: {tag}
          """)
    # Calculate the shared session key
    session_key = pow(server_public_key, private_key, prime)
    session_key_hashed = hash.sha256(str(session_key).encode()).digest()[-16:]
    session_key_b64 = base64.b64encode(session_key_hashed).decode()
    nonce_bytes = int(nonce, 16).to_bytes((int(nonce, 16).bit_length() + 7) // 8, 'big')
    nonce_b64 = base64.b64encode(nonce_bytes).decode()
    plaintext = decrypt_AES(session_key_b64, nonce_b64, ciphertext, tag)
    print(f"Decrypted session key: {plaintext}")
    if str(session_key) == plaintext:
        print("Session key matched.")
    else:
        print("Session key mismatch.")


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
                handle_server_response(data.decode()[29:])
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
                    message = "${CONNECT_TAG}:40:49:6D"
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