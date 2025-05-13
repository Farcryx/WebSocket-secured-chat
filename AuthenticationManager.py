# import logging_module
from Crypto.Cipher import AES
from dh import *
from DHKE import DHKE

class AuthenticationManager:
    def __init__(self):
        self.no_auth_clients = {}
        self.list_of_clients = {}
        self.DHKE_instance = DHKE()

    def add_unauthenticated_client(self, sender: str, public_key: str, nonce: str):
        """
        Adds an unauthenticated client to the list of clients.
        Args:
            sender (str): The identifier of the client.
            public_key (str): The public key of the client.
            nonce (str): The nonce for the client.
        """
        self.no_auth_clients[sender] = {
            "client_public_key": public_key,
            "nonce": nonce
        }
    
    def add_authenticated_client(self, sender: str, username: str, session_key: str) -> None:
        """
        Adds an authenticated client to the list of clients.
        Args:
            sender (str): The identifier of the client.
            username (str): The username of the client.
            session_key (str): The session key for the client.
        """
        if sender in self.no_auth_clients:
            del self.no_auth_clients[sender]
        self.list_of_clients[sender] = {
            "username": username,
            "session_key": session_key,
            "logged": True
        }

    def decrypt_AES(self, session_key: str, nonce: str, ciphertext: str, tag: str) -> str:
        """
        Decrypts the AES-encrypted session key using the provided nonce and tag.
        Args:
            session_key (str): The session key for decryption.
            nonce (str): The nonce used for encryption.
            ciphertext (str): The encrypted data.
            tag (str): The authentication tag.
        Returns:
            str: The decrypted session key.
        """
        secret_bytes = (int(session_key, 16).bit_length() + 7) // 8
        nonce_bytes = (int(nonce, 16).bit_length() + 7) // 8
        cipher = AES.new(
            int(session_key, 16).to_bytes(secret_bytes, 'big'),
            AES.MODE_GCM,
            nonce=int(nonce, 16).to_bytes(nonce_bytes, 'big')
        )
        plaintext = cipher.decrypt_and_verify(bytes.fromhex(ciphertext), bytes.fromhex(tag))
        return plaintext.decode()
    
    def encrypt_AES(self, session_key: str, nonce: str, plaintext: str) -> tuple[str, str]:
        """
        Encrypts the plaintext using AES with the provided session key and nonce.
        Args:
            session_key (str): The session key for encryption.
            nonce (str): The nonce used for encryption.
            plaintext (str): The data to encrypt.
        Returns:
            tuple[str, str]: The ciphertext and authentication tag.
        """
        secret_bytes = (int(session_key, 16).bit_length() + 7) // 8
        nonce_bytes = (int(nonce, 16).bit_length() + 7) // 8
        cipher = AES.new(
            int(session_key, 16).to_bytes(secret_bytes, 'big'),
            AES.MODE_GCM,
            nonce=int(nonce, 16).to_bytes(nonce_bytes, 'big')
        )
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
        return ciphertext.hex(), tag.hex()

    def init_connection_for_client(self, sender: str, client_public_key: str, prime: str, generator: str) -> str:
        """
        Initializes a connection for the client by generating Diffie-Hellman keys and sending the response.
        Args:
            sender (str): The identifier of the client.
            client_public_key (str): The public key of the client.
            Returns (str): The response message containing the server's public key, prime, generator, nonce, and encrypted session key.
        """
        print(f"Client {sender} requested initialization of connection.")
        self.DHKE_instance.input_params(int(prime, 16), int(generator, 16))
        
        # Generowanie kluczy Diffie-Hellmana
        self.DHKE_instance.generate_publickey()
        print(f"Server's public key: {self.DHKE_instance.pub_key}")
        self.DHKE_instance.generate_nonce()
        session_key = self.DHKE_instance.exchange_key(int(client_public_key, 16))
        self.no_auth_clients[sender]["session_key"] = session_key
        
        # Dodanie klienta do listy nieautoryzowanych
        self.add_unauthenticated_client(sender, client_public_key, self.DHKE_instance.nonce)
        
        ciphertext, tag = self.encrypt_AES(
            session_key=str(self.DHKE_instance.share_key),
            nonce=str(self.DHKE_instance.nonce),
            plaintext=str(self.DHKE_instance.share_key)
        )

        return "${CONNECT_TAG}:" + f"{hex(self.DHKE_instance.pub_key)[2:]}:{hex(self.DHKE_instance.nonce)[2:]}:{ciphertext}:{tag}".upper()

    def log_client(self, sender) -> bool:
        """
        Flag for the auth client.
        """
        # For the sender in self.auth_clients add flag True
        if sender in self.no_auth_clients:
            self.no_auth_clients[sender]["logged"] = True
            return True
        else:
            return False
        
    def get_session_key(self, sender) -> str:
        """
        Returns the session key for the client.
        Args:
            sender (str): The identifier of the client.
        Returns:
            str: The session key for the client.
        """
        if sender in self.list_of_clients:
            return self.list_of_clients[sender]["session_key"]
        else:
            return None
        
    def get_username(self, sender) -> str:
        """
        Returns the username for the client.
        Args:
            sender (str): The identifier of the client.
        Returns:
            str: The username for the client.
        """
        if sender in self.list_of_clients:
            return self.list_of_clients[sender]["username"]
        else:
            return "Unknown"
        
    def get_client_logged(self, sender) -> bool:
        """
        Returns the logged status for the client.
        Args:
            sender (str): The identifier of the client.
        Returns:
            bool: The logged status for the client.
        """
        if sender in self.list_of_clients:
            return self.list_of_clients[sender]["logged"]
        else:
            return False