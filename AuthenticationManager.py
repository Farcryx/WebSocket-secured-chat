# import logging_module
import base64
from Crypto.Cipher import AES
from dh import *
from DHKE import DHKE
from encryption_module import EncryptionModule


class AuthenticationManager:
    def __init__(self, logger=None):
        self.no_auth_clients = {}  # No longer used (should be removed)
        self.list_of_clients = {}
        self.DHKE_instance = DHKE()
        self.logger = logger

    def add_unauthenticated_client(self, sender: str, public_key: str, nonce: str):
        """
        Adds an unauthenticated client to the list of clients.
        Args:
            sender (str): The identifier of the client.
            public_key (str): The public key of the client.
            nonce (str): The nonce for the client.
        """
        self.no_auth_clients[sender] = {"client_public_key": public_key, "nonce": nonce}

    def add_authenticated_client(
        self, sender: str, username: str, session_key: str
    ) -> None:
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
            "logged": True,
        }

    def add_client(
        self, sender: str, username: str, session_key: str, nonce: str
    ) -> None:
        """
        Adds a client to the list of clients.
        Args:
            sender (str): The identifier of the client.
            username (str): The username of the client.
            session_key (str): The session key for the client.
        """
        self.list_of_clients[sender] = {
            "username": username,
            "session_key": session_key,
            "nonce": nonce,
            "authenticated": False,
            "logged": False,
        }

    def init_connection_for_client(
        self, sender: str, client_public_key: str, prime: str, generator: str
    ) -> str:
        """
        Initializes a connection for the client by generating Diffie-Hellman keys and sending the response.
        Args:
            sender (str): The identifier of the client.
            client_public_key (str): The public key of the client.
            Returns (str): The response message containing the server's public key, prime, generator, nonce, and encrypted session key.
        """
        self.logger.debug(f"Client {sender} requested initialization of connection.")
        self.DHKE_instance.input_params(int(prime, 16), int(generator, 16))

        # Generowanie kluczy Diffie-Hellmana
        self.DHKE_instance.generate_publickey()
        self.DHKE_instance.generate_nonce()
        self.DHKE_instance.generate_session_key(int(client_public_key, 16))
        self.add_client(
            sender, "Unknown", self.DHKE_instance.session_key, self.DHKE_instance.nonce
        )
        self.logger.debug(
            f"Client {sender} connected with session key: {self.DHKE_instance.session_key} and nonce: {self.DHKE_instance.nonce}"
        )

        # Use the same nonce for encryption as generated
        session_key_hex = str(self.DHKE_instance.session_key)
        nonce_int = self.DHKE_instance.nonce
        nonce_hex = hex(nonce_int)[2:]  # Convert nonce to hex string
        nonce_bytes = nonce_int.to_bytes((nonce_int.bit_length() + 7) // 8, "big")

        ciphertext, tag = EncryptionModule.encrypt_AES(
            session_key=session_key_hex, nonce=nonce_hex, plaintext=session_key_hex
        )

        # Check if the encryption was successful (decrypt the ciphertext)
        try:
            decrypted_session_key = EncryptionModule.decrypt_AES(
                session_key=session_key_hex,
                nonce=nonce_hex,
                ciphertext=ciphertext,
                tag=tag,
            )
            # print(f"Decrypted session key: {decrypted_session_key}")
        except Exception as e:
            self.logger.error(f"Decryption failed: {e}")

        if decrypted_session_key == session_key_hex:
            print("Keys match!")

        # print(
        #     f"""
        #       IV: {nonce_hex}
        #       Ciphertext: {ciphertext}
        #       Tag: {tag}
        #       Session key: {session_key_hex}"""
        # )

        return (
            "${CONNECT_TAG}:"
            + f"{hex(self.DHKE_instance.pub_key)[2:]}:{hex(self.DHKE_instance.nonce)[2:]}:{ciphertext}:{tag}".upper()
        )

    def signin_client(self, sender):
        """
        Set the client as signed in.
        """
        # For the sender in self.auth_clients add flag True
        if sender in self.list_of_clients:
            self.list_of_clients[sender]["logged"] = True

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

    def set_authenticated_client(self, sender) -> None:
        """
        Sets the client as authenticated.
        Args:
            sender (str): The identifier of the client.
        """
        if sender in self.list_of_clients:
            self.list_of_clients[sender]["authenticated"] = True

    def check_if_username_logged(self, username: str) -> bool:
        """
        Checks if the username already exists in the list of clients.
        Args:
            username (str): The username to check.
        Returns:
            bool: True if the username exists, False otherwise.
        """
        for client in self.list_of_clients.values():
            if client["username"] == username:
                return True
        return False

    def encrypt_message(self, sender: str, message: str) -> str:
        """
        Encrypts the message using the session key of the client.
        Args:
            sender (str): The identifier of the client.
            message (str): The message to encrypt.
        Returns:
            str: The encrypted message.
        """
        if sender in self.list_of_clients:
            session_key = self.list_of_clients[sender]["session_key"]
            nonce = self.list_of_clients[sender]["nonce"]
            ciphertext, tag = EncryptionModule.encrypt_AES(session_key, nonce, message)
            return f"{nonce}:{ciphertext}:{tag}"
        else:
            return None
