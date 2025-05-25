from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from console_logger import logger
from binascii import unhexlify
from Crypto.Cipher import AES

class EncryptionModule:
    """
    Handles AES-GCM encryption and decryption.
    """

    @staticmethod
    def encrypt_AES(session_key: str, nonce: str, plaintext: str) -> tuple[str, str]:
        """
        Encrypts the plaintext using AES with the provided session key and nonce.
        Args:
            session_key (str): The session key for encryption (hex string).
            nonce (str): The nonce used for encryption (hex string).
            plaintext (str): The data to encrypt.
        Returns:
            tuple[str, str]: The ciphertext and authentication tag (both hex encoded).
        """
        key_bytes = bytes.fromhex(session_key)
        nonce_bytes = bytes.fromhex(nonce)
        cipher = Cipher(
            algorithms.AES(key_bytes), modes.GCM(nonce_bytes), backend=default_backend()
        )
        encryptor = cipher.encryptor()
        if type(plaintext) is not bytes:
            ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        else:
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext.hex(), encryptor.tag.hex()

    @staticmethod
    def decrypt_AES(session_key: str, nonce: str, ciphertext: str, tag: str, message_flag: bool=False) -> str:
        """
        Decrypts the AES-encrypted data using the provided key, nonce and tag.
        Args:
            session_key (str): The session key for decryption (hex string).
            nonce (str): The nonce used for encryption (hex string).
            ciphertext (str): The encrypted data (hex string).
            tag (str): The authentication tag (hex string).
        Returns:
            str: The decrypted plaintext.
        """
        logger.debug("Starting decryption process...")
        logger.debug(f"Ciphertext: {ciphertext}, Session Key: {session_key}, Nonce: {nonce}, Tag: {tag}")
        try:
            key_bytes = bytes.fromhex(session_key)
            nonce_bytes = bytes.fromhex(nonce)
        except ValueError as ve:
            logger.error(f"ValueError during hex to bytes conversion: {ve}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error during hex to bytes conversion: {e}")
            return None
        
        try:
            key = unhexlify(session_key)
            nonce = unhexlify(nonce)
            ciphertext = unhexlify(ciphertext)
            tag = unhexlify(tag)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            cipher.update(b'')
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            logger.debug(f"Decrypted plaintext: {plaintext.hex()}")
            if message_flag:
                return plaintext.decode()
            else:
                # Return the hex representation of the plaintext
                logger.debug(f"Returning hex representation of plaintext: {plaintext.hex()}")
            return plaintext.hex()
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
        return None
