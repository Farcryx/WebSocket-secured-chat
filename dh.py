import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

P = int('FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1'
        '29024E088A67CC74020BBEA63B139B22514A08798E3404DD'
        'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245'
        'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
        'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381'
        'FFFFFFFFFFFFFFFF', 16)
G = 2

def generate_dh_keys() -> tuple[int, int]:
    """
    Generuje klucze Diffie-Hellmana.
    Zwraca:
        tuple: Klucz prywatny i klucz publiczny.
    """
    private_key = random.randint(2, P - 2)
    public_key = pow(G, private_key, P)
    return private_key, public_key
    
def AES_CBC_Decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

# def process_authentication(client_data: dict, client_public_key: str, IV_AES: str, encrypted: str) -> bool:
#     """
#     Processes the authentication of a client by decrypting and validating their data.
#     """
#     try:
#         prime = client_data["prime"]
#         private_key = client_data["private_key"]
#         session_key = pow(int(client_public_key, 16), private_key, prime)

#         # Decrypt the data using AES
#         plaintext = AES_CBC_Decrypt(session_key, IV_AES, encrypted)
#         plaintext_parts = plaintext.decode().split(":")
#         hash_pw = plaintext_parts[0]
#         decrypted_session_key = plaintext_parts[1]

#         return decrypted_session_key == session_key
#     except Exception as e:
#         print(f"Authentication failed: {e}")
#         return False