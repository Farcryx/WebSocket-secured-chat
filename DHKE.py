import random
import os
import hashlib as hash

class DHKE:
    # def __init__(self):
        # self.G_param = 2
        # self.P_param = int('FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1'
        # '29024E088A67CC74020BBEA63B139B22514A08798E3404DD'
        # 'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245'
        # 'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
        # 'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381'
        # 'FFFFFFFFFFFFFFFF', 16)
        # self.P_param = int('FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1', 16)
        # self.P_param = os.urandom(16) # to int
        # self.P_param = int.from_bytes(os.urandom(16), 'big')

    def input_params(self, P, G):
        self.P_param = P
        self.G_param = G

    def generate_privatekey(self):
        self.pk = int.from_bytes(os.urandom(16), 'big')
        print(f"Private key: {self.pk}")

    def generate_publickey(self):
        self.generate_privatekey()
        self.pub_key = pow(self.G_param,self.pk) % self.P_param
        print(f"Public key: {self.pub_key}")

    def generate_session_key(self,other_public):
        self.share_key = pow(other_public,self.pk) % self.P_param
        # Hash the shared key to create a 128-bit session key
        self.session_key = hash.sha256(str(self.share_key).encode()).hexdigest()[16:]
        print(f"Session key: {self.session_key}")
    
    def generate_nonce(self):
        self.nonce = random.randrange(start = 1,stop = 10,step = 1)
        print(f"Nonce: {self.nonce}")
    
    