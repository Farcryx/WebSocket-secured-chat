import random
import os
import hashlib as hash


class DHKE:
    def input_params(self, G, P):
        self.P_param = P
        self.G_param = G
        # print(f"Input params: P = {self.P_param}, G = {self.G_param}")

    def generate_privatekey(self):
        self.pk = int.from_bytes(os.urandom(16), "big")
        # print(f"Private key: {self.pk}")

    def generate_publickey(self):
        self.generate_privatekey()
        self.pub_key = pow(self.G_param, self.pk, self.P_param)
        # print(f"Public key: {self.pub_key}")

    def generate_session_key(self, other_public):
        self.share_key = pow(other_public, self.pk, self.P_param)
        # print(f"Shared key: {self.share_key}")
        # Hash the shared key to create a 128-bit session key
        self.session_key = (
            hash.sha256(str(self.share_key).encode()).hexdigest().upper()[:32]
        )  # [32:]
        # print(f"Session key: {self.session_key}")

    def generate_nonce(self):
        while True:
            self.nonce = int.from_bytes(os.urandom(12), "big")
            if (
                all(c in "0123456789abcdefABCDEF" for c in hex(self.nonce)[2:])
                and len(hex(self.nonce)[2:]) == 24
            ):
                break
