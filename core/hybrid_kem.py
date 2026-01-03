# core/hybrid_kem.py
import secrets
import hashlib

class HybridKEM:
    def __init__(self):
        self.pqc_name = "Kyber-512 (Mock)"
        self.ecc_name = "Secp256r1"

    def generate_handshake_package(self):
        ecc_pub = secrets.token_bytes(32)
        pqc_pub = secrets.token_bytes(800)
        return ecc_pub + pqc_pub

    def derive_final_key(self, ecc_shared, pqc_shared):
        hasher = hashlib.sha256()
        hasher.update(ecc_shared)
        hasher.update(pqc_shared)
        return hasher.digest()