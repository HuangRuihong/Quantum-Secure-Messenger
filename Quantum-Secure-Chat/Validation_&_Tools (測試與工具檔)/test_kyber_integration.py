
# network/test_kyber_integration.py
import sys
import os

# Add current directory to path so we can import modules
sys.path.append(os.getcwd())
sys.path.append(os.path.join(os.getcwd(), 'network'))

from innovative_hybrid_kem import InnovativeHybridKEM

def test_kyber_flow():
    print(">>> Starting Kyber-768 Integration Test")
    
    try:
        kem = InnovativeHybridKEM()
        print(f"Algorithm: {kem.pqc_name}")
        
        # 1. Client KeyGen
        print("\n[1] Client KeyGen...")
        pk, sk = kem.client_pqc_keygen()
        print(f"    Public Key size: {len(pk)} bytes (Expected: {kem.PQC_PUBLIC_KEY_LENGTH})")
        print(f"    Secret Key size: {len(sk)} bytes")
        
        if len(pk) != kem.PQC_PUBLIC_KEY_LENGTH:
            print("[FAIL] Public Key length mismatch!")
            return False

        # 2. Server Encapsulate
        print("\n[2] Server Encapsulate...")
        ciphertext, ss_server = kem.server_pqc_encapsulate(pk)
        print(f"    Ciphertext size: {len(ciphertext)} bytes (Expected: {kem.PQC_CIPHERTEXT_LENGTH})")
        print(f"    Shared Secret (Server): {ss_server.hex()[:16]}...")

        if len(ciphertext) != kem.PQC_CIPHERTEXT_LENGTH:
            print("[FAIL] Ciphertext length mismatch!")
            return False

        # 3. Client Decapsulate
        print("\n[3] Client Decapsulate...")
        ss_client = kem.client_pqc_decapsulate(ciphertext, sk)
        print(f"    Shared Secret (Client): {ss_client.hex()[:16]}...")
        
        # 4. Verify
        if ss_server == ss_client:
            print("\n[OK] SUCCESS: Shared Secrets MATCH!")
            print("Kyber-768 integration verified.")
            return True
        else:
            print("\n[FAIL] FAILURE: Shared Secrets do NOT match!")
            return False
            
    except Exception as e:
        print(f"\n[FAIL] Exception occurred: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    if test_kyber_flow():
        sys.exit(0)
    else:
        sys.exit(1)
