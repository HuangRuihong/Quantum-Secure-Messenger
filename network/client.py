import socket
from core.hybrid_kem import HybridKEM # 引入你的核心邏輯

def run_client():
    kem = HybridKEM()
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0.1', 8888))

    # 呼叫你寫的邏輯產生真正的「混合金鑰包」
    handshake_data = kem.generate_handshake_package()
    
    header = len(handshake_data).to_bytes(4, byteorder='big')
    client.sendall(header + handshake_data)
    print(f"📤 混合金鑰 ({kem.pqc_name} + {kem.ecc_name}) 已發送。")
    client.close()

if __name__ == "__main__":
    run_client()