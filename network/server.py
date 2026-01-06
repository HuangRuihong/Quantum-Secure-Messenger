# server.py
import socket
import json
import traceback
from innovative_hybrid_kem import InnovativeHybridKEM

def start_gateway():
    print(" 創新安全閘道器 v2.1 (架構重構版)")
    print("=" * 50)
    
    # 初始化核心
    server_kem = InnovativeHybridKEM()
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', 8888))
    server.listen(5)
    print(" 監聽 127.0.0.1:8888...\n")

    while True:
        conn, addr = server.accept()
        print(f"\n[連線] {addr}")
        
        try:
            # 1. 接收 Header (版本 + 長度)
            version = conn.recv(1)
            header = conn.recv(4)
            if not header: break
            
            expected_size = int.from_bytes(header, 'big')
            print(f" 預期封包大小: {expected_size} bytes")
            
            # 2. 接收 Payload
            data = b""
            while len(data) < expected_size:
                packet = conn.recv(min(4096, expected_size - len(data)))
                if not packet: break
                data += packet
            
            # 3. 調用核心進行解析 (封裝後的好處：Server 不用管第幾個 byte 是什麼)
            package = server_kem.parse_handshake_package(data)
            
            print(f" 解析成功 -> SessionID: {package['session_id']}")
            # Server 必須同步採用 Client 的 Session ID，否則 KDF 運算結果會不同
            server_kem.session_id = package['session_id']
            
            # 4. PQC 解封裝
            pqc_shared = server_kem.decapsulate_pqc(package['pqc_ciphertext_effective'])
            
            # 5. 衍生金鑰
            session_keys = server_kem.derive_final_key(
                package['ecc_pub'],
                pqc_shared,
                package['salt'],
                package['timestamp']
            )
            
            print(" 金鑰協商完成!")
            print(f"  • Session Key (Hex): {session_keys['session_key'].hex()[:16]}...")

            # 6. 回應 Client (必須包含 Server 的 ECC 公鑰)
            response = {
                'success': True,
                'server_ecc_pub': server_kem.ecc_public_bytes.hex(), # 重要！
                'session_id': server_kem.session_id
            }
            conn.sendall(json.dumps(response).encode())
            
        except Exception as e:
            print(f" 錯誤: {e}")
            traceback.print_exc()
            conn.close()

if __name__ == "__main__":
    start_gateway()