# client.py
import socket
import json
from innovative_hybrid_kem import InnovativeHybridKEM

def run_client():
    print(" 啟動 Client v2.1...")
    kem = InnovativeHybridKEM()
    
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect(('127.0.0.1', 8888))
        
        # 1. [關鍵] 生成 PQC 共享秘密與密文
        # 這是混合加密的核心：Client 決定 PQC 秘密，Server 決定 ECC 秘密(透過ECDH)
        pqc_shared_secret, pqc_ciphertext = kem.encapsulate_pqc()
        print(f" 本地生成 PQC Secret (前16碼): {pqc_shared_secret.hex()[:16]}...")
        
        # 2. 打包 (將密文放入握手包)
        handshake_data = kem.generate_handshake_package(pqc_ciphertext)
        
        # 3. 發送
        client.sendall(b'\x02') # Version
        client.sendall(len(handshake_data).to_bytes(4, 'big'))
        client.sendall(handshake_data)
        print(" 握手包已發送")
        
        # 4. 接收 Server 回應
        resp_raw = client.recv(4096)
        response = json.loads(resp_raw.decode())
        
        if response['success']:
            print(" 收到 Server 回應")
            
            # 5. 取得 Server 的 ECC 公鑰
            server_ecc_pub = bytes.fromhex(response['server_ecc_pub'])
            
            # 6. 衍生最終金鑰
            # 為了拿到 salt 和 timestamp (與發送出去的一致)，我們解析剛剛生成的包
            my_pkg = kem.parse_handshake_package(handshake_data)
            
            session_keys = kem.derive_final_key(
                server_ecc_pub,      # 對方的 ECC 公鑰
                pqc_shared_secret,   # 我剛剛生成的 PQC 秘密 (這就是為什麼兩邊會一樣！)
                my_pkg['salt'],
                my_pkg['timestamp']
            )
            
            print("="*30)
            print(" Client 協商成功！")
            print(f" • Session Key: {session_keys['session_key'].hex()[:16]}...")
            print("="*30)
            print(" (請比對 Server 端的 Session Key，兩者應該完全一致)")
            
    except Exception as e:
        print(f" Error: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    run_client()