
import socket
import json
import time
import threading
import traceback
from typing import Optional, Callable
from innovative_hybrid_kem import InnovativeHybridKEM, PacketFormatError, KeyGenerationError

class ClientBackend:
    def __init__(self, callback_log: Optional[Callable[[str], None]] = None):
        self.kem = InnovativeHybridKEM()
        self.client_socket: Optional[socket.socket] = None
        self.session_keys = None
        self.connected = False
        self.log_callback = callback_log if callback_log else print

    def log(self, message: str):
        self.log_callback(message)

    def connect(self, host: str = '127.0.0.1', port: int = 8888) -> bool:
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(10.0)
            self.client_socket.connect((host, port))
            self.connected = True
            self.log(f" 連接成功! ({host}:{port})")
            return True
        except Exception as e:
            self.log(f" 連接失敗: {e}")
            return False

    def perform_handshake(self) -> bool:
        if not self.client_socket:
            return False
        
        try:
            # 1. 生成 KeyPair
            self.log(" 生成 PQC 金鑰對 (Kyber-768)...")
            pqc_pk, pqc_sk = self.kem.client_pqc_keygen()
            
            # 2. 發送
            handshake_data = self.kem.generate_handshake_package(pqc_pk)
            self.client_socket.sendall(b'\x02')
            self.client_socket.sendall(len(handshake_data).to_bytes(4, 'big'))
            self.client_socket.sendall(handshake_data)
            self.log(" 握手包已發送")

            # 3. 接收
            self.client_socket.settimeout(10.0)
            resp_raw = self.client_socket.recv(4096)
            
            if not resp_raw:
                self.log(" 伺服器無回應")
                return False

            response = json.loads(resp_raw.decode('utf-8'))
            
            if response.get('success'):
                # 4. 解封裝
                server_ecc_pub = bytes.fromhex(response['server_ecc_pub'])
                pqc_ciphertext = bytes.fromhex(response['pqc_ciphertext'])
                pqc_shared = self.kem.client_pqc_decapsulate(pqc_ciphertext, pqc_sk)
                
                # 5. 衍生金鑰
                my_pkg = self.kem.parse_handshake_package(handshake_data)
                self.session_keys = self.kem.derive_final_key(
                    server_ecc_pub, pqc_shared, my_pkg['salt'], my_pkg['timestamp']
                )
                self.log(" 握手成功! 金鑰協商完成")
                return True
            else:
                self.log(f" 握手失敗: {response.get('error')}")
                return False

        except Exception as e:
            self.log(f" 握手過程出錯: {e}")
            traceback.print_exc()
            return False

    def send_secure_message(self, message: str) -> Optional[str]:
        if not self.session_keys:
            self.log(" 尚未建立安全會話")
            return None
            
        try:
            encrypted = self.kem.encrypt_aes_gcm(self.session_keys['encryption_key'], message)
            payload = {
                "type": "secure_msg",
                "data": encrypted,
                "timestamp": time.time()
            }
            self.client_socket.sendall(json.dumps(payload).encode())
            
            # 簡單等待回應 (Blocking)
            resp = self.client_socket.recv(4096)
            if resp:
                return resp.decode('utf-8')
            return None
        except Exception as e:
            self.log(f" 發送失敗: {e}")
            return None

    def close(self):
        if self.client_socket:
            self.client_socket.close()
        self.connected = False

# Console Runner
def run_console_client():
    client = ClientBackend()
    if client.connect():
        if client.perform_handshake():
            while True:
                msg = input("輸入消息 (q退出): ")
                if msg.lower() == 'q': break
                resp = client.send_secure_message(msg)
                print(f"Server回應: {resp}")
    client.close()

if __name__ == "__main__":
    run_console_client()