import socket
import threading
import json
import time
import struct
import traceback
from typing import Dict, Optional, Callable
from innovative_hybrid_kem import InnovativeHybridKEM, PacketFormatError, KeyGenerationError
class ServerBackend:
    def __init__(self, host: str = '0.0.0.0', port: int = 8888, log_callback: Optional[Callable[[str], None]] = None):
        self.host = host
        self.port = port
        self.server_socket: Optional[socket.socket] = None
        self.running = False
        self.kem = InnovativeHybridKEM()
        self.active_connections: Dict[str, threading.Thread] = {}
        self.log_callback = log_callback if log_callback else print
    def log(self, message: str):
        self.log_callback(message)
    def start_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.running = True
        self.log(f" 伺服器啟動於 {self.host}:{self.port}")
        accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        accept_thread.start()
    def _accept_loop(self):
        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                client_id = f"{addr[0]}:{addr[1]}"
                self.log(f"[新連接] {client_id}")
                t = threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True)
                self.active_connections[client_id] = t
                t.start()
            except OSError:
                break
            except Exception as e:
                self.log(f" 接受連接錯誤: {e}")
    def _handle_client(self, conn: socket.socket, addr):
        connection_kem = InnovativeHybridKEM() # 每個連接獨立的 KEM 實例 (如果需要) - 其實 Server 一個主要的 Key 就夠，但 Session ID 不同
        # 這裡為了簡單，我們混用 self.kem 的 ECC Key 但用新的 Session 狀態
        # 注意: InnovativeHybridKEM 預設 init 會生成新 Key。Server 應保持長期 Key
        # 為了正確性，這裡我們暫時讓每個連接有獨立 Key (Forward Secrecy 更好)
        session_keys = None
        client_id = f"{addr[0]}:{addr[1]}"
        try:
            # 1. 讀取版本
            version = conn.recv(1)
            if not version: return
            # 2. 讀取長度
            length_bytes = conn.recv(4)
            length = int.from_bytes(length_bytes, 'big')
            # 3. 讀取握手包
            handshake_data = b""
            while len(handshake_data) < length:
                chunk = conn.recv(length - len(handshake_data))
                if not chunk: break
                handshake_data += chunk
            # 4. 解析與 PQC 封裝
            package = connection_kem.parse_handshake_package(handshake_data)
            connection_kem.session_id = package['session_id']
            connection_kem._session_id_bin = package['session_id_bin']
            pqc_ciphertext, pqc_shared = connection_kem.server_pqc_encapsulate(package['pqc_public_key'])
            session_keys = connection_kem.derive_final_key(
                package['ecc_pub'], pqc_shared, package['salt'], package['timestamp']
            )
            self.log(f"[{client_id}] 握手成功")
            # 5. 回應
            response = {
                'success': True,
                'server_ecc_pub': connection_kem.ecc_public_bytes.hex(),
                'pqc_ciphertext': pqc_ciphertext.hex(),
                'session_id': connection_kem.session_id,
                'timestamp': time.time()
            }
            conn.sendall(json.dumps(response).encode())
            # 6. 訊息迴圈
            while True:
                data = conn.recv(4096)
                if not data: break
                
                try:
                    msg_obj = json.loads(data.decode('utf-8'))
                    if msg_obj.get('type') == 'secure_msg':
                        decrypted = connection_kem.decrypt_aes_gcm(
                            session_keys['encryption_key'],
                            msg_obj['data']
                        )
                        self.log(f"[{client_id}] 收到加密訊息: {decrypted}")
                        conn.sendall(json.dumps({"type": "ack"}).encode())
                except Exception as e:
                    self.log(f"[{client_id}] 解密/處理錯誤: {e}")
                    
        except Exception as e:
            self.log(f"[{client_id}] 連接中斷: {e}")
        finally:
            conn.close()
            if client_id in self.active_connections:
                del self.active_connections[client_id]
    def stop(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()
# Console Runner
def run_console_server():
    server = ServerBackend()
    server.start_server()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.stop()
if __name__ == "__main__":
    run_console_server()