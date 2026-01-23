import socket
import threading
import json
import time
import sys
import os

# 自動偵測「Core_Logic (核心邏輯)」資料夾並加入搜尋路徑
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
core_logic_path = os.path.join(project_root, "Core_Logic (核心邏輯)")

if core_logic_path not in sys.path:
    sys.path.append(core_logic_path)

import struct

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
        self.connected_clients: Dict[str, dict] = {} # {client_id: {'conn': conn, 'keys': keys, 'addr': addr}}
        self.session_key_cache: Dict[str, bytes] = {}
        self.log_callback = log_callback if log_callback else print
        self.client_event_callback: Optional[Callable[[str, str, str], None]] = None # (event, client_id, info)
        self.client_counter = 0

    def set_event_callback(self, callback):
        self.client_event_callback = callback

    def _trigger_event(self, event_type, client_id, info=""):
        if self.client_event_callback:
            self.client_event_callback(event_type, client_id, info)

    def log(self, message: str):
        self.log_callback(message)

    def start_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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
                
                self.client_counter += 1
                client_short_id = f"Client-{self.client_counter:02d}"
                client_full_id = f"{client_short_id} ({addr[0]}:{addr[1]})"

                self.log(f"[新連接] {client_full_id}")
                t = threading.Thread(target=self._handle_client, args=(conn, addr, client_full_id), daemon=True)
                self.active_connections[client_full_id] = t
                t.start()
            except OSError:
                break
            except Exception as e:
                self.log(f" 接受連接錯誤: {e}")

    def _remove_client(self, client_id):
        if client_id in self.connected_clients:
            try:
                self.connected_clients[client_id]['conn'].close()
            except:
                pass
            del self.connected_clients[client_id]
            self.log(f"[{client_id}] 已移除連接")
            self._trigger_event("leave", client_id)

    def broadcast(self, message: str, sender_id: str):
        """
        將解密後的訊息加密並發送給所有已連接且握手完成的客戶端
        """
        # 移除失效連接
        to_remove = []
        
        for client_id, client_data in self.connected_clients.items():

            try:
                target_conn = client_data['conn']
                target_keys = client_data['keys']
                
                if not target_keys: continue
                # 加密訊息 (使用該目標客戶端的 Key)
                # 訊息格式: "[sender_id] message"
                full_msg = f"[{sender_id}] {message}"
                encrypted = self.kem.encrypt_aes_gcm(target_keys['encryption_key'], full_msg)
                
                payload = {
                    "type": "secure_msg",
                    "data": encrypted,
                    "timestamp": time.time(),
                    "sender": sender_id
                }
                data = json.dumps(payload).encode('utf-8')
                header = struct.pack('!I', len(data)) # '!I' 代表大端序的無符號整數 (4 bytes)
                target_conn.sendall(header + data)
            except Exception as e:
                self.log(f" 廣播給 {client_id} 失敗: {e}")
                to_remove.append(client_id)
        
        for cid in to_remove:
            self._remove_client(cid)



    def _handle_client(self, conn: socket.socket, addr, client_id):
        connection_kem = InnovativeHybridKEM() 
        session_keys = None
        # client_id passed as arg
        
        # 暫存連接，尚未握手不加入 connected_clients (或加入但標記無 key)
        
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
            
            # 記錄握手成功的客戶端
            self.connected_clients[client_id] = {
                'conn': conn,
                'keys': session_keys,
                'addr': addr
            }
            self.session_key_cache[client_id] = session_keys
            
            self.log(f"[{client_id}] 握手成功")
            self._trigger_event("join", client_id)
            
            # 5. 回應
            response = {
                'success': True,
                'server_ecc_pub': connection_kem.ecc_public_bytes.hex(),
                'pqc_ciphertext': pqc_ciphertext.hex(),
                'session_id': connection_kem.session_id,
                'timestamp': time.time()
            }
            conn.sendall(json.dumps(response).encode())
        except Exception as e:
            self.log(f"[{client_id}] 握手/初始化失敗: {e}")
            conn.close()
            return

        def recv_all(conn, n):
            """輔助函式：確保從 socket 接收到正確數量的位元組"""
            data = b''
            while len(data) < n:
                packet = conn.recv(n - len(data))
                if not packet: return None
                data += packet
            return data

        while True:
            raw_header = recv_all(conn, 4)
            if raw_header:
                msg_len = struct.unpack('!I', raw_header)[0]
                raw_data = recv_all(conn, msg_len)
                msg_obj = json.loads(raw_data.decode('utf-8'))
                try:
                    if msg_obj.get('type') == 'secure_msg':
                        decrypted = connection_kem.decrypt_aes_gcm(
                            session_keys['encryption_key'],
                            msg_obj['data']
                        )
                        self.log(f"[{client_id}] 收到加密訊息: {decrypted}")
                        # 廣播訊息
                        self.broadcast(decrypted, client_id)
                except Exception as e:
                    self.log(f"[{client_id}] 訊息處理錯誤: {e}")
                    break
            else:
                break
        
        # Cleanup properly after loop breaks
        self._remove_client(client_id)
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