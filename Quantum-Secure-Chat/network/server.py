# server.py
# =============================================================================
# 模組名稱：量子安全聊天伺服器 (Server Backend)
# 負責功能：TCP 連線管理、多執行緒併發處理、握手協定控管與訊息廣播
# 架構層次：網路傳輸層 (水管)
# =============================================================================

import socket
import threading
import json
import time
import sys
import os
import struct
from typing import Dict, Optional, Callable

# 自動偵測核心邏輯目錄並加入搜尋路徑
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
core_logic_path = os.path.join(project_root, "core")
if core_logic_path not in sys.path:
    sys.path.append(core_logic_path)

from innovative_hybrid_kem import InnovativeHybridKEM, PacketFormatError, KeyGenerationError

class ServerBackend:
    """
    伺服器後端引擎：管理所有連入客戶端的生命週期
    """
    def __init__(self, host: str = '0.0.0.0', port: int = 8888, log_callback: Optional[Callable[[str], None]] = None):
        self.host = host
        self.port = port
        self.server_socket: Optional[socket.socket] = None
        self.running = False
        
        # 伺服器自身的密碼學引擎
        self.kem = InnovativeHybridKEM()
        
        # 連線管理資料結構 (執行緒安全)
        self._lock = threading.Lock()
        self.active_connections: Dict[str, threading.Thread] = {}
        self.connected_clients: Dict[str, dict] = {} # {client_id: {'conn': conn, 'keys': keys, 'addr': addr}}
        
        self.log_callback = log_callback if log_callback else print
        self.client_event_callback: Optional[Callable[[str, str, str], None]] = None
        self.client_counter = 0

    def log(self, message: str):
        self.log_callback(f"[伺服器] {message}")

    # =============================================================================
    # 【核心邏輯 1：連線生命週期管理】
    # =============================================================================

    def start_server(self):
        """啟動監聽並進入接受連線迴圈"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(10)
        self.running = True
        self.log(f" 服務已啟動於 {self.host}:{self.port}")
        
        # 在獨立執行緒執行的 Accept 迴圈
        accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        accept_thread.start()

    def _accept_loop(self):
        """接收新連線的無限迴圈"""
        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                
                # 分配臨時客戶端 ID
                self.client_counter += 1
                client_id = f"Client-{self.client_counter:02d} ({addr[0]}:{addr[1]})"

                # 為每個連線開啟獨立執行緒處理
                t = threading.Thread(target=self._handle_client, args=(conn, addr, client_id), daemon=True)
                self.active_connections[client_id] = t
                t.start()
            except Exception as e:
                if self.running: self.log(f"接受連線異常: {e}")

    def _remove_client(self, client_id):
        """清理已斷開的連線資源"""
        with self._lock:
            if client_id in self.connected_clients:
                try:
                    self.connected_clients[client_id]['conn'].close()
                    self.log(f"已關閉與 [{client_id}] 的 Socket 連線")
                except Exception as e:
                    self.log(f"關閉 [{client_id}] 連線時發生錯誤: {e}")
                
                del self.connected_clients[client_id]
                self.log(f"[{client_id}] 已離線")
                if self.client_event_callback: self.client_event_callback("leave", client_id, "")

    # =============================================================================
    # 【核心邏輯 2：單一連線處理程序 (大腦)】
    # =============================================================================

    def _handle_client(self, conn: socket.socket, addr, client_id):
        """
        處理客戶端的關鍵流程：[1. 協定握手] -> [2. 持續通訊]
        """
        # 每一個連線都有一個獨立的引擎實例處理本次握手
        connection_kem = InnovativeHybridKEM() 
        session_keys = None
        
        try:
            # --- [階段一：接收握手請求] ---
            # 1. 讀取版本 (1B)
            version = conn.recv(1)
            if not version: return
            
            # 2. 讀取長度標頭 (4B)
            length_bytes = self._recv_exact(conn, 4)
            if not length_bytes: return
            length = struct.unpack('!I', length_bytes)[0]
            
            # 3. 讀取完整握手包內容
            handshake_data = self._recv_exact(conn, length)
            if not handshake_data: return
                
            # --- [階段二：執行量子安全協商] ---
            # 4. 解析 PQC 與 ECC 公鑰
            package = connection_kem.parse_handshake_package(handshake_data)
            
            # 5. 執行伺服器端 PQC 封裝 (產生 Ciphertext 與共享秘密)
            pqc_ciphertext, pqc_shared = connection_kem.server_pqc_encapsulate(package['pqc_public_key'])
            
            # 6. 衍生最終通訊金鑰 (KDF)
            session_keys = connection_kem.derive_final_key(
                package['ecc_pub'], pqc_shared, package['salt'], package['timestamp']
            )
            
            # 7. 註冊握手成功的連線 (使用鎖確保安全)
            with self._lock:
                self.connected_clients[client_id] = {
                    'conn': conn,
                    'keys': session_keys,
                    'addr': addr
                }
            self.log(f"[{client_id}] 🤝 連線成功！歡迎光臨")
            if self.client_event_callback: self.client_event_callback("join", client_id, "")
            
            # --- [階段三：回傳握手回應] ---
            response = {
                'success': True,
                'server_ecc_pub': connection_kem.ecc_public_bytes.hex(),
                'pqc_ciphertext': pqc_ciphertext.hex(),
                'session_id': connection_kem.session_id,
                'timestamp': time.time()
            }
            # 封裝回應資料 [Len (4B)] + [JSON]
            resp_data = json.dumps(response).encode('utf-8')
            resp_header = struct.pack('!I', len(resp_data))
            conn.sendall(resp_header + resp_data)

        except Exception as e:
            self.log(f"[{client_id}] 連線失敗: {e}")
            conn.close()
            return

        # --- [階段四：進入加密訊息無限迴圈] ---
        while True:
            try:
                # 讀取訊息長度 (4B)
                raw_header = self._recv_exact(conn, 4)
                if not raw_header: break
                
                msg_len = struct.unpack('!I', raw_header)[0]
                raw_data = self._recv_exact(conn, msg_len)
                if not raw_data: break
                
                # 解析並解密訊息
                msg_obj = json.loads(raw_data.decode('utf-8'))
                if msg_obj.get('type') == 'secure_msg':
                    # 使用握手取得的 Key 進行 AES-GCM 解密
                    decrypted = connection_kem.decrypt_aes_gcm(
                        session_keys['encryption_key'],
                        msg_obj['data']
                    )
                    self.log(f"[{client_id}] 收到訊息: {decrypted}")
                    
                    # 進行廣播給其他使用者
                    self.broadcast(decrypted, client_id)
            except Exception as e:
                self.log(f"[{client_id}] 訊息異常: {e}")
                break
        
        self._remove_client(client_id)

    # =============================================================================
    # 【核心邏輯 3：訊息分發與輔助函式】
    # =============================================================================

    def broadcast(self, message: str, sender_id: str):
        """將經過解密確認的明文，重新加密後分發給所有在線客戶端"""
        to_remove = []
        
        # 使用鎖保護字典讀取
        with self._lock:
            clients = list(self.connected_clients.items())
            
        for client_id, data in clients:
            try:
                target_conn = data['conn']
                target_keys = data['keys']
                
                # 重新針對目標客戶端的 Key 進行 AES 加密
                full_msg = f"[{sender_id}] {message}"
                encrypted = self.kem.encrypt_aes_gcm(target_keys['encryption_key'], full_msg)
                
                payload = {
                    "type": "secure_msg",
                    "data": encrypted,
                    "sender": sender_id,
                    "timestamp": time.time()
                }
                data_bytes = json.dumps(payload).encode('utf-8')
                header = struct.pack('!I', len(data_bytes))
                
                # 發送加密封包
                target_conn.sendall(header + data_bytes)
                # self.log(f"已轉發廣播至 [{client_id}]") # 偵錯用，流量大時可註解
            except Exception as e:
                self.log(f"廣播至 [{client_id}] 失敗: {e}")
                to_remove.append(client_id)
        
        for cid in to_remove:
            self._remove_client(cid)

    def _recv_exact(self, conn, n):
        """輔助函式：確保接收到完整的 n 個位元組"""
        res = b''
        while len(res) < n:
            try:
                chunk = conn.recv(n - len(res))
                if not chunk:
                    # 對端已關閉連線
                    return None
                res += chunk
            except Exception as e:
                self.log(f"接收實體資料時發生 Socket 異常: {e}")
                return None
        return res

    def stop(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()

if __name__ == "__main__":
    # 簡易主控台執行模式
    server = ServerBackend()
    server.start_server()
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        server.stop()