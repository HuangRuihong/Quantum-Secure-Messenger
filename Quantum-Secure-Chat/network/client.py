# client.py
# =============================================================================
# 模組名稱：量子安全聊天客戶端 (Client Backend)
# 負責功能：連接伺服器、發起量子安全握手、執行訊息加密發送與非同步接收
# 架構層次：客戶端通訊層 (水管)
# =============================================================================

import sys
import os
import socket
import json
import time
import threading
import struct
from typing import Optional, Callable

# 自動路徑引導：確保能正確載入同級或上級目錄的核心邏輯
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
core_logic_path = os.path.join(project_root, "core")
if core_logic_path not in sys.path:
    sys.path.append(core_logic_path)

from innovative_hybrid_kem import InnovativeHybridKEM

class ClientBackend:
    """
    客戶端後端引擎：控管與伺服器的加密連線生命週期
    """
    def __init__(self, callback_log: Optional[Callable[[str], None]] = None, on_message: Optional[Callable[[str], None]] = None):
        # 初始化專屬的密碼學引擎
        self.kem = InnovativeHybridKEM()
        
        self.client_socket: Optional[socket.socket] = None
        self.session_keys = None
        self.connected = False
        
        # 回呼函式 (UI 溝通介介面)
        self.log_callback = callback_log if callback_log else print
        self.on_message_callback = on_message
        self.listen_thread: Optional[threading.Thread] = None

    def log(self, message: str):
        self.log_callback(f"[客戶端] {message}")

    # =============================================================================
    # 【核心邏輯 1：連線建立與握手】
    # =============================================================================

    def connect(self, host: str = '127.0.0.1', port: int = 8888) -> bool:
        """[階段一：發起 TCP 連線]"""
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(5.0) 
            self.client_socket.connect((host, port))
            self.connected = True
            self.log(f" 成功建立連線 ({host}:{port})")
            return True
        except Exception as e:
            self.log(f" 連線失敗: {e}")
            return False

    def perform_handshake(self) -> bool:
        """
        [階段二與階段四：執行混合量子安全握手協定]
        協定流程：
        1. Client 發送：[Ver(1B)] + [Len(4B)] + [Handshake Data]
        2. Client 接收：[Len(4B)] + [Server Response JSON]
        """
        if not self.client_socket: return False
        
        try:
            # 1. 生成客戶端專屬的臨時 PQC 金鑰對 (Kyber-768)

            self.log(" 正在生成金鑰對...")
            pqc_pk, pqc_sk = self.kem.client_pqc_keygen()
            
            # 2. 封裝握手包並送出
            handshake_data = self.kem.generate_handshake_package(pqc_pk)
            self.client_socket.sendall(b'\x02') # 協定版本 v2
            self.client_socket.sendall(struct.pack('!I', len(handshake_data)))
            self.client_socket.sendall(handshake_data)
            self.log(" 連線請求已送出，等待回應...")

            # 3. 接收伺服器回傳的密文
            self.client_socket.settimeout(10.0)
            
            # 先讀 4 字節長度標頭
            header = self._recv_exact(4)
            if not header:
                self.log(" 讀取回應長度失敗")
                return False
            resp_len = struct.unpack('!I', header)[0]
            
            # 精確讀取 JSON 內容
            resp_raw = self._recv_exact(resp_len)
            if not resp_raw: return False

            response = json.loads(resp_raw.decode('utf-8'))
            
            if response.get('success'):
                # 4. 解開 PQC 密文 (Decapsulation)
                server_ecc_pub = bytes.fromhex(response['server_ecc_pub'])
                pqc_ciphertext = bytes.fromhex(response['pqc_ciphertext'])
                pqc_shared = self.kem.client_pqc_decapsulate(pqc_ciphertext, pqc_sk)
                
                # 5. 衍生最終對稱金鑰 (金鑰同步完成)
                my_pkg = self.kem.parse_handshake_package(handshake_data)
                self.session_keys = self.kem.derive_final_key(
                    server_ecc_pub, pqc_shared, my_pkg['salt'], my_pkg['timestamp']
                )
                self.log(" ✅ 連線完成！會話已建立。")
                return True
            else:
                self.log(f" 連線被拒絕: {response.get('error')}")
                return False

        except Exception as e:
            self.log(f" 連線執行錯誤: {e}")
            return False

    # =============================================================================
    # 【核心邏輯 2：安全通訊】
    # =============================================================================

    def send_secure_message(self, message: str) -> bool:
        """[階段五：訊息加密傳送]"""
        if not self.session_keys:
            self.log(" 尚未建立會話，無法傳送")
            return False
            
        try:
            # 使用 Session Key 進行 AES-GCM 加密
            encrypted = self.kem.encrypt_aes_gcm(self.session_keys['encryption_key'], message)
            payload = {
                "type": "secure_msg",
                "data": encrypted,
                "timestamp": time.time()
            }
            
            # 打包成標準格式 [Len (4B)] + [JSON]
            data = json.dumps(payload).encode('utf-8')
            header = struct.pack('!I', len(data))
            self.client_socket.sendall(header + data)
            return True
        except Exception as e:
            self.log(f" 傳送失敗: {e}")
            return False

    def start_listening(self):
        """啟動非同步背景監聽，確保在聊天時能隨時接收訊息"""
        if not self.connected or not self.client_socket: return
        # 重要修正：在進入背景監聽前，將 Socket 設回阻塞模式 (無逾時)
        # 避免因一段時間沒有訊息而導致 `recv` 拋出逾時異常並中斷連線
        self.client_socket.settimeout(None) 
        self.listen_thread = threading.Thread(target=self._listen_loop, daemon=True)
        self.listen_thread.start()

    def _listen_loop(self):
        """核心監聽迴圈：不斷接收伺服器轉發的加密訊息"""
        while self.connected:
            try:
                # 1. 讀取封包標頭
                header = self._recv_exact(4)
                if not header: break
                msg_len = struct.unpack('!I', header)[0]
                
                # 2. 精確讀取加密 Payload
                raw_data = self._recv_exact(msg_len)
                if not raw_data: break
                
                msg_obj = json.loads(raw_data.decode('utf-8'))
                if msg_obj.get('type') == 'secure_msg':
                    # 解密伺服器轉發的訊息 (使用同步後的會話金鑰)
                    decrypted = self.kem.decrypt_aes_gcm(self.session_keys['encryption_key'], msg_obj['data'])
                    
                    if self.on_message_callback:
                        self.on_message_callback(decrypted)
                    else:
                        self.log(f" [收到廣播] {decrypted}")

            except Exception as e:
                self.log(f"[錯誤] 監聽迴圈發生異常: {e}")
                # 若是解密失敗，通常是因為金鑰不匹配或資料損毀
                if "decrypt" in str(e).lower():
                    self.log("[警告] 訊息解密失敗，請檢查金鑰同步狀態。")
                break
        self.connected = False
        self.log(" 與伺服器的加密連線已中斷")

    def _recv_exact(self, n: int) -> Optional[bytes]:
        """精確接收輔助函式"""
        data = b''
        while len(data) < n:
            try:
                packet = self.client_socket.recv(n - len(data))
                if not packet:
                    # socket.recv 回傳空位元組表示對端已關閉連線
                    return None
                data += packet
            except Exception as e:
                # 這裡會捕捉到 timeout 或其他 socket 錯誤
                self.log(f"[系統] Socket 接收異常: {e}")
                return None
        return data

    def close(self):
        self.connected = False
        if self.client_socket:
            try: self.client_socket.close()
            except: pass
        self.client_socket = None

if __name__ == "__main__":
    # 簡易測試用互動終端
    client = ClientBackend()
    if client.connect():
        if client.perform_handshake():
            client.start_listening()
            print("--- 進入量子安全聊天室 (輸入 q 退出) ---")
            while True:
                msg = input("")
                if msg.lower() == 'q': break
                client.send_secure_message(msg)
    client.close()