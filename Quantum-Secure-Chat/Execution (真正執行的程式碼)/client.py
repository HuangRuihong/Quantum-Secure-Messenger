import sys
import os
import socket
import json
import time
import threading
import struct

from typing import Optional, Callable

# 自動路徑引導
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
core_logic_path = os.path.join(project_root, "Core_Logic (核心邏輯)")

if core_logic_path not in sys.path:
    sys.path.append(core_logic_path)

from innovative_hybrid_kem import InnovativeHybridKEM

class ClientBackend:
    def __init__(self, callback_log: Optional[Callable[[str], None]] = None, on_message: Optional[Callable[[str], None]] = None):
        self.kem = InnovativeHybridKEM()
        self.client_socket: Optional[socket.socket] = None
        self.session_keys = None
        self.connected = False
        self.log_callback = callback_log if callback_log else print
        self.on_message_callback = on_message
        self.listen_thread: Optional[threading.Thread] = None

    # --- Public Methods ---

    def log(self, message: str):
        self.log_callback(message)

    def connect(self, host: str = '127.0.0.1', port: int = 8888) -> bool:
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(5.0) 
            self.client_socket.connect((host, port))
            self.connected = True
            self.log(f" 連接成功! ({host}:{port})")
            return True
        except Exception as e:
            self.log(f" 連接失敗: {e}")
            return False

    def perform_handshake(self) -> bool:
        """
        Handshake Protocol:
        1. Client Send: [Ver (1B)] + [Len (4B)] + [Handshake Data]
        2. Client Recv: [Response JSON] (Currently no length prefix from server for handshake response)
        """
        if not self.client_socket:
            return False
        
        try:
            # 1. 生成 KeyPair
            self.log(" 生成 PQC 金鑰對 (Kyber-768)...")
            pqc_pk, pqc_sk = self.kem.client_pqc_keygen()
            
            # 2. 發送
            handshake_data = self.kem.generate_handshake_package(pqc_pk)
            
            self.client_socket.sendall(b'\x02') # Version
            self.client_socket.sendall(len(handshake_data).to_bytes(4, 'big'))
            self.client_socket.sendall(handshake_data)
            self.log(" 握手包已發送")

            # 3. 接收回應 (Blocking wait)
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
            return False

    def start_listening(self):
        """啟動非同步訊息監聽"""
        if not self.connected or not self.client_socket:
            return
        
        self.listen_thread = threading.Thread(target=self._listen_loop, daemon=True)
        self.listen_thread.start()

    def send_secure_message(self, message: str) -> bool:
        if not self.session_keys:
            self.log(" 尚未建立安全會話")
            return False
            
        try:
            encrypted = self.kem.encrypt_aes_gcm(self.session_keys['encryption_key'], message)
            payload = {
                "type": "secure_msg",
                "data": encrypted,
                "timestamp": time.time()
            }
            
            # Framing: [Length (4B)] + [JSON Data]
            data = json.dumps(payload).encode('utf-8')
            header = struct.pack('!I', len(data))
            self.client_socket.sendall(header + data)
            return True
            
        except Exception as e:
            self.log(f" 發送失敗: {e}")
            return False

    def close(self):
        self.connected = False
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
        self.client_socket = None

    # --- Private Methods ---

    def _listen_loop(self):
        """
        Main Loop Protocol:
        [Length (4B)] + [JSON Data]
        """
        while self.connected:
            try:
                self.client_socket.settimeout(None) 
                
                # 1. Read Header
                raw_header = self._recv_exact(4)
                if not raw_header:
                    self.log(" 與伺服器連接中斷")
                    self.connected = False
                    break
                
                msg_len = struct.unpack('!I', raw_header)[0]
                
                # 2. Read Body
                raw_data = self._recv_exact(msg_len)
                if not raw_data:
                    break
                
                try:
                    msg_obj = json.loads(raw_data.decode('utf-8'))
                    if msg_obj.get('type') == 'secure_msg':
                        encrypted = msg_obj['data']
                        decrypted = self.kem.decrypt_aes_gcm(self.session_keys['encryption_key'], encrypted)
                        
                        if self.on_message_callback:
                            self.on_message_callback(decrypted)
                        else:
                            self.log(f" [收到] {decrypted}")

                except json.JSONDecodeError:
                    pass
                except Exception as e:
                    self.log(f" 訊息處理錯誤: {e}")

            except OSError:
                break
            except Exception as e:
                self.log(f" 監聽錯誤: {e}")
                break

    def _recv_exact(self, n: int) -> Optional[bytes]:
        """Helper to receive exactly n bytes"""
        data = b''
        while len(data) < n:
            try:
                packet = self.client_socket.recv(n - len(data))
                if not packet: return None
                data += packet
            except:
                return None
        return data

# Console Runner
def run_console_client():
    def on_msg(text):
        print(f"\n{text}")
    
    client = ClientBackend(on_message=on_msg)
    if client.connect():
        if client.perform_handshake():
            client.start_listening()
            print("--- 聊天開始 (輸入 q 退出) ---")
            while True:
                msg = input("")
                if msg.lower() == 'q': break
                client.send_secure_message(msg)
    client.close()

if __name__ == "__main__":
    run_console_client()