# C:\PJ02\network\gui_server.py
import tkinter as tk
from tkinter import scrolledtext
import threading
import socket
import json
import traceback
from innovative_hybrid_kem import InnovativeHybridKEM

class ServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ AI 時代安全閘道器 - 監控中心")
        self.root.geometry("900x600")
        self.root.configure(bg="#121212")
        
        # 初始化核心 (注意：每個連線其實應該有獨立的 KEM 實例，這裡簡化為單一實例演示)
        self.server_kem = InnovativeHybridKEM()
        self.session_keys = None
        
        self.setup_ui()
        self.start_server()

    def setup_ui(self):
        # 標題區
        tk.Label(self.root, text="QUANTUM-SECURE GATEWAY MONITOR", font=("Consolas", 16, "bold"), fg="#00ff00", bg="#121212").pack(pady=10)
        
        # 狀態顯示
        self.status_bar = tk.Label(self.root, text="狀態: 等待客戶端握手...", font=("微軟正黑體", 10), fg="white", bg="#333333")
        self.status_bar.pack(fill=tk.X, padx=10)

        # 流量監控區
        tk.Label(self.root, text="[ 即時流量與加密分析 ]", font=("微軟正黑體", 10), fg="#888888", bg="#121212").pack(anchor="w", padx=10, pady=(10,0))
        self.log_area = scrolledtext.ScrolledText(self.root, width=100, height=25, bg="#000000", fg="#00ff00", font=("Consolas", 10))
        self.log_area.pack(padx=10, pady=5)

    def log(self, msg, color="#00ff00"):
        # 跨執行緒更新 UI
        def _update():
            self.log_area.insert(tk.END, f"{msg}\n")
            self.log_area.see(tk.END)
        self.root.after(0, _update)

    def start_server(self):
        threading.Thread(target=self.run_socket_server, daemon=True).start()

    def run_socket_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('127.0.0.1', 8888))
        server.listen(5)
        self.log(">>> 系統啟動。正在 127.0.0.1:8888 執行混合 KEM 監聽...")

        while True:
            try:
                conn, addr = server.accept()
                self.log(f"\n[連線] 來自 {addr}")
                
                # 1. 接收 Header
                version = conn.recv(1)
                header = conn.recv(4)
                if not header:
                    conn.close()
                    continue
                
                expected_size = int.from_bytes(header, 'big')
                self.log(f"收到握手請求，大小: {expected_size} bytes")

                # 2. 接收 Payload
                data = b""
                while len(data) < expected_size:
                    packet = conn.recv(min(4096, expected_size - len(data)))
                    if not packet: break
                    data += packet

                self.log(">>> 正在執行多路徑解密與 KDF 衍生...")
                
                # 3. [核心] 解析握手包
                package = self.server_kem.parse_handshake_package(data)
                
                # 4. [核心] 同步 Session ID
                self.server_kem.session_id = package['session_id']
                self.log(f"同步 SessionID: {package['session_id']}")

                # 5. [核心] PQC 解封裝
                pqc_shared = self.server_kem.decapsulate_pqc(package['pqc_ciphertext_effective'])
                
                # 6. [核心] 衍生金鑰
                self.session_keys = self.server_kem.derive_final_key(
                    package['ecc_pub'],
                    pqc_shared,
                    package['salt'],
                    package['timestamp']
                )

                key_preview = self.session_keys['session_key'].hex()[:16]
                self.log(f"✅ 握手成功！金鑰協商完成", "#00ffff")
                self.log(f"🔑 Session Key: {key_preview}...", "#ffff00")
                
                # 更新狀態列
                self.root.after(0, lambda: self.status_bar.config(text=f"狀態: 已連接 {addr} | 安全等級: 256-bit PQC | Key: {key_preview}...", fg="#00ff00"))

                # 7. 回覆 Client (包含 Server ECC 公鑰)
                response = {
                    "success": True, 
                    "server_ecc_pub": self.server_kem.ecc_public_bytes.hex(),
                    "session_id": self.server_kem.session_id
                }
                conn.sendall(json.dumps(response).encode())

                # ==========================================
                # 8. [修正] 真實 AES-GCM 解密迴圈 (替換掉原本的模擬迴圈)
                # ==========================================
                while True:
                    msg_data = conn.recv(4096)
                    if not msg_data: break
                    
                    try:
                        # 接收 JSON
                        payload_obj = json.loads(msg_data.decode())
                        
                        # 檢查是否為安全訊息格式 (Client 送來的是 secure_msg)
                        if payload_obj.get("type") == "secure_msg":
                            enc_data = payload_obj["data"]
                            
                            self.log(f"\n[攔截密文] Cipher: {enc_data['ciphertext'][:32]}...")
                            self.log(f"[攔截 IV] {enc_data['iv']}")
                            self.log(f"[攔截 Tag] {enc_data['tag']}")
                            
                            # 執行真實解密
                            decrypted_text = self.server_kem.decrypt_aes_gcm(
                                self.session_keys['encryption_key'], 
                                enc_data
                            )
                            
                            self.log(f"🔓 解密成功: {decrypted_text}", "#ffffff")
                        else:
                            self.log(f"收到未知格式: {payload_obj}")

                    except Exception as e:
                        self.log(f"❌ 解密失敗或數據損毀: {e}", "red")
                        traceback.print_exc()

            except Exception as e:
                self.log(f"❌ 連線錯誤: {e}", "red")
                traceback.print_exc()
            finally:
                try:
                    conn.close()
                except:
                    pass
                self.root.after(0, lambda: self.status_bar.config(text="狀態: 等待客戶端握手...", fg="white"))

if __name__ == "__main__":
    root = tk.Tk()
    app = ServerGUI(root)
    root.mainloop()