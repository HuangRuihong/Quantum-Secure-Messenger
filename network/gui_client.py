# C:\PJ02\network\gui_client.py
import tkinter as tk
from tkinter import messagebox
import socket
import json
import secrets
from innovative_hybrid_kem import InnovativeHybridKEM

class ClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🚀 量子安全通訊終端")
        self.root.geometry("600x500")
        self.root.configure(bg="#2c3e50")
        
        self.client_socket = None
        self.kem = InnovativeHybridKEM() # 初始化核心
        self.session_keys = None
        
        self.setup_ui()

    def setup_ui(self):
        tk.Label(self.root, text="SECURE MESSENGER (Hybrid KEM)", font=("Arial", 14, "bold"), fg="white", bg="#2c3e50").pack(pady=10)

        # 握手按鈕
        self.btn_handshake = tk.Button(self.root, text="1. 執行混合金鑰握手 (ECC+PQC)", command=self.perform_handshake, bg="#e67e22", fg="white", width=40)
        self.btn_handshake.pack(pady=10)

        # 訊息輸入
        tk.Label(self.root, text="輸入訊息:", fg="white", bg="#2c3e50").pack()
        self.entry_msg = tk.Entry(self.root, width=50, state=tk.DISABLED)
        self.entry_msg.pack(pady=5)

        # 發送按鈕
        self.btn_send = tk.Button(self.root, text="2. 加密並發送", command=self.send_encrypted, state=tk.DISABLED, bg="#27ae60", fg="white", width=40)
        self.btn_send.pack(pady=10)

        # 顯示區
        self.display = tk.Text(self.root, width=70, height=15, bg="#34495e", fg="#ecf0f1", font=("Consolas", 9))
        self.display.pack(padx=10, pady=10)

    def log(self, msg):
        self.display.insert(tk.END, f"{msg}\n")
        self.display.see(tk.END)

    def perform_handshake(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect(('127.0.0.1', 8888))
            self.log(">>> 連接伺服器成功...")

            # 1. [核心] 生成 PQC 共享秘密與密文
            pqc_shared, pqc_ciphertext = self.kem.encapsulate_pqc()
            self.log(">>> 本地 PQC 秘密與密文已生成")

            # 2. [核心] 打包握手包
            handshake_data = self.kem.generate_handshake_package(pqc_ciphertext)
            
            # 3. 發送
            self.client_socket.sendall(b'\x02') # Version
            self.client_socket.sendall(len(handshake_data).to_bytes(4, 'big'))
            self.client_socket.sendall(handshake_data)
            self.log(f">>> 握手包已發送 ({len(handshake_data)} bytes)")
            
            # 4. 接收回應
            resp_raw = self.client_socket.recv(4096)
            response = json.loads(resp_raw.decode())
            
            if response['success']:
                self.log(">>> 收到 Server 回應 (含 ECC 公鑰)")
                server_ecc_pub = bytes.fromhex(response['server_ecc_pub'])

                # 5. [核心] 衍生最終金鑰
                # 需解析回剛剛自己送出的包以取得 Salt/Timestamp
                my_pkg = self.kem.parse_handshake_package(handshake_data)
                
                self.session_keys = self.kem.derive_final_key(
                    server_ecc_pub,
                    pqc_shared,
                    my_pkg['salt'],
                    my_pkg['timestamp']
                )

                key_preview = self.session_keys['session_key'].hex()[:16]
                self.log(f"\n✅ 握手成功！")
                self.log(f"🔑 Session Key: {key_preview}...")
                self.log(f"(請比對 Server 端顯示的 Key，應完全一致)\n")
                
                self.btn_handshake.config(state=tk.DISABLED)
                self.entry_msg.config(state=tk.NORMAL)
                self.btn_send.config(state=tk.NORMAL)
            else:
                self.log("❌ 握手失敗")

        except Exception as e:
            messagebox.showerror("連線錯誤", str(e))
            if self.client_socket:
                self.client_socket.close()

    
    def send_encrypted(self):
        text = self.entry_msg.get()
        if not text: return
        
        try:
            # 1. 獲取加密金鑰 (從握手結果中)
            # 注意：確保握手已完成且 self.session_keys 存在
            enc_key = self.session_keys['encryption_key']
            
            # 2. 執行真實加密
            # 這會返回一個包含 iv, ciphertext, tag 的字典
            encrypted_data = self.kem.encrypt_aes_gcm(enc_key, text)
            
            # 3. 組裝傳輸封包
            payload = {
                "type": "secure_msg",
                "data": encrypted_data
            }
            
            self.client_socket.sendall(json.dumps(payload).encode())
            
            # log 顯示 (只顯示部分密文，假裝很神秘)
            short_cipher = encrypted_data['ciphertext'][:16] + "..."
            self.log(f"[發送] {text} (加密: {short_cipher})")
            self.entry_msg.delete(0, tk.END)
            
        except Exception as e:
            self.log(f"❌ 加密/發送失敗: {e}")
            print(e)

if __name__ == "__main__":
    root = tk.Tk()
    app = ClientGUI(root)
    root.mainloop()