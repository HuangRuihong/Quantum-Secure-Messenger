import sys
import os
import queue
import threading
import tkinter as tk
from tkinter import scrolledtext

# 自動路徑引導
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
core_logic_path = os.path.join(project_root, "Core_Logic (核心邏輯)")

if core_logic_path not in sys.path:
    sys.path.append(core_logic_path)

from client import ClientBackend

# --- 配色方案 (Cipher/Cyberpunk) ---
COLOR_BG = "#0f0f0f"        # 極深灰背景
COLOR_FG = "#00ff41"        # 駭客綠
COLOR_ACCENT = "#00b8ff"    # 賽博藍
COLOR_BUTTON = "#1a1a1a"    # 按鈕深色
COLOR_ERROR = "#ff3333"     # 錯誤紅
COLOR_SUCCESS = "#00ff41"   # 成功綠

FONT_MONO = ("Consolas", 10)
FONT_HEADER = ("Consolas", 14, "bold")

class ClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("量子安全終端 Q-TERM v2.2")
        self.root.geometry("700x550")
        self.root.configure(bg=COLOR_BG)
        
        self.backend = ClientBackend(callback_log=self.enqueue_log, on_message=self.on_incoming_message)
        self.msg_queue = queue.Queue()
        
        self.setup_ui()
        self.periodic_check()

    def setup_ui(self):
        # 1. 頂部狀態列
        top_frame = tk.Frame(self.root, bg=COLOR_BG)
        top_frame.pack(fill=tk.X, padx=15, pady=15)
        
        self.lbl_title = tk.Label(top_frame, text="[ QUANTUM SECURE LINK ]", font=FONT_HEADER, bg=COLOR_BG, fg=COLOR_ACCENT)
        self.lbl_title.pack(side=tk.LEFT)
        
        self.lbl_status = tk.Label(top_frame, text="● DISCONNECTED", font=("Consolas", 10, "bold"), bg=COLOR_BG, fg=COLOR_ERROR)
        self.lbl_status.pack(side=tk.RIGHT)

        # 2. 控制面板 (功能區)
        control_frame = tk.Frame(self.root, bg=COLOR_BG, highlightbackground=COLOR_ACCENT, highlightthickness=1)
        control_frame.pack(fill=tk.X, padx=15, pady=5)
        
        btn_style = {"bg": COLOR_BUTTON, "fg": COLOR_ACCENT, "font": ("Consolas", 10, "bold"), 
                    "activebackground": COLOR_ACCENT, "activeforeground": COLOR_BG, "relief": tk.FLAT, "padx": 15, "pady": 5}
        
        self.btn_connect = tk.Button(control_frame, text="> ESTABLISH SECURE LINK", command=self.do_secure_connect, **btn_style)
        self.btn_connect.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.X, expand=True)
        
        # 3. 終端機日誌
        log_frame = tk.Frame(self.root, bg=COLOR_BG)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)
        
        tk.Label(log_frame, text="SECURE LOG:", font=FONT_MONO, bg=COLOR_BG, fg="#666666").pack(anchor=tk.W)
        
        self.log_area = scrolledtext.ScrolledText(log_frame, height=15, bg="#000000", fg=COLOR_FG, font=FONT_MONO, insertbackground=COLOR_FG, relief=tk.FLAT, bd=2)
        self.log_area.pack(fill=tk.BOTH, expand=True)
        self.log("System Initialized... Ready.")

        # 4. 訊息輸入區
        input_frame = tk.Frame(self.root, bg=COLOR_BG)
        input_frame.pack(fill=tk.X, padx=15, pady=15)
        
        tk.Label(input_frame, text="MSG >", font=FONT_HEADER, bg=COLOR_BG, fg=COLOR_ACCENT).pack(side=tk.LEFT, padx=(0, 10))
        
        self.entry_msg = tk.Entry(input_frame, font=FONT_MONO, bg="#222222", fg="#ffffff", insertbackground="#ffffff", relief=tk.FLAT)
        self.entry_msg.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.entry_msg.bind('<Return>', lambda e: self.send_message())
        
        self.btn_send = tk.Button(input_frame, text="SEND", command=self.send_message, state=tk.DISABLED, **btn_style)
        self.btn_send.pack(side=tk.RIGHT, padx=(10, 0))

    def periodic_check(self):
        try:
            while True:
                msg = self.msg_queue.get_nowait()
                self.log(msg)
        except queue.Empty:
            pass
        self.root.after(100, self.periodic_check)

    # --- Actions ---

    def do_secure_connect(self):
        self.btn_connect.config(state=tk.DISABLED, text="CONNECTING...")
        self.log("[SYSTEM] Initiating Sequence: Connect -> Handshake")
        
        def _thread():
            try:
                if not self.backend.connect():
                    self.log("[ERROR] TCP Connection Failed. Is Server Running?")
                    self._reset_connect_btn()
                    self._update_status("CONN FAILED", COLOR_ERROR)
                    return

                self.log("[SYSTEM] Starting Kyber-768 Handshake...")
                if not self.backend.perform_handshake():
                    self.log("[ERROR] Handshake Failed.")
                    self._reset_connect_btn()
                    self._update_status("HANDSHAKE FAILED", COLOR_ERROR)
                    self.backend.close()
                    return

                self.backend.start_listening()
                self.root.after(0, lambda: self._update_status("SECURE LINK ESTABLISHED", COLOR_SUCCESS))
                self.root.after(0, lambda: self.btn_send.config(state=tk.NORMAL, bg=COLOR_BUTTON))
                self.root.after(0, lambda: self.btn_connect.config(text="> CONNECTION ACTIVE", bg="#004400"))
                self.log(f"[SUCCESS] Secure Channel Established.")
                
            except Exception as e:
                self.log(f"[CRITICAL ERROR] {e}")
                self._reset_connect_btn()
        
        threading.Thread(target=_thread, daemon=True).start()

    def send_message(self):
        msg = self.entry_msg.get()
        if not msg: return
        
        self.entry_msg.delete(0, tk.END)
        
        def _thread():
            if not self.backend.send_secure_message(msg):
                self.log("[ERROR] Send Failed")
        
        threading.Thread(target=_thread).start()
    
    def log(self, message):
        def _append():
            self.log_area.insert(tk.END, f"{message}\n")
            self.log_area.see(tk.END) # Auto-scroll to bottom
        self.root.after(0, _append)

    def on_close(self):
        self.backend.close()
        self.root.destroy()

    # --- Helpers ---

    def enqueue_log(self, message):
        self.msg_queue.put(message)

    def on_incoming_message(self, message):
        self.enqueue_log(message)

    def _reset_connect_btn(self):
        self.root.after(0, lambda: self.btn_connect.config(state=tk.NORMAL, text="> ESTABLISH SECURE LINK"))

    def _update_status(self, text, color):
        self.lbl_status.config(text=f"● {text}", fg=color)

if __name__ == "__main__":
    root = tk.Tk()
    app = ClientGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()