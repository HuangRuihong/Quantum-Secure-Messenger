import sys
import os
import threading
import tkinter as tk
from tkinter import scrolledtext

# 自動路徑引導
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
network_path = os.path.join(project_root, "network")

if network_path not in sys.path:
    sys.path.append(network_path)

from server import ServerBackend

# --- 配色方案 (Cipher/Cyberpunk) ---
COLOR_BG = "#0a0a0a"         # 近黑背景
COLOR_FG = "#bcbcbc"         # 灰白文字
COLOR_ACCENT = "#ff0055"     # 警示紅/粉
COLOR_PRIMARY = "#00ccff"    # 科技藍

FONT_MONO = ("Consolas", 9)
FONT_HEADER = ("Consolas", 14, "bold")

class ServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("量子安全中繼站 Q-HUB v2.0")
        self.root.geometry("800x600")
        self.root.configure(bg=COLOR_BG)
        
        self.backend = ServerBackend(log_callback=self.log)
        self.backend.client_event_callback = self.on_client_event
        self.clients_list = [] # List of client_ids
        
        self.setup_ui()
        self.start_server()

    def setup_ui(self):
        # 1. 指揮中心標題
        header_frame = tk.Frame(self.root, bg="#111111", highlightbackground=COLOR_PRIMARY, highlightthickness=1)
        header_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(header_frame, text="[ SECURITY OPERATIONS CENTER ]", font=FONT_HEADER, bg="#111111", fg=COLOR_PRIMARY).pack(pady=10)
        
        # 2. 狀態儀表板
        status_frame = tk.Frame(self.root, bg=COLOR_BG)
        status_frame.pack(fill=tk.X, padx=15, pady=5)
        
        self.lbl_server_status = tk.Label(status_frame, text="SERVER: STARTING...", font=("Consolas", 11, "bold"), bg=COLOR_BG, fg="orange")
        self.lbl_server_status.pack(side=tk.LEFT)
        
        self.lbl_protocol = tk.Label(status_frame, text="PROTOCOL: KYBER-768 + X25519", font=("Consolas", 9), bg=COLOR_BG, fg="#555555")
        self.lbl_protocol.pack(side=tk.RIGHT)

        # 3. 廣播控制台
        broadcast_frame = tk.Frame(self.root, bg=COLOR_BG, highlightbackground=COLOR_PRIMARY, highlightthickness=1)
        broadcast_frame.pack(fill=tk.X, padx=15, pady=10)
        
        tk.Label(broadcast_frame, text="BROADCAST >", font=("Consolas", 10, "bold"), bg=COLOR_BG, fg=COLOR_PRIMARY).pack(side=tk.LEFT, padx=10)
        
        self.entry_broadcast = tk.Entry(broadcast_frame, font=FONT_MONO, bg="#1a1a1a", fg="#ffffff", insertbackground="#ffffff", relief=tk.FLAT)
        self.entry_broadcast.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)
        self.entry_broadcast.bind('<Return>', lambda e: self.do_broadcast())
        
        btn_bc = tk.Button(broadcast_frame, text="TRANSMIT", command=self.do_broadcast, bg="#004466", fg="#ffffff", font=("Consolas", 9, "bold"), relief=tk.FLAT)
        btn_bc.pack(side=tk.RIGHT, padx=10, pady=5)

        # 4. 主內容區: 左側日誌 + 右側客戶端列表
        content_frame = tk.Frame(self.root, bg=COLOR_BG)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 左側日誌
        log_frame = tk.Frame(content_frame, bg=COLOR_BG)
        log_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        tk.Label(log_frame, text="> TRAFFIC INTERCEPTION LOG:", font=FONT_MONO, bg=COLOR_BG, fg=COLOR_PRIMARY).pack(anchor=tk.W)
        
        self.log_area = scrolledtext.ScrolledText(log_frame, bg="#000000", fg=COLOR_FG, 
                                                font=FONT_MONO, insertbackground=COLOR_PRIMARY, relief=tk.FLAT, bd=1)
        self.log_area.pack(fill=tk.BOTH, expand=True)

        # 右側客戶端列表
        list_frame = tk.Frame(content_frame, bg=COLOR_BG, width=200)
        list_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(5, 0))
        
        tk.Label(list_frame, text="> CONNECTED NODES:", font=FONT_MONO, bg=COLOR_BG, fg="#00ff41").pack(anchor=tk.W)
        
        self.client_listbox = tk.Listbox(list_frame, bg="#111111", fg="#00ff41", font=FONT_MONO, 
                                        relief=tk.FLAT, bd=1, highlightthickness=1, highlightbackground="#00ff41",
                                        width=25)
        self.client_listbox.pack(fill=tk.BOTH, expand=True)

    # --- Actions ---

    def start_server(self):
        try:
            self.backend.start_server()
            self.lbl_server_status.config(text="● SYSTEM ONLINE (LISTENING)", fg=COLOR_PRIMARY)
        except Exception as e:
            self.log(f"啟動失敗: {e}")
            self.lbl_server_status.config(text="● SYSTEM FAILURE", fg=COLOR_ACCENT)

    def do_broadcast(self):
        msg = self.entry_broadcast.get()
        if not msg: return
        
        self.backend.broadcast(msg, "SERVER")
        self.entry_broadcast.delete(0, tk.END)
        self.log(f"[BROADCAST] Sent: {msg}")

    def on_close(self):
        self.backend.stop()
        self.root.destroy()

    # --- Helpers ---

    def log(self, message):
        def _append():
            prefix = "[LOG]"
            if "收到" in message or "IN" in message: prefix = "[IN ]"
            elif "發送" in message or "OUT" in message: prefix = "[OUT]"
            elif "握手" in message or "SEC" in message: prefix = "[SEC]"
            elif "錯誤" in message or "失敗" in message: prefix = "[ERR]"
            
            self.log_area.insert(tk.END, f"{prefix} {message}\n")
            self.log_area.see(tk.END)
        self.root.after(0, _append)

    def on_client_event(self, event_type, client_id, info):
        def _update():
            if event_type == "join":
                if client_id not in self.clients_list:
                    self.clients_list.append(client_id)
                    self.client_listbox.insert(tk.END, client_id)
            elif event_type == "leave":
                if client_id in self.clients_list:
                    idx = self.clients_list.index(client_id)
                    self.clients_list.remove(client_id)
                    self.client_listbox.delete(idx)
        self.root.after(0, _update)

if __name__ == "__main__":
    root = tk.Tk()
    app = ServerGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()