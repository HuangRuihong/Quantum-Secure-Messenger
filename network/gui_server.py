
import tkinter as tk
from tkinter import scrolledtext, font
import threading
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
        
        # 狀態指標
        self.lbl_server_status = tk.Label(status_frame, text="SERVER: STARTING...", font=("Consolas", 11, "bold"), bg=COLOR_BG, fg="orange")
        self.lbl_server_status.pack(side=tk.LEFT)
        
        self.lbl_protocol = tk.Label(status_frame, text="PROTOCOL: KYBER-768 + X25519", font=("Consolas", 9), bg=COLOR_BG, fg="#555555")
        self.lbl_protocol.pack(side=tk.RIGHT)

        # 3. 實時日誌監控
        log_frame = tk.Frame(self.root, bg=COLOR_BG)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        tk.Label(log_frame, text="> TRAFFIC INTERCEPTION LOG:", font=FONT_MONO, bg=COLOR_BG, fg=COLOR_PRIMARY).pack(anchor=tk.W)
        
        self.log_area = scrolledtext.ScrolledText(log_frame, height=20, bg="#000000", fg=COLOR_FG, 
                                                 font=FONT_MONO, insertbackground=COLOR_PRIMARY, relief=tk.FLAT, bd=1)
        self.log_area.pack(fill=tk.BOTH, expand=True)

    def log(self, message):
        def _append():
            prefix = "[LOG]"
            if "收到" in message: prefix = "[IN ]"
            elif "發送" in message: prefix = "[OUT]"
            elif "握手" in message: prefix = "[SEC]"
            
            self.log_area.insert(tk.END, f"{prefix} {message}\n")
            self.log_area.see(tk.END)
        self.root.after(0, _append)

    def start_server(self):
        try:
            self.backend.start_server()
            self.lbl_server_status.config(text="● SYSTEM ONLINE (LISTENING)", fg=COLOR_PRIMARY)
        except Exception as e:
            self.log(f"啟動失敗: {e}")
            self.lbl_server_status.config(text="● SYSTEM FAILURE", fg=COLOR_ACCENT)

    def on_close(self):
        self.backend.stop()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = ServerGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()