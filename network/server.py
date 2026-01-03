import socket

def start_gateway():
    # 建立 TCP Socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 允許地址重用，避免重啟 Server 時顯示位址已在使用
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    server.bind(('127.0.0.1', 8888))
    server.listen(5)
    print("🛡️ 安全閘道器已啟動，監聽中...")

    while True:
        conn, addr = server.accept()
        print(f"\n[+] 來自 {addr} 的新連線")
        try:
            # 1. 接收 4 Bytes 的「長度標頭」
            header = conn.recv(4)
            if not header:
                continue

            # 2. 將 Bytes 轉回整數
            expected_size = int.from_bytes(header, byteorder='big')

            # --- 💡 工程判斷：輸入驗證 ---
            MAX_KEY_SIZE = 10000 
            if expected_size > MAX_KEY_SIZE or expected_size <= 0:
                print(f"❌ 警告：收到異常長度請求 ({expected_size} bytes)，中斷連線防止 DoS。")
                conn.close()
                continue 

            print(f"📦 預期金鑰長度: {expected_size} bytes")

            # 3. 循環接收資料，確保完整性
            data = b""
            while len(data) < expected_size:
                # 剩餘多少收多少
                packet = conn.recv(expected_size - len(data))
                if not packet:
                    break
                data += packet
            
            if len(data) == expected_size:
                print(f" 金鑰接收成功！實際大小: {len(data)} bytes")
                # TODO: 下個月在此接入 HybridKEM.derive_final_key()
            else:
                print(f" 接收不完整：預期 {expected_size}，實際得到 {len(data)}")

        except Exception as e:
            print(f" 處理連線時發生錯誤: {e}")
        finally:
            conn.close()
            print(f"[-] 連線已關閉")

if __name__ == "__main__":
    start_gateway()