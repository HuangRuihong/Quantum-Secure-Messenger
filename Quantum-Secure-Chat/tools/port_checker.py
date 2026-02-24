import socket
import subprocess
import sys
import os
import re

def check_port_availability(port):
    """
    檢查指定 Port 是否可用 (嘗試 Bind)
    回傳: (is_available, message)
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # 嘗試綁定 Port，如果成功則代表未被佔用
        sock.bind(('0.0.0.0', port))
        sock.close()
        return True, f"Port {port} 目前【可用】 (沒有被佔用)。"
    except OSError:
        return False, f"Port {port} 目前【已被佔用】！"

def find_pid_by_port(port):
    """
    使用 netstat 尋找佔用 port 的 PID
    """
    try:
        output = subprocess.check_output("netstat -ano", shell=True).decode(errors='ignore')
        lines = output.split('\n')
        
        # 尋找包含 :port 的行
        pattern = re.compile(f":{port}\\s+.*\\s+(\\d+)\\s*$")
        
        for line in lines:
            if f":{port}" in line:
                match = pattern.search(line.strip())
                if match:
                    pid = match.group(1)
                    return pid, line.strip()
        return None, None
    except Exception as e:
        return None, f"查詢失敗: {e}"

def get_listening_ports():
    """
    獲取所有正在監聽 (LISTENING) 的 Port 資訊列表
    回傳: List[Dict]
    """
    ports_info = []
    try:
        output = subprocess.check_output("netstat -ano", shell=True).decode(errors='ignore')
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            if "LISTENING" in line:
                parts = line.split()
                if len(parts) >= 5:
                    # parts: [Proto, Local Address, Foreign Address, State, PID]
                    # Local Address usually is 0.0.0.0:8888 or [::]:8888
                    local_addr = parts[1]
                    pid = parts[4]
                    
                    ports_info.append({
                        'proto': parts[0],
                        'local_addr': local_addr,
                        'state': parts[3],
                        'pid': pid,
                        'raw': line
                    })
    except Exception as e:
        print(f"執行 netstat 失敗: {e}")
        
    return ports_info

def kill_process(pid):
    """
    終止指定 PID 的程序
    """
    try:
        print(f"正在終止 PID {pid} ...")
        # /F 強制終止
        cmd = f"taskkill /F /PID {pid}"
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode(errors='ignore')
        print(f"成功: {output.strip()}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"失敗: {e.output.decode(errors='ignore').strip()}")
        return False
    except Exception as e:
        print(f"發生錯誤: {e}")
        return False

def show_ports_and_interact():
    """
    顯示 Port 列表並提供互動選項
    """
    while True:
        ports = get_listening_ports()
        
        print(f"\n{'='*60}")
        print(f"{'協議':<6} {'本地地址':<25} {'狀態':<12} {'PID':<8}")
        print(f"{'='*60}")
        
        for p in ports:
            print(f"{p['proto']:<6} {p['local_addr']:<25} {p['state']:<12} {p['pid']:<8}")
            
        print(f"{'='*60}")
        print(f"共找到 {len(ports)} 個監聽中的服務。")
        
        print("\n[功能選項]")
        print("直接輸入 PID 並按 Enter 可強制關閉該程序")
        print("輸入 r 刷新列表")
        print("輸入 q 返回主選單")
        
        choice = input("\n請輸入: ").strip().lower()
        
        if choice == 'q':
            break
        elif choice == 'r':
            continue
        elif choice.isdigit():
            pid_to_kill = choice
            # 確認該 PID 是否在列表中 (選用，但為了安全最好檢查)
            target = next((p for p in ports if p['pid'] == pid_to_kill), None)
            
            if target:
                confirm = input(f"確定要關閉 PID {pid_to_kill} (位於 {target['local_addr']}) 嗎? (y/n): ")
                if confirm.lower() == 'y':
                    kill_process(pid_to_kill)
                    input("按 Enter 繼續...")
            else:
                # 允許關閉不在列表中的 PID，但在這裡給出警告
                confirm = input(f"PID {pid_to_kill} 不在上述監聽列表中，仍要在關閉嗎? (y/n): ")
                if confirm.lower() == 'y':
                    kill_process(pid_to_kill)
                    input("按 Enter 繼續...")
        else:
            print("無效輸入。")

def main():
    while True:
        print("\n=== Port 檢測與管理工具 ===")
        print("1. 檢查特定 Port 狀態")
        print("2. 列出所有監聽中的 Port (並可選擇關閉)")
        print("3. 查詢佔用 Port 的程序 (PID)")
        print("0. 離開")
        
        choice = input("\n請選擇功能 (0-3): ").strip()
        
        if choice == '1':
            try:
                p_str = input("請輸入要檢查的 Port (例如 8888): ")
                port = int(p_str)
                available, msg = check_port_availability(port)
                print(f"\n檢測結果: {msg}")
                
                if not available:
                    pid, line = find_pid_by_port(port)
                    if pid:
                        print(f"佔用詳情: {line}")
                        action = input("是否要立即關閉此程序? (y/n): ")
                        if action.lower() == 'y':
                            kill_process(pid)
                    else:
                        print("無法獲取 PID 資訊。")
                        
            except ValueError:
                print("輸入錯誤，請輸入有效的數字。")
                
        elif choice == '2':
            show_ports_and_interact()
            
        elif choice == '3':
            try:
                p_str = input("請輸入要查詢的 Port: ")
                port = int(p_str)
                pid, line = find_pid_by_port(port)
                if pid:
                    print(f"\n找到佔用程序 PID: {pid}")
                    print(f"完整資訊: {line}")
                    action = input("是否要立即關閉此程序? (y/n): ")
                    if action.lower() == 'y':
                        kill_process(pid)
                else:
                    print(f"\n未發現 Port {port} 被佔用，或該 Port 目前無活動。")
            except ValueError:
                print("輸入錯誤。")

        elif choice == '0':
            print("再見！")
            break
        else:
            print("無效的選擇，請重試。")

if __name__ == "__main__":
    main()
