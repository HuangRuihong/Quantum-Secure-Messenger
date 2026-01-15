# 🛡️ 量子安全混合加密通訊系統 (Quantum-Secure Hybrid Communication System)

### 混合密鑰封裝機制 (Hybrid KEM + AES-GCM)

> **專案核心目標**：實作一個抗量子電腦攻擊的混合密鑰封裝機制 (Hybrid KEM)，結合傳統橢圓曲線 (ECC) 與後量子密碼學 (PQC) 的優勢，建立具備前向保密性 (PFS) 與完整性驗證 (Integrity) 的安全通訊通道。

---

## 🏗 專案架構

本系統採用 **Client-Server 架構**，所有核心程式碼位於 `network/` 目錄下。

### 檔案結構

*   **`network/innovative_hybrid_kem.py`**: 核心加密模組。
    *   負責所有密碼學運算 (ECC 金鑰生成, PQC 封裝/解封裝, 分層 KDF, AES-GCM)。
    *   定義握手包格式 `!32s Q 32s 32s 32s 1184s`。
*   **`network/server.py`**: 後端伺服器邏輯。
    *   處理 TCP Socket 連線，多執行緒 (Threading) 架構。
    *   負責解析握手包並維護連線狀態。
*   **`network/gui_client.py`**: 用戶端圖形介面。
    *   提供視覺化操作：執行握手、發送加密訊息。
*   **`network/gui_server.py`**: 伺服器端圖形介面。
    *   提供即時流量監控與解密分析儀表板。
*   **`network/client.py`**: 用戶端核心邏輯 (被 GUI 引用)。

---

## 🛠 核心技術堆疊

| 組件 | 技術選擇 | 實作細節 |
| --- | --- | --- |
| **PQC (後量子)** | **Kyber-768 (模擬)** | 目前使用隨機數模擬封裝機制 (Mock Implementation)，保留標準介面以便未來替換為 `liboqs`。 |
| **ECC (傳統)** | **X25519** | 使用 `cryptography` 套件。提供高效的 ECDH 交換，作為混合加密的傳統防線。 |
| **KDF (金鑰衍生)** | **HKDF-SHA3** | 自定義 5 層衍生函數，結合 Salt 與 Context，產出 Session Key, Encryption Key, Auth Key。 |
| **加密傳輸** | **AES-256-GCM** | 使用協商出的金鑰進行對稱加密。GCM 模式提供機密性與完整性 (Tag 驗證)。 |
| **通訊協定** | **Custom TCP** | 封包結構：`Version (1B) + Length (4B) + Payload`。 |

---

## 🔄 運作流程

### 1. 混合密鑰握手 (Handshake)

1.  **Client 初始化**: 生成臨時 X25519 金鑰對與 PQC 共享秘密。
2.  **打包請求**: 
    *   將 Salt, Timestamp, Proof, SessionID, ECC Public Key, PQC Ciphertext 依據 `struct` 格式打包。
    *   發送至 Server。
3.  **Server 處理**:
    *   解析封包，驗證格式與長度。
    *   執行 PQC 解封裝 (取得 Shared Secret)。
    *   執行 X25519 (取得 ECC Shared Secret)。
    *   KDF 衍生最終 Session Keys。
4.  **回應**: Server 回傳其 ECC Public Key。
5.  **Client 完成**: Client 收到 Server Pub Key 後算出相同 Session Keys，握手完成。

### 2. 安全訊息傳輸

*   **加密**: 使用 `AES-256-GCM`，每次訊息生成隨機 12-byte IV。
*   **傳輸**: JSON 格式 `{ "type": "secure_msg", "data": { "iv": "...", "ciphertext": "...", "tag": "..." } }`。
*   **解密**: 接收方驗證 Tag 並解密，若失敗則丟棄。

---

## 🚀 快速開始

### 環境需求

*   Python 3.10+
*   安裝依賴套件:
    ```bash
    pip install cryptography
    ```

### 啟動方式

請開啟兩個終端機視窗，分別執行 Server 與 Client。

**1. 啟動伺服器 (Server)**

```bash
# 在專案根目錄 (c:\PJ02) 執行
python network/gui_server.py
# 或若無 GUI 需求可執行 console 版本
python network/server.py
```

**2. 啟動用戶端 (Client)**

```bash
# 在專案根目錄 (c:\PJ02) 執行
python network/gui_client.py
```

### 操作步驟

1.  在 Client 視窗點擊 **"1. 執行混合金鑰握手"**。
2.  觀察 Server Console 顯示 "金鑰協商完成"。
3.  在 Client 輸入訊息，點擊 **"2. 加密並發送"**。
4.  Server 將收到密文並自動解密顯示。

---

> **Note**: 本專案為概念驗證 (PoC)，PQC 部分目前為模擬實作。