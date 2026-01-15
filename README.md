# 🛡️ 量子安全混合加密通訊系統 (Quantum-Secure Hybrid Communication System)

![License](https://img.shields.io/badge/license-MIT-blue.svg) ![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg) ![Security](https://img.shields.io/badge/security-Post--Quantum-green.svg)

> **專案核心目標**：實作一個抗量子電腦攻擊的混合密鑰封裝機制 (Hybrid KEM)，結合傳統橢圓曲線 (X25519) 與 NIST 標準化後量子密碼學 (ML-KEM/Kyber-768) 的優勢，建立具備高度前向保密性 (PFS) 與抗量子攻擊能力的資安通訊系統。

---

## ✨ 核心特色 (Key Features)

*   **真正的後量子安全性 (Real PQC)**: 整合 `kyber-py` 實作 **Kyber-768** 演算法，而非模擬數據。
*   **混合密鑰交換 (Hybrid Key Exchange)**: 同時結合 **X25519 (ECC)** 與 **Kyber-768**，即使其中一種演算法被破解，通訊仍然安全。
*   **賽博龐克風格介面 (Cyberpunk UI)**: 
    *   **Client**: 駭客終端機風格 (Dark/Neon Green)。
    *   **Server**: 資安戰情中心風格 (Command Center Dashboard)。
*   **模組化架構 (Modular Architecture)**: 
    *   **Backend**: `ClientBackend` / `ServerBackend` 封裝核心邏輯。
    *   **Frontend**: `GUI` 與 `Console` 版本共享同一套後端代碼。
*   **AES-256-GCM 加密**: 使用協商出的高強度金鑰進行數據傳輸，確保機密性與完整性。

---

## 🏗 系統架構 (System Architecture)

本系統採用 **Client-Server 架構**，核心邏輯完全分離：

### 📁 檔案結構 (`network/`)

*   **核心層 (Core)**:
    *   `innovative_hybrid_kem.py`: 密碼學核心。處理 Kyber-768 封裝/解封裝、X25519 交換、HKDF 金鑰衍生。
*   **後端層 (Backend)**:
    *   `server.py`: 定義 `ServerBackend` 類別。處理多執行緒連線、監聽、握手邏輯。
    *   `client.py`: 定義 `ClientBackend` 類別。處理連線建立、握手請求、訊息發送。
*   **前端層 (Frontend - GUI)**:
    *   `gui_server.py`: 伺服器端圖形介面 (戰情中心風格)。
    *   `gui_client.py`: 用戶端圖形介面 (駭客終端風格)。

---

## 🛠 技術堆疊 (Tech Stack)

| 組件 | 技術選擇 | 實作細節 |
| --- | --- | --- |
| **PQC (後量子)** | **Kyber-768** | 使用 `kyber-py` 套件。FIPS 203 標準候選算法。提供 1184 bytes 公鑰 與 1088 bytes 密文。 |
| **ECC (傳統)** | **X25519** | 使用 `cryptography` 套件。提供高效的 ECDH 交換，作為混合加密的傳統防線。 |
| **KDF (金鑰衍生)** | **Hybrid HKDF** | 自定義 KDF，輸入參數包含：Client/Server ECC PubKeys, Kyber Shared Secret, Salt, Timestamp。 |
| **加密傳輸** | **AES-256-GCM** | GCM 模式提供機密性 (Confidentiality) 與完整性 (Integrity/Tag)。 |
| **UI 框架** | **Tkinter** | Python 內建 GUI 庫，經高度客製化樣式 (Custom Styling)。 |

---

## 🔄 握手協議流程 (Handshake Protocol)

1.  **Client KeyGen**: Client 生成 Kyber-768 金鑰對 `(pk, sk)`。
2.  **Client Hello**: Client 發送 `pk` (1184 bytes) 給 Server。
3.  **Server Encaps**: 
    *   Server 接收 `pk`。
    *   Server 使用 `pk` 進行封裝，生成 `ciphertext` (1088 bytes) 與 `shared_secret`。
    *   Server 生成自己的 ECC KeyPair。
4.  **Key Derivation (Server)**: Server 結合 ECC Shared Secret 與 Kyber Shared Secret 算出 Session Key。
5.  **Server Hello**: Server 回傳 `ciphertext` + `server_ecc_pk` 給 Client。
6.  **Client Decaps**: 
    *   Client 使用 `sk` 解開 `ciphertext` 取得 `shared_secret`。
    *   Client 結合 ECC Shared Secret 算出 Session Key。
7.  **Secure Channel**: 雙方金鑰一致，建立 AES-GCM 安全通道。

---

## 🚀 快速開始 (Quick Start)

### 1. 環境準備

*   Python 3.10+
*   安裝依賴:
    ```bash
    pip install cryptography kyber-py
    ```

### 2. 啟動系統

**啟動伺服器 (Server - Command Center):**
```bash
python network/gui_server.py
```

**啟動用戶端 (Client - Cyberpunk Terminal):**
```bash
python network/gui_client.py
```

### 3. 操作指引

1.  **連接**: 在 Client 點擊 `> INIT CONNECTION`。
2.  **握手**: 點擊 `> EXECUTE HANDSHAKE`。觀察 Server log 出現握手成功訊息。
3.  **通訊**: 在 Client 輸入訊息並發送，Server 將解密並顯示於儀表板。

---

## ⚠️ 免責聲明 (Disclaimer)

本專案旨在演示後量子密碼學在實際通訊系統中的整合應用。儘管使用了真實的密碼學演算法，但在生產環境使用前仍需經過嚴格的代碼審計與側信道攻擊測試。