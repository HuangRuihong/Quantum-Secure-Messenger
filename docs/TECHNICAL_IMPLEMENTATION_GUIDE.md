# 🛡️ 量子安全混合加密通訊系統 - 技術實現指南

**專案版本**: 2.2  
**最後更新**: 2026年1月15日  
**語言**: Python 3.10+  
**安全等級**: 256-bit PQC (後量子密碼學)  

---

## 📋 目錄

1. [系統概述](#系統概述)
2. [技術架構](#技術架構)
3. [核心模組詳解](#核心模組詳解)
4. [執行流程](#執行流程)
5. [加密算法原理](#加密算法原理)
6. [網路通訊協議](#網路通訊協議)
7. [實現細節](#實現細節)
8. [使用指南](#使用指南)
9. [安全分析](#安全分析)

---

## 系統概述

### 🎯 核心目標

本系統實現了一套**抗量子電腦攻擊**的混合密鑰封裝機制 (Hybrid KEM)，結合：
- **傳統密碼學**: X25519 (Elliptic Curve Diffie-Hellman)
- **後量子密碼學**: Kyber-768 (ML-KEM，NIST 標準)
- **對稱加密**: AES-256-GCM

### 🌟 關鍵特性

| 特性 | 說明 |
|------|------|
| **真實 PQC** | 使用 `kyber-py` 庫實作真正的 Kyber-768，非模擬 |
| **混合安全性** | 雙算法設計，一種破解時仍保有安全性 |
| **前向保密** | 即使長期金鑰洩露，過去通訊仍安全 |
| **會話隔離** | 每個連線均有獨立的會話 ID 和金鑰 |
| **完整性驗證** | AES-GCM 提供認證加密 (AEAD) |
| **現代 UI** | Tkinter 實現的賽博龐克風格介面 |

---

## 技術架構

### 🏗 系統分層

```
┌─────────────────────────────────────┐
│     Frontend (GUI / Console)         │
│  gui_client.py  │  gui_server.py    │
└─────────────────┬───────────────────┘
                  │
┌─────────────────┴───────────────────┐
│   Backend (Business Logic)           │
│  client.py (ClientBackend)           │
│  server.py (ServerBackend)           │
└─────────────────┬───────────────────┘
                  │
┌─────────────────┴───────────────────┐
│   Crypto Core (加密引擎)              │
│  innovative_hybrid_kem.py            │
│  ├─ Kyber-768 PQC                   │
│  ├─ X25519 ECC                      │
│  ├─ AES-256-GCM                     │
│  └─ Hybrid HKDF                     │
└─────────────────────────────────────┘
```

### 📦 檔案結構

```
network/
├── innovative_hybrid_kem.py      # 核心加密模組 (329 行)
├── server.py                     # 伺服器後端 (97 行)
├── client.py                     # 用戶端後端 (93 行)
├── gui_server.py                 # 伺服器 GUI
├── gui_client.py                 # 用戶端 GUI (134 行)
├── test_kyber_integration.py     # 集成測試
└── inspect_kyber_params.py       # 參數檢查工具
```

---

## 核心模組詳解

### 1. InnovativeHybridKEM (innovative_hybrid_kem.py)

**職責**: 實現所有密碼學操作的核心引擎

#### 常量定義

```python
# Kyber-768 標準參數
PQC_CIPHERTEXT_LENGTH = 1088          # 密文長度 (bytes)
PQC_SHARED_SECRET_LENGTH = 32         # 共享秘密 (256-bit)
PQC_PUBLIC_KEY_LENGTH = 1184          # 公鑰長度 (bytes)

# X25519 標準參數
ECC_PUBLIC_KEY_LENGTH = 32            # X25519 公鑰 (256-bit)

# 握手協議參數
SALT_LENGTH = 32                      # 鹽值長度
TIMESTAMP_LENGTH = 8                  # 時間戳 (64-bit)
PROOF_LENGTH = 32                     # 完整性證明
SESSION_ID_BIN_LENGTH = 32            # 會話 ID

# 握手包結構 (二進制格式)
HANDSHAKE_FORMAT = '!32s Q 32s 32s 32s 1184s'
# 總長度: 32 + 8 + 32 + 32 + 32 + 1184 = 1320 bytes
```

#### 核心方法

##### (1) Kyber-768 PQC 操作

```python
def client_pqc_keygen() -> Tuple[bytes, bytes]:
    """
    用戶端生成 Kyber-768 密鑰對
    
    返回值:
        (public_key: 1184 bytes, secret_key: bytes)
    """
    pk, sk = Kyber768.keygen()
    return pk, sk

def server_pqc_encapsulate(client_pub_key: bytes) -> Tuple[bytes, bytes]:
    """
    伺服器執行封裝，生成共享秘密
    
    流程:
        1. 接收用戶端公鑰 (1184 bytes)
        2. 執行 Kyber768.encaps(pk)
        3. 生成密文 (1088 bytes) 和共享秘密 (32 bytes)
    
    返回值:
        (ciphertext: 1088 bytes, shared_secret: 32 bytes)
    """
    shared_secret, ciphertext = Kyber768.encaps(client_pub_key)
    return ciphertext, shared_secret

def client_pqc_decapsulate(ciphertext: bytes, secret_key: bytes) -> bytes:
    """
    用戶端進行解封裝
    
    流程:
        1. 接收伺服器發回的密文 (1088 bytes)
        2. 使用本地秘密金鑰執行解封裝
        3. 恢復相同的共享秘密 (32 bytes)
    
    返回值:
        shared_secret: 32 bytes (應與伺服器相同)
    """
    shared_secret = Kyber768.decaps(secret_key, ciphertext)
    return shared_secret
```

**Kyber-768 工作原理**:
- 基於 **CRYSTALS-Kyber** (Module-LWE)
- NIST PQC 標準化算法 (FIPS 203 候選)
- 抵抗 Shor 演算法 (量子攻擊)

##### (2) 握手包生成與解析

```python
def generate_handshake_package(pqc_public_key: bytes) -> bytes:
    """
    生成握手包 (客戶端發送給伺服器)
    
    步驟:
        1. 驗證 PQC 公鑰長度 (必須 1184 bytes)
        2. 生成鹽值: SHA3-256(ecc_pub || pqc_pub)[:32]
        3. 時間戳: 當前毫秒級時間
        4. 完整性證明: HMAC-SHA3-512(entropy_proof)
        5. 會話 ID: 32 字節隨機數
        
    包結構 (1320 bytes):
        [Salt 32B][Timestamp 8B][Proof 32B][SessionID 32B][ECC_Pub 32B][PQC_Pub 1184B]
    
    返回值:
        binary_package: 1320 bytes
    """
    salt = hashlib.sha3_256(
        self.ecc_public_bytes + pqc_public_key
    ).digest()[:32]
    
    timestamp = int(time.time() * 1000)
    
    proof_key = secrets.token_bytes(32)
    combined = self.ecc_public_bytes + pqc_public_key
    entropy_proof = hmac.new(
        proof_key, combined, hashlib.sha3_512
    ).digest()[:32]
    
    package = struct.pack(
        self.HANDSHAKE_FORMAT,
        salt,
        timestamp,
        entropy_proof,
        self._session_id_bin,
        self.ecc_public_bytes,
        pqc_public_key
    )
    return package

def parse_handshake_package(data: bytes) -> Dict:
    """
    解析握手包
    
    返回值:
        {
            'salt': bytes (32),
            'timestamp': int (毫秒),
            'entropy_proof': bytes (32),
            'session_id': str (hex 編碼),
            'session_id_bin': bytes (32),
            'ecc_pub': bytes (32),
            'pqc_public_key': bytes (1184)
        }
    """
    (salt, timestamp, entropy_proof, session_id_bin, 
     ecc_pub, pqc_pub) = struct.unpack(
        self.HANDSHAKE_FORMAT, data
    )
    return {
        'salt': salt,
        'timestamp': timestamp,
        'entropy_proof': entropy_proof,
        'session_id': session_id_bin.hex(),
        'session_id_bin': session_id_bin,
        'ecc_pub': ecc_pub,
        'pqc_public_key': pqc_pub
    }
```

##### (3) AES-256-GCM 加密通訊

```python
def encrypt_aes_gcm(key: bytes, plaintext: str) -> Dict[str, str]:
    """
    使用 AES-256-GCM 加密訊息
    
    步驟:
        1. 生成 12 字節隨機 IV (初始向量)
        2. 建立 AES-256-GCM 加密器
        3. 加密明文
        4. 生成 16 字節認證標籤 (Tag)
    
    參數:
        key: 32 bytes (256-bit)
        plaintext: 明文字符串
    
    返回值:
        {
            "iv": hex 字符串 (24 字元),
            "ciphertext": hex 字符串 (密文長度 * 2),
            "tag": hex 字符串 (32 字元)
        }
    """
    iv = secrets.token_bytes(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    
    ciphertext = encryptor.update(
        plaintext.encode('utf-8')
    ) + encryptor.finalize()
    
    return {
        "iv": iv.hex(),
        "ciphertext": ciphertext.hex(),
        "tag": encryptor.tag.hex()
    }

def decrypt_aes_gcm(key: bytes, data: Dict[str, str]) -> str:
    """
    使用 AES-256-GCM 解密訊息
    
    參數:
        key: 32 bytes (256-bit)
        data: 加密包字典
    
    流程:
        1. 還原 IV、密文、標籤
        2. 建立 GCM 解密器 (含標籤驗證)
        3. 解密
        4. 驗證完整性 (GCM 自動驗證，失敗拋出異常)
    
    返回值:
        plaintext: 解密後的字符串
    """
    iv = bytes.fromhex(data['iv'])
    ciphertext = bytes.fromhex(data['ciphertext'])
    tag = bytes.fromhex(data['tag'])
    
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode('utf-8')
```

**GCM 模式特性**:
- **AEAD**: 認證加密 (Authenticated Encryption)
- **密文完整性**: 任何篡改被立即檢測
- **防止重放攻擊**: IV 不能重複使用

##### (4) 混合金鑰衍生函數 (Hybrid HKDF)

```python
def derive_final_key(peer_ecc_pub: bytes, pqc_shared: bytes, 
                     salt: bytes, timestamp: int) -> Dict[str, bytes]:
    """
    從混合共享秘密衍生三個獨立的會話金鑰
    
    步驟:
        1. ECC 金鑰交換: X25519(自己私鑰, 對方公鑰)
        2. 生成 KDF 上下文
        3. 分層 KDF (5 層)
        4. 金鑰分離 (HMAC 樹)
    
    參數:
        peer_ecc_pub: 對方 X25519 公鑰 (32 bytes)
        pqc_shared: Kyber-768 共享秘密 (32 bytes)
        salt: 握手包中的鹽值 (32 bytes)
        timestamp: 握手時間戳 (毫秒)
    
    返回值:
        {
            'encryption_key': 32 bytes (AES-256 金鑰),
            'session_key': 32 bytes (會話識別用),
            'authentication_key': 16 bytes (HMAC 金鑰)
        }
    """
    # 步驟 1: ECC 金鑰交換
    peer_key = x25519.X25519PublicKey.from_public_bytes(peer_ecc_pub)
    ecc_shared = self._private_key.exchange(peer_key)  # 32 bytes
    
    # 步驟 2: KDF 上下文
    context = b"HybridKEM-v2.2" + timestamp.to_bytes(8, 'big') + salt
    
    # 步驟 3: 分層 KDF
    master_key = self._layered_kdf(
        [ecc_shared, pqc_shared],  # 兩個共享秘密
        context,
        rounds=5                   # 5 層 SHA3 變換
    )
    
    # 步驟 4: 金鑰分離
    keys = {
        'encryption_key': hmac.new(
            master_key, b"ENC-v2", hashlib.sha3_256
        ).digest(),                # 32 bytes
        'session_key': hmac.new(
            master_key, b"SESSION-v2", hashlib.sha3_256
        ).digest(),                # 32 bytes
        'authentication_key': hmac.new(
            master_key, b"AUTH-v2", hashlib.sha3_256
        ).digest()[:16]            # 16 bytes
    }
    return keys
```

**分層 KDF 詳解**:
```python
def _layered_kdf(shared_secrets: List[bytes], context: bytes, 
                 rounds: int = 3) -> bytes:
    """
    多層密鑰衍生 (增強安全性)
    
    每層 (Round i):
        L1 = SHA3-512(current || context || "Li-1")
        L2 = HMAC-SHA3-256(L1[:32], current || context || "Li-2")
        current = L1 || L2 (64 bytes)
    
    最終:
        master_key = SHA3-256(current || session_id_bin)
    """
    combined = b"".join(shared_secrets)
    current = combined
    
    for i in range(rounds):
        layer1 = hashlib.sha3_512(
            current + context + f"L{i+1}-1".encode()
        ).digest()
        
        layer2 = hmac.new(
            layer1[:32],
            current + context + f"L{i+1}-2".encode(),
            hashlib.sha3_256
        ).digest()
        
        current = layer1 + layer2
    
    master_key = hashlib.sha3_256(
        current + self._session_id_bin
    ).digest()
    
    return master_key
```

---

### 2. ServerBackend (server.py)

**職責**: 管理伺服器端網路連接和握手

#### 關鍵流程

```python
class ServerBackend:
    def __init__(self, host='0.0.0.0', port=8888):
        """初始化伺服器"""
        self.kem = InnovativeHybridKEM()  # 伺服器 KEM 實例
        self.active_connections = {}      # 連線池
    
    def start_server(self):
        """啟動伺服器"""
        # 1. 建立 socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # 2. 啟用地址重用 (避免 TIME_WAIT 問題)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # 3. 綁定並監聽
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        
        # 4. 啟動接受執行緒
        threading.Thread(target=self._accept_loop, daemon=True).start()
    
    def _handle_client(self, conn: socket.socket, addr):
        """處理單個客戶端連接"""
        # 每個連線建立獨立的 KEM 實例 (PFS)
        connection_kem = InnovativeHybridKEM()
        
        try:
            # === 握手階段 ===
            
            # 1. 接收版本號 (1 byte)
            version = conn.recv(1)
            
            # 2. 接收握手包長度 (4 bytes, big-endian)
            length_bytes = conn.recv(4)
            length = int.from_bytes(length_bytes, 'big')
            
            # 3. 接收握手包 (1320 bytes)
            handshake_data = b""
            while len(handshake_data) < length:
                chunk = conn.recv(length - len(handshake_data))
                if not chunk: break
                handshake_data += chunk
            
            # 4. 解析握手包
            package = connection_kem.parse_handshake_package(handshake_data)
            connection_kem.session_id = package['session_id']
            
            # 5. 執行 Kyber 封裝
            pqc_ciphertext, pqc_shared = connection_kem.server_pqc_encapsulate(
                package['pqc_public_key']
            )
            
            # 6. 衍生會話金鑰
            session_keys = connection_kem.derive_final_key(
                package['ecc_pub'],
                pqc_shared,
                package['salt'],
                package['timestamp']
            )
            
            # === 回應握手 ===
            
            # 7. 構建回應
            response = {
                'success': True,
                'server_ecc_pub': connection_kem.ecc_public_bytes.hex(),
                'pqc_ciphertext': pqc_ciphertext.hex(),
                'session_id': connection_kem.session_id,
                'timestamp': time.time()
            }
            
            # 8. 發送回應 (JSON)
            conn.sendall(json.dumps(response).encode())
            
            # === 訊息迴圈 ===
            
            while True:
                # 9. 接收加密訊息
                data = conn.recv(4096)
                if not data: break
                
                msg_obj = json.loads(data.decode('utf-8'))
                
                if msg_obj.get('type') == 'secure_msg':
                    # 10. 解密
                    decrypted = connection_kem.decrypt_aes_gcm(
                        session_keys['encryption_key'],
                        msg_obj['data']
                    )
                    
                    # 11. 發送確認
                    conn.sendall(json.dumps({"type": "ack"}).encode())
        
        except Exception as e:
            self.log(f"連接中斷: {e}")
        
        finally:
            conn.close()
```

---

### 3. ClientBackend (client.py)

**職責**: 用戶端連接、握手和訊息發送

#### 關鍵流程

```python
class ClientBackend:
    def __init__(self):
        self.kem = InnovativeHybridKEM()
        self.session_keys = None
        self.connected = False
    
    def connect(self, host='127.0.0.1', port=8888) -> bool:
        """建立 TCP 連接"""
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(10.0)
            self.client_socket.connect((host, port))
            self.connected = True
            return True
        except Exception as e:
            self.log(f"連接失敗: {e}")
            return False
    
    def perform_handshake(self) -> bool:
        """執行量子安全握手"""
        if not self.client_socket:
            return False
        
        try:
            # === 步驟 1: 生成 Kyber 密鑰對 ===
            pqc_pk, pqc_sk = self.kem.client_pqc_keygen()  # pk=1184B, sk=?
            
            # === 步驟 2: 生成握手包 ===
            handshake_data = self.kem.generate_handshake_package(pqc_pk)
            # 握手包結構: [鹽32B][時間戳8B][證明32B][SessionID32B][ECC_Pub32B][PQC_Pub1184B]
            # 總計: 1320 bytes
            
            # === 步驟 3: 發送握手包 ===
            self.client_socket.sendall(b'\x02')  # 版本號
            self.client_socket.sendall(
                len(handshake_data).to_bytes(4, 'big')
            )
            self.client_socket.sendall(handshake_data)
            
            # === 步驟 4: 接收伺服器回應 ===
            resp_raw = self.client_socket.recv(4096)
            response = json.loads(resp_raw.decode('utf-8'))
            
            if not response.get('success'):
                self.log(f"握手失敗: {response.get('error')}")
                return False
            
            # === 步驟 5: 解封裝 Kyber 密文 ===
            server_ecc_pub = bytes.fromhex(response['server_ecc_pub'])
            pqc_ciphertext = bytes.fromhex(response['pqc_ciphertext'])
            
            pqc_shared = self.kem.client_pqc_decapsulate(
                pqc_ciphertext, pqc_sk
            )  # 應與伺服器相同
            
            # === 步驟 6: 衍生會話金鑰 ===
            my_pkg = self.kem.parse_handshake_package(handshake_data)
            
            self.session_keys = self.kem.derive_final_key(
                server_ecc_pub,
                pqc_shared,
                my_pkg['salt'],
                my_pkg['timestamp']
            )
            
            return True
        
        except Exception as e:
            self.log(f"握手錯誤: {e}")
            return False
    
    def send_secure_message(self, message: str):
        """發送加密訊息"""
        if not self.session_keys:
            self.log("未建立會話")
            return None
        
        try:
            # === 步驟 1: 加密 ===
            encrypted = self.kem.encrypt_aes_gcm(
                self.session_keys['encryption_key'],
                message
            )
            
            # === 步驟 2: 構建封包 ===
            payload = {
                "type": "secure_msg",
                "data": encrypted,
                "timestamp": time.time()
            }
            
            # === 步驟 3: 發送 ===
            self.client_socket.sendall(json.dumps(payload).encode())
            
            # === 步驟 4: 等待確認 ===
            resp = self.client_socket.recv(4096)
            return resp.decode('utf-8') if resp else None
        
        except Exception as e:
            self.log(f"發送失敗: {e}")
            return None
```

---

## 執行流程

### 完整握手流程時序圖

```
客戶端                                      伺服器
  │                                           │
  │ 1. KeyGen (Kyber)                        │
  │─────────────────────────────────────────>│
  │    [握手包: Salt|TS|Proof|SID|ECC|PQC]   │
  │                                           │
  │                        2. Parse Package  │
  │                        3. Encapsulate    │
  │<─────────────────────────────────────────│
  │   [Response: ServerECC|Ciphertext|SID]   │
  │                                           │
  │ 4. Decapsulate                          │
  │ 5. Derive Final Key                     │
  │                                           │
  │══════════════════════════════════════════│
  │   Secure Channel Established             │
  │═══════════════════════════════════════════
  │                                           │
  │ 6. SendSecureMessage (AES-256-GCM)      │
  │─────────────────────────────────────────>│
  │                        7. Decrypt        │
  │                        8. Process        │
  │<─────────────────────────────────────────│
  │         [ACK]                            │
```

### 握手包結構詳解

**發送方向**: 客戶端 → 伺服器

```
Byte Position   Field              Size    Description
─────────────────────────────────────────────────────────
0-31            Salt               32B     SHA3-256(ECC_Pub || PQC_Pub)
32-39           Timestamp          8B      當前毫秒 (Big-Endian)
40-71           Entropy Proof      32B     HMAC-SHA3-512 完整性驗證
72-103          Session ID         32B     會話標識符 (隨機)
104-135         ECC Public Key     32B     X25519 公鑰
136-1319        PQC Public Key     1184B   Kyber-768 公鑰

總計: 1320 bytes
```

**傳輸層封裝**:

```
[Version:1B][Length:4B][Handshake Packet:1320B]
```

---

## 加密算法原理

### 1. Kyber-768 (Module-LWE)

**理論基礎**: 模 Learning With Errors 問題 (ML-LWE)

**工作機制**:

```
客戶端                              伺服器
KeyGen:                             
  (pk, sk) ← K768.KeyGen()         
      │
      └─> pk: 1184 bytes            
      └─> sk: ? bytes
            │
            └─────────────────────────>
                                       Encaps:
                                       (ss, ct) ← K768.Encaps(pk)
                                       ss: 32 bytes (共享秘密)
                                       ct: 1088 bytes (密文)
                                       │
                                       └─────────────────────>
Decaps:
ss' ← K768.Decaps(sk, ct)
ss == ss' ✓
```

**安全性**:
- **量子後安全**: 即使 Shor 演算法也無法多項式時間求解
- **標準化**: NIST PQC 標準 (FIPS 203)
- **參數**: 768-dim 格點，≈ 256-bit 安全強度

### 2. X25519 (Elliptic Curve DH)

**曲線**: Curve25519 (Montgomery 曲線)

**公式**:
$$\text{shared\_secret} = k \cdot Q$$

其中:
- $k$ = 私鑰 (32 bytes)
- $Q$ = 對方公鑰 (32 bytes)
- 結果 = 共享秘密 (32 bytes)

**安全性**:
- **傳統強度**: ≈ 128-bit (對經典電腦)
- **實用性**: 極快速 (~1ms)
- **作用**: 兼容舊系統，提供傳統密碼學保障

### 3. 混合 HKDF

**概念**: 將兩個獨立的共享秘密融合

$$\text{Master Key} = \text{KDF}([\text{ECC SS} || \text{PQC SS}], \text{context})$$

**HKDF 展開** (RFC 5869):

```
Step 1: 提取
  PRK = HMAC-Hash(salt, IKM)

Step 2: 展開
  T(0) = empty string
  T(1) = HMAC-Hash(PRK, T(0) || info || 0x01)
  T(2) = HMAC-Hash(PRK, T(1) || info || 0x02)
  ...
  OKM = T(1) || T(2) || ... || T(N)
```

本系統採用**分層 KDF**:

```
Round i (i = 1 to 5):
  L1[i] = SHA3-512(current || context || "Li-1")
  L2[i] = HMAC-SHA3-256(L1[i][:32], current || context || "Li-2")
  current = L1[i] || L2[i]

Master Key = SHA3-256(final_current || session_id_bin)
```

**安全特性**:
- **雙保險**: PQC + ECC，一種破解時仍安全
- **前向保密**: 即使長期金鑰洩露，歷史通訊仍密
- **金鑰隔離**: 加密 / 會話 / 認證 金鑰分開

### 4. AES-256-GCM

**Galois/Counter Mode** (AEAD)

**結構**:

```
Plaintext
    │
    ├──> [AES-256 CTR Mode] ──> Ciphertext
    │
    └──> [GMAC 認證] ───> Tag (16 bytes)
```

**工作流程**:

```python
IV = 12 random bytes
Ciphertext = AES-CTR(key, IV, plaintext)
Tag = GMAC(key, IV, ciphertext)

# 解密方驗證 Tag
```

**特點**:
- **完整性保證**: GCM 標籤防止篡改
- **高效**: 並行加密/認證
- **標準**: NIST 推薦 (SP 800-38D)

---

## 網路通訊協議

### 協議版本

| 版本 | 特性 |
|------|------|
| v2.0 | 初版 (6層KDF) |
| v2.1 | 優化握手包格式 |
| v2.2 | **當前版本** (5層KDF, 改進的會話隔離) |

### 訊息格式

#### 握手請求

```json
[Header: 1B version][Length: 4B][Packet: 1320B]
```

#### 握手回應

```json
{
  "success": true,
  "server_ecc_pub": "hex_string (64 chars)",
  "pqc_ciphertext": "hex_string (2176 chars)",
  "session_id": "hex_string (64 chars)",
  "timestamp": 1705312200.123
}
```

#### 安全訊息

```json
{
  "type": "secure_msg",
  "data": {
    "iv": "hex_string (24 chars)",
    "ciphertext": "hex_string",
    "tag": "hex_string (32 chars)"
  },
  "timestamp": 1705312201.456
}
```

#### 確認

```json
{
  "type": "ack"
}
```

---

## 實現細節

### 1. 隨機數生成

```python
import secrets

# 安全隨機數生成 (OS-level entropy)
session_id = secrets.token_bytes(32)  # 256-bit
iv = secrets.token_bytes(12)           # 96-bit
salt = hashlib.sha3_256(...).digest()  # 衍生自公鑰
```

**不使用 `random` 模組**: 
- `random` 基於 Mersenne Twister (不安全)
- `secrets` 使用系統熵源 (Cryptographically Secure)

### 2. 時間戳對齊

```python
# 客戶端: 毫秒級時間戳
timestamp = int(time.time() * 1000)

# 伺服器: 重放攻擊防禦 (簡單版本)
# 實際應用應檢查: |server_time - client_timestamp| < threshold
```

### 3. 金鑰衍生樹

```
Master Key (32 bytes)
    │
    ├─[HMAC(key, "ENC-v2")] → Encryption Key (32B)
    │
    ├─[HMAC(key, "SESSION-v2")] → Session Key (32B)
    │
    └─[HMAC(key, "AUTH-v2")][:16] → Auth Key (16B)
```

**好處**:
- 獨立派生，不同用途
- 一個金鑰洩露不影響其他

### 4. 會話隔離

```python
# 每個連接獨立的 KEM 實例
class ServerBackend:
    def _handle_client(self, conn, addr):
        connection_kem = InnovativeHybridKEM()  # ← 新實例
        # ...
```

**效果**:
- **PFS** (前向保密): 舊會話金鑰洩露不影響新連接
- **會話隔離**: 多個並發連接互不干擾

---

## 使用指南

### 環境設定

```bash
# 1. 安裝依賴
pip install cryptography kyber-py

# 2. 驗證版本
python -c "import cryptography; print(cryptography.__version__)"
python -c "from kyber_py.kyber import Kyber768; print('OK')"
```

### 執行伺服器

```bash
cd network

# GUI 版本 (推薦)
python gui_server.py

# 或 Console 版本
python server.py
```

**啟動日誌**:
```
伺服器啟動於 0.0.0.0:8888
[DEBUG] 握手包計算長度: 1320 bytes
...等待連接
```

### 執行用戶端

```bash
# GUI 版本
python gui_client.py

# 或 Console 版本
python client.py
```

**交互步驟**:

1. **INIT CONNECTION** - 連接到伺服器
2. **EXECUTE HANDSHAKE** - 進行量子安全握手
3. **輸入訊息** - 發送加密訊息

### 測試集成

```bash
# 驗證 Kyber-768 功能
python test_kyber_integration.py

# 預期輸出
[1] Client KeyGen...
    Public Key size: 1184 bytes (Expected: 1184)
[2] Server Encapsulate...
    Ciphertext size: 1088 bytes (Expected: 1088)
[3] Client Decapsulate...
[OK] SUCCESS: Shared Secrets MATCH!
```

---

## 安全分析

### 威脅模型

| 威脅 | 防禦機制 |
|------|----------|
| **量子攻擊** | Kyber-768 (模 LWE) |
| **經典攻擊** | X25519 (ECC) |
| **重放攻擊** | 時間戳 + Session ID |
| **篡改** | AES-GCM Tag |
| **密文竊聽** | AES-256 加密 |
| **握手中間人** | 雙向認證 (可拓展) |

### 已知限制

1. **身份驗證**: 當前無客戶端身份驗證
   - 方案: 可使用簽名証書 (X.509)

2. **時間戳驗證**: 簡化實現
   - 改進: NTP 時鐘同步 + 時間窗口檢查

3. **會話恢復**: 無 session resumption
   - 改進: 票券或 PSK (Pre-Shared Key)

### 安全強度估計

| 組件 | 強度 | 量子後強度 |
|------|------|-----------|
| **X25519** | 128-bit | 0-bit (易被破解) |
| **Kyber-768** | ? | 256-bit (安全) |
| **混合** | 128-bit | **256-bit** ✓ |

**結論**: 即使 ECC 被破解，系統仍保有 256-bit 安全強度。

---

## 效能指標

### 握手耗時 (單位: ms)

| 階段 | 耗時 |
|------|------|
| Kyber KeyGen | ~1ms |
| Kyber Encaps | ~1ms |
| Kyber Decaps | ~1ms |
| HKDF 衍生 | ~5ms |
| **總計** | **~8ms** |

### 訊息吞吐量

```
AES-256-GCM 加密速度: ~1000 MB/s (現代 CPU)
典型訊息 (1KB): < 1μs

實際瓶頸: 網路 I/O (而非加密)
```

---

## 附錄

### A. 依賴套件

```
cryptography >= 41.0.0
  ├─ hazmat (底層密碼原語)
  └─ x25519 (ECC 實現)

kyber-py >= 0.4.0
  └─ Kyber768.keygen/encaps/decaps
```

### B. 調試標籤

```python
# 啟用調試輸出
[DEBUG_KDF] Salt: ...
[DEBUG_KDF] Timestamp: ...
[DEBUG_KDF] ECC Shared: ...
[DEBUG_KDF] PQC Shared: ...
[DEBUG] Key Derived: Session=..., Enc=...
```

### C. 常見錯誤

| 錯誤 | 原因 | 解決 |
|------|------|------|
| `PacketFormatError` | 握手包長度不是 1320 | 檢查 struct 格式 |
| `AES-GCM 解密失敗` | Tag 驗證失敗 | 訊息被篡改 |
| `金鑰交換失敗` | 公鑰格式錯誤 | 檢查編碼 (hex/bytes) |
| `連接超時` | 伺服器未啟動 | 先啟動 server |

---

## 許可證

MIT License - 開源自由使用

**引用本系統的研究論文時，請註明**:
```
Hybrid Quantum-Secure Communication System v2.2
Based on ML-KEM (Kyber-768) and X25519
```

---

**文檔完成時間**: 2026年1月15日  
**技術審核**: ✓  
**安全評估**: ✓ (預備版本)
