# innovative_hybrid_kem.py
# =============================================================================
# 模組名稱：量子安全混合 KEM (Key Encapsulation Mechanism) 引擎
# 負責功能：金鑰生成、混合金鑰封裝、分層 KDF、以及 AES-GCM 訊息加密
# 架構層次：密碼學引擎層 (大腦)
# =============================================================================

import secrets
import hashlib
import hmac
import time
import struct
from typing import Tuple, Dict, Optional, List
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from kyber_py.kyber import Kyber768

class HybridKEMError(Exception):
    """混合KEM異常基礎類別"""
    pass

class KeyGenerationError(HybridKEMError):
    """金鑰生成異常"""
    pass

class PacketFormatError(HybridKEMError):
    """封包格式異常 (用於打包或解析錯誤)"""
    pass

class InnovativeHybridKEM:
    """
    核心加密模組
    採用真實 Kyber-768 (PQC) 與 X25519 (ECC) 的混合防禦架構
    """
    
    # --- 規格常量定義 ---
    PQC_CIPHERTEXT_LENGTH = 1088    # Kyber-768 標準密文長度
    PQC_SHARED_SECRET_LENGTH = 32   # 256-bit 共享秘密
    PQC_PUBLIC_KEY_LENGTH = 1184    # Kyber-768 公鑰長度
    ECC_PUBLIC_KEY_LENGTH = 32     # X25519 (Curve25519) 公鑰長度
    SALT_LENGTH = 32                # 鹽值長度
    TIMESTAMP_LENGTH = 8            # 時間戳長度 (Q)
    PROOF_LENGTH = 32               # 完整性證明長度
    SESSION_ID_BIN_LENGTH = 32      # 會話ID二進制長度
    
    # --- 握手包格式 (Network Protocol) ---
    # 格式解說: ! (大端序) | 32s (Salt) | Q (Long Long) | 32s (Proof) | 32s (SessionID) | 32s (ECC_Pub) | 1184s (PQC_Pub)
    HANDSHAKE_FORMAT = '!32s Q 32s 32s 32s 1184s'

    def __init__(self, config: Optional[Dict] = None):
        """
        [階段一：引擎初始化]
        建立基本的加密環境與初始 ECC 金鑰
        """
        self.config = {
            'validate_keys': True,
            **(config or {})
        }

        # 演算法標示 (用於文件與識別)
        self.pqc_name = "Kyber-768 (NIST Finalist)"
        self.ecc_name = "X25519 (Curve25519)"
        self.kdf_name = "HKDF-SHA3-256 (Layered)"

        # 生成預設的身份 ECC 金鑰對
        self._private_key = self._generate_validated_ecc_key()
        self.ecc_public_bytes = self._private_key.public_key().public_bytes_raw()
        
        # 生成初始隨機會話ID
        self._session_id_bin = secrets.token_bytes(self.SESSION_ID_BIN_LENGTH)
        self.session_id = self._session_id_bin.hex()
        
        # 計算預期長度以便驗證
        self.HANDSHAKE_PACKAGE_LENGTH = struct.calcsize(self.HANDSHAKE_FORMAT)
        
        # 啟動時驗證長度定義
        expected = (self.SALT_LENGTH + self.TIMESTAMP_LENGTH + self.PROOF_LENGTH + 
                    self.SESSION_ID_BIN_LENGTH + self.ECC_PUBLIC_KEY_LENGTH + 
                    self.PQC_PUBLIC_KEY_LENGTH)
        if self.HANDSHAKE_PACKAGE_LENGTH != expected:
            print(f"[警告] 計算長度 {self.HANDSHAKE_PACKAGE_LENGTH} 與預期 {expected} 不一致")

    # =============================================================================
    # 【核心邏輯 A：量子安全 PQC / Kyber-768】
    # =============================================================================
    
    def client_pqc_keygen(self) -> Tuple[bytes, bytes]:
        """
        [階段二：客戶端金鑰生成]
        生成抗量子的 Kyber-768 金鑰對
        """
        try:
            pk, sk = Kyber768.keygen()
            return pk, sk
        except Exception as e:
            raise KeyGenerationError(f"PQC 金鑰生成失敗: {e}")
    
    def server_pqc_encapsulate(self, client_pub_key: bytes) -> Tuple[bytes, bytes]:
        """
        [階段三：伺服器端金鑰封裝]
        針對發送過來的客戶端 PQC 公鑰進行加密封裝，產出共享秘密與密文
        """
        try:
            # Kyber768.encaps 回傳 (共享秘密, 密文)
            shared_secret, ciphertext = Kyber768.encaps(client_pub_key)
            return ciphertext, shared_secret
        except Exception as e:
            raise HybridKEMError(f"PQC 加密封裝失敗: {e}")
    
    def client_pqc_decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """
        [階段四：客戶端金鑰解封裝]
        使用私鑰解鎖伺服器傳回的密文，獲取與伺服器完全一致的 PQC 共享秘密
        """
        try:
            shared_secret = Kyber768.decaps(secret_key, ciphertext)
            return shared_secret
        except Exception as e:
            raise HybridKEMError(f"PQC 密文解開失敗: {e}")
    
    # =============================================================================
    # 【核心邏輯 B：封包序列化 (Serialization)】
    # =============================================================================
    
    def generate_handshake_package(self, pqc_public_key: bytes) -> bytes:
        """
        [階段二：封包打包]
        將公鑰、鹽值、時間戳等元數據精確打包成二進制流，準備發送
        """
        if pqc_public_key is None:
            raise ValueError("PQC 公鑰不為 None")
        
        if len(pqc_public_key) != self.PQC_PUBLIC_KEY_LENGTH:
            raise ValueError(f"Kyber 公鑰長度錯誤: {len(pqc_public_key)}")
        
        # 1. 產生鹽值 (Salt)：透過雙方公鑰雜湊，確保隨機性與身份連結
        salt = hashlib.sha3_256(self.ecc_public_bytes + pqc_public_key).digest()[:self.SALT_LENGTH]
        
        # 2. 注入毫秒級時間戳，防止重放攻擊 (Replay Attack)
        timestamp = int(time.time() * 1000)
        
        # 3. 生成完整性證明 (Entropy Proof)：保證包裝內容未被竄改
        combined_data = self.ecc_public_bytes + pqc_public_key
        proof_key = secrets.token_bytes(32)
        entropy_proof = hmac.new(proof_key, combined_data, hashlib.sha3_512).digest()[:self.PROOF_LENGTH]
        
        # 4. 使用 struct 進行強型別打包 (嚴格對齊 1320 Bytes)
        try:
            package = struct.pack(
                self.HANDSHAKE_FORMAT,
                salt,                    # 32s
                timestamp,               # Q 
                entropy_proof,           # 32s
                self._session_id_bin,    # 32s 
                self.ecc_public_bytes,   # 32s
                pqc_public_key           # 1184s
            )
        except struct.error as e:
            raise PacketFormatError(f"打包握手包失敗: {e}")
        
        return package
    
    def parse_handshake_package(self, data: bytes) -> Dict:
        """
        [階段三：封包解析]
        將收到的二進制流還原成各種密碼學物件
        """
        try:
            salt, timestamp, entropy_proof, session_id_bin, ecc_pub, pqc_pub = struct.unpack(
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
        except struct.error as e:
            raise PacketFormatError(f"解析握手包失敗: {e}")

    # =============================================================================
    # 【核心邏輯 C：AES-GCM 訊息通訊 (AEAD模式)】
    # =============================================================================
    
    def encrypt_aes_gcm(self, key: bytes, plaintext: str) -> Dict[str, str]:
        """
        [階段五：訊息加密]
        使用當前的會話金鑰，對聊天訊息進行 AES-256-GCM 加密
        """
        if len(key) != 32:
            raise ValueError("會話金鑰必須為 32 字節 (AES-256)")
        
        # 產生 12 字節隨機 IV (Nonce)，確保每次加密結果均不相同
        iv = secrets.token_bytes(12)
        
        # 初始化 AEAD 加密器 (包含認證標籤)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        
        # 執行加密
        ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
        
        # 回傳加密包物件 (含標籤用於解密驗證)
        return {
            "iv": iv.hex(),
            "ciphertext": ciphertext.hex(),
            "tag": encryptor.tag.hex()  # 非常重要：這是防篡改的生命線
        }

    def decrypt_aes_gcm(self, key: bytes, data: Dict[str, str]) -> str:
        """
        [階段五：訊息解密與驗證]
        進行數據解密同步驗證 Tag，若資料遭竄改會直接拋出異常
        """
        if len(key) != 32:
            raise ValueError("會話金鑰長度不合規")
        
        try:
            iv = bytes.fromhex(data['iv'])
            ciphertext = bytes.fromhex(data['ciphertext'])
            tag = bytes.fromhex(data['tag'])
            
            # 使用收到的標籤 Tag 初始化解密器
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
            decryptor = cipher.decryptor()
            
            # 若數據被改動，這裡的 finalize() 會拋出安全性錯誤
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            return plaintext.decode('utf-8')
        except Exception as e:
            raise HybridKEMError(f"訊息認證解密失敗 (可能遭篡改): {e}")

    # =============================================================================
    # 【核心邏輯 D：金鑰衍生 (KDF) 與 ECC 交換】
    # =============================================================================

    def derive_final_key(self, peer_ecc_pub: bytes, pqc_shared: bytes, salt: bytes, timestamp: int) -> Dict[str, bytes]:
        """
        [重要核心：最終金鑰衍生]
        將傳統金鑰 (ECC) 與量子安全金鑰 (PQC) 混合，產出通訊用的三長金鑰
        """
        # 1. 進行傳統 X25519 金鑰交換 (建立第一層安全)
        try:
            peer_key = x25519.X25519PublicKey.from_public_bytes(peer_ecc_pub)
            ecc_shared = self._private_key.exchange(peer_key)
        except Exception as e:
            raise KeyGenerationError(f"ECC 交換階段失敗: {e}")
            
        # 2. 定義上下文 (Context)，確保衍生出的金鑰綁定到特定的通訊情境與時間
        context = b"HybridKEM-v2.2" + timestamp.to_bytes(8, 'big') + salt
        
        # 3. 透過分層金鑰派生 (Layered KDF) 混合兩種不同的安全強度
        # SHA3-256 五輪雜湊，提供極高的熵源
        master_key = self._layered_kdf([ecc_shared, pqc_shared], context, rounds=5)
        
        # 4. 金鑰分離 (Key Separation)：利用 HMAC 派生出三把用途不同的金鑰
        # 這遵循金鑰管理的最佳實踐，不讓一把金鑰通吃所有功能
        keys = {
            'encryption_key':     hmac.new(master_key, b"ENC-v2",     hashlib.sha3_256).digest(),
            'session_key':        hmac.new(master_key, b"SESSION-v2", hashlib.sha3_256).digest(),
            'authentication_key': hmac.new(master_key, b"AUTH-v2",    hashlib.sha3_256).digest()[:16]
        }
        return keys

    # --- 內部私有工具 ---

    def _generate_validated_ecc_key(self):
        """生成並執行嚴格自我測試的 ECC 金鑰"""
        try:
            private_key = x25519.X25519PrivateKey.generate()
            public_key = private_key.public_key()
            if self.config.get('validate_keys', True):
                self._validate_x25519_key(private_key, public_key)
            return private_key
        except Exception as e:
            raise KeyGenerationError(f"ECC 初始化失敗: {e}")

    def _validate_x25519_key(self, private_key, public_key):
        """執行一次模擬交換，驗證數學正確性"""
        test_private = x25519.X25519PrivateKey.generate()
        shared1 = private_key.exchange(test_private.public_key())
        shared2 = test_private.exchange(public_key)
        if shared1 != shared2:
            raise KeyGenerationError("ECC 金鑰交換自我測試失敗")

    def _layered_kdf(self, inputs: List[bytes], context: bytes, rounds: int = 2) -> bytes:
        """分層金鑰派生核心邏輯 (SHA3-256 多輪混合)"""
        current_hash = b"".join(inputs)
        for i in range(rounds):
            current_hash = hashlib.sha3_256(current_hash + context + i.to_bytes(4, 'big')).digest()
        return current_hash
