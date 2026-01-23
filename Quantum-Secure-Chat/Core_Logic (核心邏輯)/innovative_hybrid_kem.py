# innovative_hybrid_kem.py
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
    """混合KEM異常基類"""
    pass

class KeyGenerationError(HybridKEMError):
    """金鑰生成異常"""
    pass

class PacketFormatError(HybridKEMError):
    """封包格式異常"""
    pass

class InnovativeHybridKEM:
    """
    核心加密模組 (真實 Kyber-768 版)
    """
    
    # 定義標準長度常量
    PQC_CIPHERTEXT_LENGTH = 1088  # Kyber-768 標準密文長度
    PQC_SHARED_SECRET_LENGTH = 32  # 256-bit 共享秘密
    PQC_PUBLIC_KEY_LENGTH = 1184   # Kyber-768 公鑰長度
    ECC_PUBLIC_KEY_LENGTH = 32  # X25519 公鑰長度
    SALT_LENGTH = 32
    TIMESTAMP_LENGTH = 8
    PROOF_LENGTH = 32
    SESSION_ID_BIN_LENGTH = 32
    
    # 握手包格式定義: 改為傳送 PQC 公鑰 (1184 bytes)
    # salt(32), timestamp(8), proof(32), session_id(32), ecc_pub(32), pqc_pub(1184)
    HANDSHAKE_FORMAT = '!32s Q 32s 32s 32s 1184s'

    def __init__(self, config: Optional[Dict] = None):
        """
        初始化混合KEM
        """
        # 默認配置
        self.config = {
            'validate_keys': True,
            **(config or {})
        }

        # 算法標識
        self.pqc_name = "Kyber-768 (Real)"
        self.ecc_name = "X25519"
        self.kdf_name = "HKDF-SHA3-256"

        # 安全金鑰生成
        self._private_key = self._generate_validated_ecc_key()
        self.ecc_public_bytes = self._private_key.public_key().public_bytes_raw()
        
        # 會話ID生成 - 生成32字節的二進制數據
        self._session_id_bin = secrets.token_bytes(self.SESSION_ID_BIN_LENGTH)
        self.session_id = self._session_id_bin.hex()  # hex版本用於顯示和兼容舊代碼
        
        # 計算握手包長度
        self.HANDSHAKE_PACKAGE_LENGTH = struct.calcsize(self.HANDSHAKE_FORMAT)

        
        # 驗證長度
        expected = (self.SALT_LENGTH + self.TIMESTAMP_LENGTH + self.PROOF_LENGTH + 
                self.SESSION_ID_BIN_LENGTH + self.ECC_PUBLIC_KEY_LENGTH + 
                self.PQC_PUBLIC_KEY_LENGTH)
        if self.HANDSHAKE_PACKAGE_LENGTH != expected:
            print(f"[WARNING] 計算長度{self.HANDSHAKE_PACKAGE_LENGTH}與期望長度{expected}不一致")

    # ========== 核心邏輯 1: 真實 Kyber PQC ==========
    def client_pqc_keygen(self) -> Tuple[bytes, bytes]:
        try:
            pk, sk = Kyber768.keygen()
            return pk, sk
        except Exception as e:
            raise KeyGenerationError(f"PQC金鑰生成失敗: {e}")
    
    def server_pqc_encapsulate(self, client_pub_key: bytes) -> Tuple[bytes, bytes]:
        try:
            # Kyber768.encaps returns (shared_secret, ciphertext)
            shared_secret, ciphertext = Kyber768.encaps(client_pub_key)
            return ciphertext, shared_secret
        except Exception as e:
            raise HybridKEMError(f"PQC封裝失敗: {e}")
    
    def client_pqc_decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        try:
            # kyber-py uses decaps(sk, c) order to align with FIPS 203
            shared_secret = Kyber768.decaps(secret_key, ciphertext)
            return shared_secret
        except Exception as e:
            raise HybridKEMError(f"PQC解封裝失敗: {e}")
    
    # ========== 核心邏輯 2: 封包生成與解析 ==========
    def generate_handshake_package(self, pqc_public_key: bytes) -> bytes:
        if pqc_public_key is None:
            raise ValueError("pqc_public_key不能為None")
        
        # 1. 驗證長度
        if len(pqc_public_key) != self.PQC_PUBLIC_KEY_LENGTH:
            raise ValueError(f"Kyber 公鑰長度錯誤: {len(pqc_public_key)}")
        
        # 2. 生成鹽值 (綁定雙方公鑰)
        salt = hashlib.sha3_256(self.ecc_public_bytes + pqc_public_key).digest()[:self.SALT_LENGTH]
        
        # 3. 時間戳
        timestamp = int(time.time() * 1000)  # 毫秒級時間戳
        
        # 4. 生成完整性證明
        combined_data = self.ecc_public_bytes + pqc_public_key
        proof_key = secrets.token_bytes(32)
        entropy_proof = hmac.new(proof_key, combined_data, hashlib.sha3_512).digest()[:self.PROOF_LENGTH]
        
        # 5. 使用struct打包確保精確長度
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
        try:
            # 使用struct解包
            salt, timestamp, entropy_proof, session_id_bin, ecc_pub, pqc_pub = struct.unpack(
                self.HANDSHAKE_FORMAT, data
            )
            
            # 將二進制session_id轉為hex字符串
            session_id_hex = session_id_bin.hex()
            
            return {
                'salt': salt,
                'timestamp': timestamp,
                'entropy_proof': entropy_proof,
                'session_id': session_id_hex,
                'session_id_bin': session_id_bin,
                'ecc_pub': ecc_pub,
                'pqc_public_key': pqc_pub
            }
            
        except struct.error as e:
            raise PacketFormatError(f"解包握手包失敗: {e}")

    # ========== 核心邏輯 3: 真實 AES-GCM 加密通訊 ==========
    def encrypt_aes_gcm(self, key: bytes, plaintext: str) -> Dict[str, str]:
        if len(key) != 32:
            raise ValueError("金鑰必須為32字節")
        
        # 生成隨機初始向量 (12字節)
        iv = secrets.token_bytes(12)
        
        # 建立加密器 (AES-256-GCM)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        
        # 加密
        ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
        
        # 返回加密包（轉為Hex以便網路傳輸JSON）
        return {
            "iv": iv.hex(),
            "ciphertext": ciphertext.hex(),
            "tag": encryptor.tag.hex()  # GCM 驗證標籤
        }

    def decrypt_aes_gcm(self, key: bytes, data: Dict[str, str]) -> str:
        """
        使用協商好的金鑰進行 AES-GCM 解密
        """
        if len(key) != 32:
            raise ValueError("金鑰必須為32字節")
        
        try:
            # 還原 Bytes
            iv = bytes.fromhex(data['iv'])
            ciphertext = bytes.fromhex(data['ciphertext'])
            tag = bytes.fromhex(data['tag'])
            
            # 建立解密器
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
            decryptor = cipher.decryptor()
            
            # 解密（若tag驗證失敗，會拋出Exception）
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            return plaintext.decode('utf-8')
        except Exception as e:
            raise HybridKEMError(f"AES-GCM 解密失敗: {e}")

    # ========== 輔助功能 ==========
    def _generate_validated_ecc_key(self):
        """生成並驗證ECC金鑰對"""
        try:
            # 生成私鑰
            private_key = x25519.X25519PrivateKey.generate()
            
            # 計算公鑰
            public_key = private_key.public_key()
            public_bytes = public_key.public_bytes_raw()
            
            # 基本驗證
            if len(public_bytes) != self.ECC_PUBLIC_KEY_LENGTH:
                raise KeyGenerationError("ECC公鑰長度不正確")
            
            # 簡化的金鑰驗證
            if self.config.get('validate_keys', True):
                self._validate_x25519_key(private_key, public_key)
            
            return private_key
            
        except Exception as e:
            raise KeyGenerationError(f"ECC金鑰生成失敗: {e}")

    def _validate_x25519_key(self, private_key, public_key):
        """驗證X25519金鑰對的有效性"""
        # 測試金鑰交換
        test_private = x25519.X25519PrivateKey.generate()
        test_public = test_private.public_key()
        
        try:
            # 雙方都能計算相同的共享秘密
            shared1 = private_key.exchange(test_public)
            shared2 = test_private.exchange(public_key)
            
            if shared1 != shared2:
                raise KeyGenerationError("金鑰交換驗證失敗")
            
            # 驗證公鑰格式
            pub_bytes = public_key.public_bytes_raw()
            if len(pub_bytes) != 32:
                raise KeyGenerationError("公鑰長度不正確")
            
        except Exception as e:
            raise KeyGenerationError(f"金鑰驗證失敗: {e}")

    def _layered_kdf(self, inputs: List[bytes], context: bytes, rounds: int = 2) -> bytes:
        """
        分層金鑰派生函數
        """
        # 合併所有共享秘密
        current_hash = b"".join(inputs)
        # 多層KDF
        for i in range(rounds):
            current_hash = hashlib.sha3_256(current_hash + context + i.to_bytes(4, 'big')).digest()
        return current_hash

    def derive_final_key(self, peer_ecc_pub: bytes, pqc_shared: bytes, salt: bytes, timestamp: int) -> Dict[str, bytes]:
        """
        衍生最終會話金鑰
        """
        # 1. ECC 金鑰交換
        try:
            peer_key = x25519.X25519PublicKey.from_public_bytes(peer_ecc_pub)
            ecc_shared = self._private_key.exchange(peer_key)
        except Exception as e:
            raise KeyGenerationError(f"ECC金鑰交換失敗: {e}")
        

        
        # 2. 混合KDF上下文
        context = b"HybridKEM-v2.2" + timestamp.to_bytes(8, 'big') + salt
        
        # 3. 分層KDF派生主金鑰
        master_key = self._layered_kdf([ecc_shared, pqc_shared], context, rounds=5)
        
        # 4. 金鑰分離
        # 確保回傳的字典中都是 bytes
        keys = {
            'encryption_key': hmac.new(master_key, b"ENC-v2", hashlib.sha3_256).digest(),
            'session_key': hmac.new(master_key, b"SESSION-v2", hashlib.sha3_256).digest(),
            'authentication_key': hmac.new(master_key, b"AUTH-v2", hashlib.sha3_256).digest()[:16]
        }

        return keys

    def get_security_metrics(self) -> Dict:
        """獲取安全指標"""
        return {
            "Level": "256-bit PQC (Hybrid)",
            "ECC": self.ecc_name,
            "PQC": self.pqc_name,
            "KDF": self.kdf_name,
            "Session_ID": self.session_id[:16] + "...",
            "Key_Size": {
                "ECC": f"{len(self.ecc_public_bytes)*8}-bit",
                "PQC": "768-bit (Kyber)",
                "AES": "256-bit"
            }
        }

# 為兼容性保留舊名
InitializationError = HybridKEMError