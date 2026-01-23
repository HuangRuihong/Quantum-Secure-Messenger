import unittest
import sys
import os


# 設定路徑以匯入核心模組
core_logic_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Core_Logic (核心邏輯)'))
sys.path.append(core_logic_path)

from innovative_hybrid_kem import InnovativeHybridKEM

class TestHybridKEMFull(unittest.TestCase):
    def setUp(self):
        self.client_kem = InnovativeHybridKEM()
        self.server_kem = InnovativeHybridKEM()
        print(f"\n[TEST] 正在測試 KDF 輪數: {self.client_kem.derive_final_key.__code__}") 
        # 注意：我們無法直接輕易訪問函數內部的默認參數，但在運行時可以觀察性能或日誌

    def test_full_handshake_and_encryption(self):
        print("\n>>> 開始測試完整握手與加密流程...")
        
        # 1. 產生金鑰與握手包
        print("[1] Client: 生成 PQC 金鑰與握手包")
        client_pqc_pk, client_pqc_sk = self.client_kem.client_pqc_keygen()
        handshake_packet = self.client_kem.generate_handshake_package(client_pqc_pk)
        self.assertEqual(len(handshake_packet), self.client_kem.HANDSHAKE_PACKAGE_LENGTH)

        # 2. Server 解析握手包
        print("[2] Server: 解析握手包")
        parsed_data = self.server_kem.parse_handshake_package(handshake_packet)
        self.server_kem.session_id = parsed_data['session_id']
        self.server_kem._session_id_bin = parsed_data['session_id_bin']

        # 3. Server 封裝 (PQC Encapsulate)
        print("[3] Server: 執行 Kyber-768 封裝")
        pqc_ciphertext, server_pqc_shared = self.server_kem.server_pqc_encapsulate(parsed_data['pqc_public_key'])
        
        # 4. Server 衍生金鑰 (KDF)
        print("[4] Server: 衍生最終會話金鑰 (KDF)")
        server_keys = self.server_kem.derive_final_key(
            parsed_data['ecc_pub'],
            server_pqc_shared,
            parsed_data['salt'],
            parsed_data['timestamp']
        )

        # 5. Client 解封裝 (PQC Decapsulate)
        print("[5] Client: 執行 Kyber-768 解封裝")
        client_pqc_shared = self.client_kem.client_pqc_decapsulate(pqc_ciphertext, client_pqc_sk)
        self.assertEqual(server_pqc_shared, client_pqc_shared, "PQC 共享秘密不匹配")

        # 6. Client 衍生金鑰
        print("[6] Client: 衍生最終會話金鑰 (KDF)")
        # 模擬 Client 收到 Server 的 ECC 公鑰 (在這裡我們直接從 server instance 拿)
        client_keys = self.client_kem.derive_final_key(
            self.server_kem.ecc_public_bytes, 
            client_pqc_shared,
            parsed_data['salt'],
            parsed_data['timestamp']
        )

        # 7. 驗證雙方金鑰一致性
        print("[7] 驗證 Session Key, Encryption Key, Auth Key 一致性")
        self.assertEqual(server_keys['session_key'], client_keys['session_key'])
        self.assertEqual(server_keys['encryption_key'], client_keys['encryption_key'])
        self.assertEqual(server_keys['authentication_key'], client_keys['authentication_key'])

        # 8. 測試 AES-GCM 加密通訊
        print("[8] 測試 AES-GCM 加解密")
        plaintext = "Quantum Security is Here!"
        encrypted_data = self.client_kem.encrypt_aes_gcm(client_keys['encryption_key'], plaintext)
        
        decrypted_text = self.server_kem.decrypt_aes_gcm(server_keys['encryption_key'], encrypted_data)
        self.assertEqual(plaintext, decrypted_text)
        print(">>> 測試成功！")

if __name__ == '__main__':
    unittest.main()
