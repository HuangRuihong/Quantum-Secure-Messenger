"""
gen_memory_layout.py
====================
根據 innovative_hybrid_kem.py 定義的封包格式常數，
生成 PNG 格式的「封包記憶體佈局圖」，圖檔輸出至 ../gui/

涵蓋四種封包結構
-----------------
1. HandshakePackage  (Client → Server，握手包)
   格式: salt(32) | timestamp(8) | proof(32) | session_id(32) | ecc_pub(32) | pqc_pub(1184)
   總計: 1320 bytes

2. ServerHelloResponse (Server → Client，JSON 格式示意)
   欄位: success | server_ecc_pub | pqc_ciphertext | session_id | timestamp

3. SecureMessage (雙向，帶長度前綴)
   結構: [Length(4B)] | JSON Body { type, data:{iv,ciphertext,tag}, timestamp }
   data 欄位: iv(12B) | ciphertext(var) | tag(16B)

4. AES-GCM Crypto Block (AES 加密細節)
   IV(12B) | Ciphertext(var) | Auth Tag(16B)
"""

import os
import sys
import struct

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    print("[ERROR] 請先安裝 Pillow：  pip install Pillow")
    sys.exit(1)

# ── 路徑 ────────────────────────────────────────────────────────────────────
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
OUTPUT_DIR   = os.path.join(PROJECT_ROOT, "gui")
os.makedirs(OUTPUT_DIR, exist_ok=True)
OUTPUT_PNG   = os.path.join(OUTPUT_DIR, "packet_memory_layout.png")

# ── 顏色主題 ─────────────────────────────────────────────────────────────────
BG         = (10,  12,  22)
TITLE_CLR  = (0,  230, 255)
SEC_CLR    = (160, 200, 255)
TEXT_CLR   = (220, 230, 255)
DIM_CLR    = (100, 115, 160)
GRID_CLR   = (30,  35,  60)

# 欄位顏色（循環使用）
FIELD_PALETTES = [
    ((0,  160, 220), (0,  80, 140)),    # 藍　- 邊框
    ((0,  190, 130), (0,  90,  70)),    # 綠
    ((200, 80, 180), (100, 30,  90)),   # 紫
    ((220,150,  30), (110, 70,   0)),   # 金
    ((60, 190, 255), (20,  90, 140)),   # 亮藍
    ((255,100,  80), (130, 40,  30)),   # 橙紅
    ((130,220,  80), ( 60, 100, 30)),   # 黃綠
    ((255,180,  60), (130,  80,  10)),  # 黃
]

# ── 字型 ─────────────────────────────────────────────────────────────────────
def _load_font(size):
    for name in ["msjh.ttc", "msjhl.ttc", "msyh.ttc", "mingliu.ttc",
                "consola.ttf","DejaVuSansMono.ttf","LiberationMono-Regular.ttf",
                "cour.ttf","arial.ttf"]:
        try:
            return ImageFont.truetype(name, size)
        except (IOError, OSError):
            pass
    return ImageFont.load_default()

# ── 封包資料定義 ──────────────────────────────────────────────────────────────

# 每個 Section: (section_title, section_subtitle, fields)
# field: (name, bytes_count_or_str, description, note)
SECTIONS = [
    # ── 1. Handshake Package ──────────────────────────────────────────────
    (
        "① HandshakePackage  (Client → Server)",
        "格式: struct.pack('!32s Q 32s 32s 32s 1184s')   共 1320 Bytes",
        [
            ("salt",         32,    "SHA3-256(ecc_pub ‖ pqc_pub)[:32]",       "防重放：綁定雙方公鑰"),
            ("timestamp",     8,    "int(time.time() × 1000)  (毫秒時間戳)",  "8B 大端序 unsigned long long"),
            ("entropy_proof", 32,   "HMAC-SHA3-512(random_key, ecc‖pqc)[:32]","完整性證明"),
            ("session_id",   32,    "secrets.token_bytes(32)  (隨機會話ID)",   "32B 二進制，顯示時轉 Hex"),
            ("ecc_pub",      32,    "X25519 公鑰 (raw bytes)",                 "Curve25519 點坐標"),
            ("pqc_pub",    1184,    "Kyber-768 公鑰",                          "NIST 標準格式 1184B"),
        ]
    ),

    # ── 2. Server Hello Response ──────────────────────────────────────────
    (
        "② ServerHelloResponse  (Server → Client)",
        "格式: [Length(4B)] + JSON (UTF-8)   大小依內容而定",
        [
            ("Length Header",   4,      "struct.pack('!I', len(json_body))",    "大端序 4B 長度前綴"),
            ("success",        "bool",   '"true"  握手成功旗標',                "JSON boolean"),
            ("server_ecc_pub", "64 hex", "Server X25519 公鑰 (hex 字串)",        "32B → 64 hex chars"),
            ("pqc_ciphertext","2176 hex","Kyber-768 密文 (hex 字串)",            "1088B → 2176 hex chars"),
            ("session_id",     "64 hex", "Session ID (hex 字串)",                "32B → 64 hex chars"),
            ("timestamp",      "float",  "time.time()  Unix 時間戳",             "JSON float"),
        ]
    ),

    # ── 3. Secure Message Frame ───────────────────────────────────────────
    (
        "③ SecureMessage Frame  (雙向通訊)",
        "格式: [Length(4B, 大端序 uint32)] ‖ [JSON Body]",
        [
            ("Length Header",  4,       "struct.pack('!I', len(json_body))",    "大端序無符號整數，指示後方 JSON 長度"),
            ('type',          "str",    '"secure_msg"  訊息類型識別',            "JSON string"),
            ('data.iv',       "24 hex", "AES-GCM IV (hex)",                     "12B 隨機值 → 24 hex chars"),
            ('data.ciphertext',"hex",   "AES-256-GCM 密文 (hex)",               "長度 = 明文長度"),
            ('data.tag',      "32 hex", "AES-GCM Auth Tag (hex)",               "16B → 32 hex chars"),
            ('timestamp',     "float",  "time.time()  傳送時間戳",              "JSON float"),
            ('sender',        "str",    'sender_id (廣播時) / 可選',            "僅廣播訊息包含"),
        ]
    ),

    # ── 4. AES-GCM Crypto Block ───────────────────────────────────────────
    (
        "④ AES-256-GCM 加密區塊  (data 欄位解構)",
        "演算法: AES-256-GCM   金鑰長度 256 bits (32 Bytes)",
        [
            ("IV / Nonce",   12,    "secrets.token_bytes(12)  每次加密隨機生成","不可重複使用，否則破壞安全性"),
            ("Ciphertext",   "len(plaintext)", "AES-CTR 加密後密文",            "長度 = 明文長度 (無填充)"),
            ("Auth Tag",     16,    "GCM 認證標籤",                             "驗證完整性+真實性，16B = 128 bits"),
        ]
    ),

    # ── 5. Session Keys ───────────────────────────────────────────────────
    (
        "⑤ Session Keys  (derive_final_key 輸出)",
        "KDF: SHA3-256 × 5 rounds → master_key(32B) → HMAC 分離",
        [
            ("encryption_key",     32, "HMAC-SHA3-256(master, b'ENC-v2')",    "用於 AES-256-GCM 加密"),
            ("session_key",        32, "HMAC-SHA3-256(master, b'SESSION-v2')","備用/擴展金鑰"),
            ("authentication_key", 16, "HMAC-SHA3-256(master, b'AUTH-v2')[:16]","訊息認證，128 bits"),
        ]
    ),
]

# ── 版面常數 ──────────────────────────────────────────────────────────────────
W              = 1400
MARGIN_X       = 50
MARGIN_TOP     = 100
SEC_GAP        = 36         # Section 之間的間距
FIELD_H        = 36         # 每個欄位的列高
HEADER_H       = 68         # Section 標題高
FONT_TITLE_SZ  = 26
FONT_SEC_SZ    = 14
FONT_FIELD_SZ  = 13
FONT_NOTE_SZ   = 11

# 欄 寬度比例（name | size | desc | note）
COL_RATIOS = [0.18, 0.11, 0.38, 0.33]

def col_widths(total_w):
    return [int(total_w * r) for r in COL_RATIOS]

def calc_total_height():
    h = MARGIN_TOP
    for (stitle, ssub, fields) in SECTIONS:
        h += HEADER_H
        h += FIELD_H * (1 + len(fields))  # 1 行表頭
        h += SEC_GAP
    h += 40
    return h

def draw_layout():
    H = calc_total_height()
    img  = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(img)

    f_title = _load_font(FONT_TITLE_SZ)
    f_sec   = _load_font(FONT_SEC_SZ)
    f_field = _load_font(FONT_FIELD_SZ)
    f_note  = _load_font(FONT_NOTE_SZ)

    # ── 頁面標題 ──────────────────────────────────────────────────────────
    draw.text((W // 2, 36), "Quantum Secure Chat — 封包記憶體佈局圖",
              font=f_title, fill=TITLE_CLR, anchor="mm")
    draw.text((W // 2, 72),
              "InnovativeHybridKEM  |  Kyber-768 PQC + X25519 ECC + AES-256-GCM",
              font=f_note, fill=(100, 130, 200), anchor="mm")
    draw.line([(MARGIN_X, 88), (W - MARGIN_X, 88)], fill=GRID_CLR, width=1)

    cw = col_widths(W - MARGIN_X * 2)
    col_xs = [MARGIN_X]
    for w in cw[:-1]:
        col_xs.append(col_xs[-1] + w)

    y = MARGIN_TOP

    for sec_idx, (stitle, ssub, fields) in enumerate(SECTIONS):
        # ── Section 標題列 ────────────────────────────────────────────────
        draw.rectangle([MARGIN_X, y, W - MARGIN_X, y + HEADER_H],
                       fill=(18, 22, 45), outline=(50, 65, 110))
        draw.text((MARGIN_X + 16, y + 12), stitle,
                  font=f_sec, fill=TITLE_CLR)
        draw.text((MARGIN_X + 16, y + 38), ssub,
                  font=f_note, fill=(120, 150, 210))
        y += HEADER_H

        # ── 欄位表頭列 ────────────────────────────────────────────────────
        headers = ["欄位名稱", "大小 (Bytes)", "說明", "備注"]
        for ci, (hdr, cx) in enumerate(zip(headers, col_xs)):
            draw.rectangle([cx, y, cx + cw[ci], y + FIELD_H],
                           fill=(22, 28, 55), outline=GRID_CLR)
            draw.text((cx + 8, y + 10), hdr,
                      font=f_note, fill=(140, 170, 230))
        y += FIELD_H

        # ── 欄位列 ───────────────────────────────────────────────────────
        for fi, field in enumerate(fields):
            fname, fsize, fdesc, fnote = field
            palette_idx = fi % len(FIELD_PALETTES)
            fill_clr, border_clr = FIELD_PALETTES[palette_idx]

            size_str = str(fsize) + " B" if isinstance(fsize, int) else str(fsize)
            row_data = [fname, size_str, fdesc, fnote]

            for ci, (val, cx) in enumerate(zip(row_data, col_xs)):
                cell_fill = (20, 25, 48) if ci > 0 else (int(fill_clr[0]*0.3),
                                                          int(fill_clr[1]*0.3),
                                                          int(fill_clr[2]*0.3))
                draw.rectangle([cx, y, cx + cw[ci], y + FIELD_H],
                               fill=cell_fill, outline=GRID_CLR)
                # 欄位名稱加色塊
                if ci == 0:
                    draw.rectangle([cx + 4, y + 6, cx + 10, y + FIELD_H - 6],
                                   fill=fill_clr)
                    draw.text((cx + 16, y + 10), val,
                              font=f_field, fill=fill_clr)
                elif ci == 1:
                    draw.text((cx + 8, y + 10), val,
                              font=f_field, fill=(200, 220, 180))
                else:
                    draw.text((cx + 8, y + 10), val,
                              font=f_note, fill=TEXT_CLR if ci == 2 else DIM_CLR)
            y += FIELD_H

        # ── Byte 條狀視覺化（僅純數字欄位且總長 < 4096） ─────────────────
        byte_fields = [(n, s, FIELD_PALETTES[i % len(FIELD_PALETTES)][0])
                       for i, (n, s, *_) in enumerate(fields)
                       if isinstance(s, int)]
        total_bytes = sum(s for _, s, _ in byte_fields)

        if byte_fields and total_bytes <= 4096:
            bar_y = y + 6
            bar_h = 24
            bar_x0 = MARGIN_X + 8
            bar_w  = W - MARGIN_X * 2 - 16
            # 背景
            draw.rectangle([bar_x0, bar_y, bar_x0 + bar_w, bar_y + bar_h],
                           fill=(15, 18, 38), outline=GRID_CLR)
            # 各欄位分段
            cx = bar_x0
            for fname, fsize, fclr in byte_fields:
                seg_w = max(2, int(bar_w * fsize / total_bytes))
                draw.rectangle([cx, bar_y, cx + seg_w - 1, bar_y + bar_h],
                               fill=fclr)
                if seg_w > 24:
                    draw.text((cx + seg_w // 2, bar_y + bar_h // 2),
                              f"{fsize}B",
                              font=f_note, fill=(10, 12, 22), anchor="mm")
                cx += seg_w
            # 標籤
            draw.text((bar_x0, bar_y + bar_h + 4),
                      f"← Byte 佈局可視化  (總計 {total_bytes} Bytes) →",
                      font=f_note, fill=DIM_CLR)
            y += bar_h + 22

        y += SEC_GAP

    img.save(OUTPUT_PNG, "PNG", dpi=(150, 150))
    print(f"[OK]  已儲存封包記憶體佈局圖 → {OUTPUT_PNG}")
    return OUTPUT_PNG


if __name__ == "__main__":
    draw_layout()
