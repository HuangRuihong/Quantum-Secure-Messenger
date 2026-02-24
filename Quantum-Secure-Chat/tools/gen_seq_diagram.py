"""
gen_seq_diagram.py
==================
根據 Quantum-Secure-Chat 的真實握手流程（client.py / server.py / innovative_hybrid_kem.py）
生成 SVG + PNG 格式的握手時序圖，圖檔輸出至 ../gui/

握手流程
--------
① Client  → Server : TCP Connect
② Client  → Server : [Ver(1B)] + [Len(4B)] + [HandshakePackage]
                HandshakePackage 結構:
                salt(32) | timestamp(8) | proof(32) | session_id(32) | ecc_pub(32) | pqc_pub(1184)
③ Server  處理      : parse_handshake_package
                    server_pqc_encapsulate  → pqc_ciphertext, pqc_shared
                    derive_final_key        → session_keys
④ Server  → Client : JSON{ success, server_ecc_pub, pqc_ciphertext, session_id, timestamp }
⑤ Client  處理      : client_pqc_decapsulate  → pqc_shared
                    derive_final_key        → session_keys
⑥ 雙向安全通訊       : [Len(4B)] + JSON{ type:"secure_msg", data:{iv,ciphertext,tag} }
"""

import os
import sys
import math
import textwrap

# ── 嘗試引入 PIL，若不存在提示安裝 ──────────────────────────────────────────
try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    print("[ERROR] 請先安裝 Pillow：  pip install Pillow")
    sys.exit(1)

# ── 輸出路徑設定 ────────────────────────────────────────────────────────────
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
OUTPUT_DIR   = os.path.join(PROJECT_ROOT, "gui")
os.makedirs(OUTPUT_DIR, exist_ok=True)
OUTPUT_PNG   = os.path.join(OUTPUT_DIR, "handshake_sequence_diagram.png")

# ── 顏色主題（深色賽博龐克） ────────────────────────────────────────────────
BG_COLOR        = (10,  12,  22)   # 背景
LANE_BG         = (16,  20,  38)   # 時間軌道背景
LIFELINE_COLOR  = (0,  200, 255)   # 生命線
CLIENT_COLOR    = (0,  200, 255)   # 客戶端 Actor
SERVER_COLOR    = (255, 80, 150)   # 伺服器 Actor
ARROW_COLOR     = (80, 230, 180)   # 訊息箭頭
SELF_COLOR      = (255, 200,  60)  # 自身處理方塊
TEXT_COLOR      = (220, 230, 255)  # 一般文字
TITLE_COLOR     = (0,  230, 255)   # 標題
NOTE_BG         = (30,  35,  60)   # 備注背景
NOTE_BORDER     = (80,  90, 140)   # 備注邊框
DIVIDER_COLOR   = (40,  45,  70)   # 分隔線

# ── 字型設定 ────────────────────────────────────────────────────────────────
def _load_font(size: int):
    """嘗試載入等寬字型，失敗則回退至預設字型"""
    candidates = [
        "msjh.ttc", "msjhl.ttc", "msyh.ttc", "mingliu.ttc",
        "consola.ttf", "consolab.ttf",
        "DejaVuSansMono.ttf", "LiberationMono-Regular.ttf",
        "cour.ttf", "arial.ttf"
    ]
    for name in candidates:
        try:
            return ImageFont.truetype(name, size)
        except (IOError, OSError):
            pass
    return ImageFont.load_default()

# ── 時序圖資料定義 ──────────────────────────────────────────────────────────
STEPS = [
    # (type, from, label, detail, phase_label)
    # type: "arrow" | "self" | "divider"
    # from: "client" | "server" | None
    ("divider", None,
    "① TCP 連線建立", "", "TCP Handshake"),

    ("arrow", "client",
    "TCP SYN  →",
    "socket.connect(host, port)",
    ""),

    ("arrow", "server",
    "← TCP SYN-ACK",
    "server.accept()",
    ""),

    ("divider", None,
    "② 客戶端發送握手包 (Client Hello)", "", "Quantum Handshake"),

    ("self", "client",
    "生成金鑰對",
    "Kyber768.keygen()  → pqc_pk, pqc_sk\n"
    "X25519.generate()  → ecc_priv, ecc_pub\n"
    "generate_handshake_package(pqc_pk)",
    ""),

    ("arrow", "client",
    "→  [Ver=0x02][Len=4B][HandshakePackage=1320B]",
    "HandshakePackage:\n"
    "  salt(32B) | timestamp(8B) | proof(32B)\n"
    "  session_id(32B) | ecc_pub(32B) | pqc_pub(1184B)",
    ""),

    ("divider", None,
    "③ 伺服器處理 PQC 封裝", "", "Server Processing"),

    ("self", "server",
    "解析握手包 & PQC 封裝",
    "parse_handshake_package(data)\n"
    "  → salt, timestamp, proof, session_id\n"
    "    ecc_pub, pqc_pub\n"
    "server_pqc_encapsulate(pqc_pub)\n"
    "  Kyber768.encaps(pqc_pub)\n"
    "  → pqc_ciphertext(1088B), pqc_shared(32B)",
    ""),

    ("self", "server",
    "衍生會話金鑰",
    "ECC: X25519.exchange(client_ecc_pub)\n"
    "     → ecc_shared(32B)\n"
    "KDF: SHA3-256 × 5 rounds\n"
    "     → master_key(32B)\n"
    "derive_final_key() → {\n"
    "  encryption_key(32B),\n"
    "  session_key(32B),\n"
    "  authentication_key(16B)\n"
    "}",
    ""),

    ("divider", None,
    "④ 伺服器回應 (Server Hello)", "", "Server Hello"),

    ("arrow", "server",
    "←  [Len=4B][JSON Response]",
    '{ "success": true,\n'
    '  "server_ecc_pub": "<32B hex>",\n'
    '  "pqc_ciphertext": "<1088B hex>",\n'
    '  "session_id": "<32B hex>",\n'
    '  "timestamp": <float> }',
    ""),

    ("divider", None,
    "⑤ 客戶端解封裝 & 衍生金鑰", "", "Client Processing"),

    ("self", "client",
    "PQC 解封裝 & 衍生金鑰",
    "client_pqc_decapsulate(pqc_ciphertext, pqc_sk)\n"
    "  Kyber768.decaps(pqc_sk, pqc_ciphertext)\n"
    "  → pqc_shared(32B)\n"
    "derive_final_key(server_ecc_pub, pqc_shared..)\n"
    "  → session_keys  ✓ 金鑰協商完成",
    ""),

    ("divider", None,
    "⑥ 安全訊息通訊 (AES-256-GCM)", "", "Secure Messaging"),

    ("self", "client",
    "加密訊息",
    "encrypt_aes_gcm(encryption_key, plaintext)\n"
    "  → { iv(12B), ciphertext, tag(16B) }",
    ""),

    ("arrow", "client",
    "→  [Len=4B][JSON]",
    '{ "type": "secure_msg",\n'
    '  "data": { "iv":"..","ciphertext":"..","tag":".." },\n'
    '  "timestamp": <float> }',
    ""),

    ("self", "server",
    "解密並廣播",
    "decrypt_aes_gcm(encryption_key, data)\n"
    "  → plaintext\n"
    "broadcast(plaintext, sender_id)\n"
    "  → encrypt & send to all clients",
    ""),

    ("arrow", "server",
    "←  [Len=4B][JSON]  (Broadcast)",
    '{ "type": "secure_msg",\n'
    '  "data": { "iv":"..","ciphertext":"..","tag":".." },\n'
    '  "sender": "<client_id>" }',
    ""),
]

# ── 版面常數 ────────────────────────────────────────────────────────────────
W = 1400           # 畫布寬度
MARGIN_TOP   = 120
MARGIN_X     = 60
ACTOR_W      = 180
ACTOR_H      = 50
FONT_TITLE   = 28
FONT_ACTOR   = 16
FONT_LABEL   = 13
FONT_DETAIL  = 11
LIFELINE_X_L = MARGIN_X + ACTOR_W // 2          # Client 生命線 X
LIFELINE_X_R = W - MARGIN_X - ACTOR_W // 2      # Server 生命線 X
STEP_H_BASE  = 28    # 每行基礎高度
DIVIDER_H    = 44
SELF_BOX_W   = 320
SELF_BOX_PAD = 8
ARROW_PAD    = 30   # 箭頭距生命線距離

def _text_height(text: str, font_size: int, max_chars: int = 60) -> int:
    lines = []
    for raw in text.split("\n"):
        if len(raw) > max_chars:
            lines.extend(textwrap.wrap(raw, max_chars))
        else:
            lines.append(raw)
    return max(1, len(lines)) * (font_size + 4)

def _calc_step_height(step) -> int:
    stype, frm, label, detail, _ = step
    if stype == "divider":
        return DIVIDER_H
    lh = _text_height(label,  FONT_LABEL,  65)
    dh = _text_height(detail, FONT_DETAIL, 65) if detail else 0
    base = lh + dh + STEP_H_BASE * 2
    if stype == "self":
        base += 20
    return base

def _total_height() -> int:
    h = MARGIN_TOP + ACTOR_H + 20
    for s in STEPS:
        h += _calc_step_height(s)
    h += ACTOR_H + 60
    return h

def draw_diagram():
    H = _total_height()
    img = Image.new("RGB", (W, H), BG_COLOR)
    draw = ImageDraw.Draw(img)

    f_title  = _load_font(FONT_TITLE)
    f_actor  = _load_font(FONT_ACTOR)
    f_label  = _load_font(FONT_LABEL)
    f_detail = _load_font(FONT_DETAIL)
    f_small  = _load_font(10)

    # ── 標題 ──────────────────────────────────────────────────────────────
    title = "Quantum Secure Chat — 握手通訊時序圖"
    draw.text((W // 2, 30), title, font=f_title, fill=TITLE_COLOR, anchor="mm")
    sub = "InnovativeHybridKEM  |  Kyber-768 (PQC) + X25519 (ECC) + AES-256-GCM"
    draw.text((W // 2, 65), sub, font=f_label, fill=(120, 140, 200), anchor="mm")
    draw.line([(MARGIN_X, 85), (W - MARGIN_X, 85)], fill=DIVIDER_COLOR, width=1)

    # ── Actor 方塊 ────────────────────────────────────────────────────────
    y_actor = MARGIN_TOP
    def draw_actor(cx, label, color):
        x0 = cx - ACTOR_W // 2
        draw.rectangle([x0, y_actor, x0 + ACTOR_W, y_actor + ACTOR_H],
                    fill=color, outline=color)
        draw.text((cx, y_actor + ACTOR_H // 2), label,
                font=f_actor, fill=(10, 12, 22), anchor="mm")

    draw_actor(LIFELINE_X_L, "🖥  Client", CLIENT_COLOR)
    draw_actor(LIFELINE_X_R, "🌐  Server", SERVER_COLOR)

    y_cur = y_actor + ACTOR_H

    def draw_lifeline(y_from, y_to):
        draw.line([(LIFELINE_X_L, y_from), (LIFELINE_X_L, y_to)],
                fill=(*CLIENT_COLOR[:3], 80), width=1)
        draw.line([(LIFELINE_X_R, y_from), (LIFELINE_X_R, y_to)],
                fill=(*SERVER_COLOR[:3], 80), width=1)

    # ── 逐步繪製 ─────────────────────────────────────────────────────────
    for step in STEPS:
        stype, frm, label, detail, phase = step
        sh = _calc_step_height(step)
        draw_lifeline(y_cur, y_cur + sh)

        if stype == "divider":
            # 分隔線 + 階段標籤
            mid_y = y_cur + DIVIDER_H // 2
            draw.line([(MARGIN_X, mid_y), (W - MARGIN_X, mid_y)],
                    fill=DIVIDER_COLOR, width=1)
            # 階段徽章
            badge_w = len(label) * (FONT_LABEL - 1) + 20
            bx0 = (W - badge_w) // 2
            draw.rectangle([bx0 - 4, mid_y - 14, bx0 + badge_w + 4, mid_y + 14],
                        fill=(25, 30, 55), outline=(60, 80, 140))
            draw.text((W // 2, mid_y), label,
                    font=f_label, fill=(160, 200, 255), anchor="mm")

        elif stype == "arrow":
            going_right = (frm == "client")
            x0 = LIFELINE_X_L if going_right else LIFELINE_X_R
            x1 = LIFELINE_X_R if going_right else LIFELINE_X_L
            ax0, ax1 = (x0 + ARROW_PAD, x1 - ARROW_PAD) if going_right else \
                        (x0 - ARROW_PAD, x1 + ARROW_PAD)

            # label 文字
            lh = _text_height(label, FONT_LABEL, 65)
            text_y = y_cur + 14
            draw.text((W // 2, text_y), label,
                    font=f_label, fill=ARROW_COLOR, anchor="mm")

            # 箭頭線
            arrow_y = text_y + lh + 4
            draw.line([(ax0, arrow_y), (ax1, arrow_y)],
                    fill=ARROW_COLOR, width=2)
            # 箭頭頭
            tip = ax1
            d = 8 if going_right else -8
            draw.polygon([(tip, arrow_y),
                        (tip - d, arrow_y - 5),
                        (tip - d, arrow_y + 5)],
                        fill=ARROW_COLOR)

            # detail 備注框
            if detail:
                note_y = arrow_y + 12
                dh = _text_height(detail, FONT_DETAIL, 68)
                note_x0 = MARGIN_X + ACTOR_W + 10
                note_x1 = W - MARGIN_X - ACTOR_W - 10
                draw.rectangle([note_x0, note_y,
                                note_x1, note_y + dh + SELF_BOX_PAD * 2],
                            fill=NOTE_BG, outline=NOTE_BORDER)
                dy = note_y + SELF_BOX_PAD
                for raw_line in detail.split("\n"):
                    draw.text((note_x0 + 8, dy), raw_line,
                            font=f_detail, fill=(160, 180, 220))
                    dy += FONT_DETAIL + 4

        elif stype == "self":
            # 自身處理方塊
            cx = LIFELINE_X_L if frm == "client" else LIFELINE_X_R
            color = CLIENT_COLOR if frm == "client" else SERVER_COLOR
            box_x0 = cx - SELF_BOX_W // 2
            box_x1 = cx + SELF_BOX_W // 2

            lh = _text_height(label,  FONT_LABEL,  45)
            dh = _text_height(detail, FONT_DETAIL, 45) if detail else 0
            box_h = lh + dh + SELF_BOX_PAD * 3 + 4

            draw.rectangle([box_x0, y_cur + 10, box_x1, y_cur + 10 + box_h],
                        fill=NOTE_BG, outline=color)
            # label
            draw.rectangle([box_x0, y_cur + 10, box_x1, y_cur + 10 + lh + SELF_BOX_PAD],
                        fill=(25, 30, 55))
            draw.text((cx, y_cur + 14 + lh // 2), label,
                    font=f_label, fill=color, anchor="mm")
            # detail
            if detail:
                dy = y_cur + 10 + lh + SELF_BOX_PAD * 2
                for raw_line in detail.split("\n"):
                    draw.text((box_x0 + 8, dy), raw_line,
                            font=f_detail, fill=(160, 180, 220))
                    dy += FONT_DETAIL + 4

        y_cur += sh

    # ── 底部 Actor ────────────────────────────────────────────────────────
    draw_lifeline(y_cur, y_cur + 10)
    draw_actor(LIFELINE_X_L, "🖥  Client", CLIENT_COLOR)
    draw_actor(LIFELINE_X_R, "🌐  Server", SERVER_COLOR)

    # ── 圖例 ──────────────────────────────────────────────────────────────
    leg_y = y_cur + ACTOR_H + 16
    legends = [
        (CLIENT_COLOR, "Client Actor"),
        (SERVER_COLOR, "Server Actor"),
        (ARROW_COLOR,  "訊息傳輸"),
        (SELF_COLOR,   "本地處理"),
    ]
    lx = MARGIN_X
    for color, text in legends:
        draw.rectangle([lx, leg_y, lx + 16, leg_y + 14], fill=color)
        draw.text((lx + 22, leg_y), text, font=f_small, fill=TEXT_COLOR)
        lx += 180

    img.save(OUTPUT_PNG, "PNG", dpi=(150, 150))
    print(f"[OK]  已儲存握手時序圖 → {OUTPUT_PNG}")
    return OUTPUT_PNG


if __name__ == "__main__":
    draw_diagram()
