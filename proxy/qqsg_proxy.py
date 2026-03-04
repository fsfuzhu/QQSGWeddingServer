#!/usr/bin/env python3
"""
QQSG TCP MITM Proxy v5 — Multi-Client, Multi-Server
- Receives TEA key + gameTime + player info from DLL (port 19900)
- Proxies game traffic between client(s) and real server(s)
- Session-based state: each DLL connection = independent session (supports same-IP multi-instance)
- Game server IP auto-detected from DLL KSRV message (no hardcoded server config needed)
- Decrypts S->C packets, detects opcode 2514 (monster spawn, type=7)
- Auto-sends skill packet (opcode 0x44E / 1102) on spawn detection
- Detects wedding countdown (opcode 4374), auto-bursts snatch packets (opcode 4368)
  at countdown=5ms, sustains until countdown=-1s
"""

import asyncio
import dataclasses
import struct
import logging
import time
import sys
import os
from collections import deque
from dataclasses import field
from typing import Optional, Dict, Tuple, Deque

# ─── Configuration ───────────────────────────────────────────────────────────

KEYRELAY_PORT  = 19900       # KeyRelay DLL connects here to send TEA key
PROXY_PORTS    = [                # 14条线路端口
    12501, 12502, 12503, 12504,   # 1-4线
    12505, 12506, 12507, 12508,   # 5-8线
    12509, 12511, 12514, 12515,   # 9-12线 (10线=12511, 11线=12514, 12线=12515)
    10513, 10514,                  # 13-14线
]
GAME_SERVER_IP_DEFAULT = "113.96.12.40"  # fallback if DLL hasn't sent KSRV yet

# Skill packet config
SKILL_OPCODE   = 0x044E      # 1102 decimal — 技能发包 opcode
SPAWN_OPCODE   = 0x09D2      # 2514 decimal — 特效包 opcode

# Wedding packet config
WEDDING_SNATCH_OPCODE    = 0x1110   # 4368 decimal — 抢婚包 (C→S, 1字节payload: 0x00)
WEDDING_COUNTDOWN_OPCODE = 0x1116   # 4374 decimal — 婚礼倒计时 (S→C, DWORD target_sec)
WEDDING_ALL_OPCODES = {4370, 4372, 4374, 4376, 4381, 4383, 4384, 4392, 4394}
WEDDING_AUTO_SNATCH    = True       # 自动抢婚开关
WEDDING_BURST_START_MS = 10         # 剩余10ms开始发包
WEDDING_BURST_END_MS   = -1         # 发到-1ms停止
WEDDING_BURST_PER_MS   = 5          # 每ms发5个包

# ─── Logging ─────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("proxy")

# ─── QQ TEA Cipher ──────────────────────────────────────────────────────────
# Verified against IDA: sub_A934DD (TEA block), sub_A93A46 (QQ CBC decrypt)
# - 16-round TEA with ntohl/htonl byte swap (BE block interpretation)
# - Key is 16 bytes interpreted as 4x BE uint32
# - QQ CBC: double-XOR chain, padding: 1+(pad)+2 header + 7 zero trailer
# - sub_A934DD decrypt: initial sum = 0xE3779B90, adds 0x61C88647 each round
#   which is equivalent to standard TEA with delta=0x9E3779B9

DELTA = 0x9E3779B9
MASK32 = 0xFFFFFFFF

def _ntohl(v):
    """Convert uint32 from network (BE) to host (LE) order."""
    return struct.unpack('>I', struct.pack('<I', v & MASK32))[0]

def _htonl(v):
    """Convert uint32 from host (LE) to network (BE) order."""
    return struct.unpack('<I', struct.pack('>I', v & MASK32))[0]



def _tea_block_decrypt_raw(input_8bytes: bytes, key_16bytes: bytes) -> bytes:
    """TEA block decrypt operating on raw bytes. Matches sub_A934DD exactly.
    Handles ntohl/htonl byte swapping internally."""
    raw0, raw1 = struct.unpack('<2I', input_8bytes)
    v3 = _ntohl(raw0)
    v4 = _ntohl(raw1)
    kr0, kr1, kr2, kr3 = struct.unpack('<4I', key_16bytes)
    k = [_ntohl(kr0), _ntohl(kr1), _ntohl(kr2), _ntohl(kr3)]
    mask = MASK32
    eax = 0xE3779B90
    for _ in range(16):
        t1 = (eax + v3) & mask
        t2 = (k[2] + ((v3 << 4) & mask)) & mask
        t3 = (k[3] + (v3 >> 5)) & mask
        v4 = (v4 - (t1 ^ t2 ^ t3)) & mask
        t1 = (eax + v4) & mask
        t2 = (k[0] + ((v4 << 4) & mask)) & mask
        t3 = (k[1] + (v4 >> 5)) & mask
        v3 = (v3 - (t1 ^ t2 ^ t3)) & mask
        eax = (eax + 0x61C88647) & mask
    out0 = _htonl(v3)
    out1 = _htonl(v4)
    return struct.pack('<2I', out0, out1)

def _tea_block_encrypt_raw(input_8bytes: bytes, key_16bytes: bytes) -> bytes:
    """TEA block encrypt operating on raw bytes. Inverse of _tea_block_decrypt_raw."""
    raw0, raw1 = struct.unpack('<2I', input_8bytes)
    v0 = _ntohl(raw0)
    v1 = _ntohl(raw1)
    kr0, kr1, kr2, kr3 = struct.unpack('<4I', key_16bytes)
    k = [_ntohl(kr0), _ntohl(kr1), _ntohl(kr2), _ntohl(kr3)]
    mask = MASK32
    eax = 0
    for _ in range(16):
        eax = (eax + DELTA) & mask
        t1 = (eax + v1) & mask
        t2 = (k[0] + ((v1 << 4) & mask)) & mask
        t3 = (k[1] + (v1 >> 5)) & mask
        v0 = (v0 + (t1 ^ t2 ^ t3)) & mask
        t1 = (eax + v0) & mask
        t2 = (k[2] + ((v0 << 4) & mask)) & mask
        t3 = (k[3] + (v0 >> 5)) & mask
        v1 = (v1 + (t1 ^ t2 ^ t3)) & mask
    out0 = _htonl(v0)
    out1 = _htonl(v1)
    return struct.pack('<2I', out0, out1)

def qq_tea_decrypt(cipher: bytes, key_bytes: bytes) -> Optional[bytes]:
    """QQ TEA double-XOR CBC decrypt. Matches sub_A93A46 exactly.
    Returns decrypted content (without padding), or None."""
    clen = len(cipher)
    if clen % 8 != 0 or clen < 16:
        return None

    blocks = [cipher[i:i+8] for i in range(0, clen, 8)]

    # Block 0: decrypt directly
    dec_buf = bytearray(_tea_block_decrypt_raw(blocks[0], key_bytes))
    dec_blocks = [bytes(dec_buf)]  # block 0 output = dec_buf XOR zeros = dec_buf

    # Blocks 1..N: double-XOR CBC
    for i in range(1, len(blocks)):
        # XOR previous decrypt buffer with current cipher block
        temp = bytes(dec_buf[j] ^ blocks[i][j] for j in range(8))
        # TEA decrypt
        dec_buf = bytearray(_tea_block_decrypt_raw(temp, key_bytes))
        # Output = dec_buf XOR previous cipher block
        output = bytes(dec_buf[j] ^ blocks[i-1][j] for j in range(8))
        dec_blocks.append(output)

    full_dec = b''.join(dec_blocks)

    # QQ padding: [pad_byte] [pad random bytes] [2 zero bytes] [CONTENT] [7 zero bytes]
    pad = full_dec[0] & 0x07
    header_len = 1 + pad + 2
    trailer_len = 7

    if header_len + trailer_len > len(full_dec):
        return None

    # Validate trailing 7 zeros
    if full_dec[-7:] != b'\x00' * 7:
        return None

    return bytes(full_dec[header_len:-trailer_len])

def qq_tea_encrypt(content: bytes, key_bytes: bytes) -> bytes:
    """QQ TEA double-XOR CBC encrypt. Adds QQ padding, returns ciphertext.
    Inverse of qq_tea_decrypt. Verified via roundtrip test."""
    content_len = len(content)
    # total = 1 + pad + 2 + content_len + 7, must be multiple of 8
    fill_count = (10 + content_len) % 8
    pad = (8 - fill_count) % 8

    padded = bytearray()
    padded.append(pad & 0x07)      # pad count in low 3 bits
    padded.extend(os.urandom(pad) if pad > 0 else b'')  # random pad → unique ciphertext each call
    padded.extend(b'\x00\x00')     # 2 zero bytes
    padded.extend(content)
    padded.extend(b'\x00' * 7)     # 7 trailing zeros

    assert len(padded) % 8 == 0

    blocks = [bytes(padded[i:i+8]) for i in range(0, len(padded), 8)]
    cipher = []

    # Block 0: encrypt directly (decrypt inverse: dec_buf = TEA_dec(cipher[0]))
    cipher_0 = _tea_block_encrypt_raw(blocks[0], key_bytes)
    cipher.append(cipher_0)

    # Blocks 1..N: double-XOR CBC (exact inverse of qq_tea_decrypt)
    # Decrypt does: temp = dec_buf ^ cipher[i], dec_buf = TEA_dec(temp), output[i] = dec_buf ^ cipher[i-1]
    # So encrypt inverse: dec_buf_i = output[i] ^ cipher[i-1], temp_i = TEA_enc(dec_buf_i), cipher[i] = temp_i ^ prev_dec_buf
    prev_dec_buf = bytearray(blocks[0])  # for block 0, dec_buf = plaintext block 0
    for i in range(1, len(blocks)):
        dec_buf_i = bytes(blocks[i][j] ^ cipher[i-1][j] for j in range(8))
        temp_i = _tea_block_encrypt_raw(dec_buf_i, key_bytes)
        cipher_i = bytes(temp_i[j] ^ prev_dec_buf[j] for j in range(8))
        cipher.append(cipher_i)
        prev_dec_buf = bytearray(dec_buf_i)

    return b''.join(cipher)

# ─── Exemption list (these opcodes are NOT encrypted) ────────────────────────

EXEMPT_OPCODES = {1, 1001, 1022, 1023, 1059, 1612, 4462, 4501, 4511, 4702, 4712, 4716, 4718, 4719, 4742, 4743, 4787}

# ─── Wire Protocol ───────────────────────────────────────────────────────────
# Header: 16 bytes (all fields BIG-ENDIAN)
#   [0:2]   magic        = 0x0010 (BE uint16)
#   [2:4]   payload_size (BE uint16) — size of payload after header
#   [4:6]   opcode       (BE uint16)
#   [6:14]  zeros / reserved
#   [14:16] tail field (unknown)

HEADER_SIZE = 16

def parse_header(data: bytes) -> tuple:
    """Parse packet header. Returns (magic, payload_size, opcode).
    Wire format is BIG-ENDIAN for header fields."""
    if len(data) < HEADER_SIZE:
        return None, None, None
    magic = struct.unpack_from(">H", data, 0)[0]
    payload_size = struct.unpack_from(">H", data, 2)[0]
    opcode = struct.unpack_from(">H", data, 4)[0]
    return magic, payload_size, opcode

# ─── Per-Client State (session-based, supports same-IP multi-instance) ───────

_next_session_id = 0

@dataclasses.dataclass
class ClientState:
    session_id: str
    ip: str                                # source IP (for logging & route matching)
    tea_key: Optional[bytes] = None
    game_time: int = 0
    game_time_local: float = 0.0
    player_name: str = ""                  # decoded from GBK — unique per game server
    player_x: int = 0
    player_y: int = 0
    player_handle: int = 0
    game_server_ip: str = ""               # auto-detected from DLL KSRV message
    client_to_server: Optional[asyncio.StreamWriter] = None
    last_c2s_header: Optional[bytes] = None
    c2s_skill_count: int = 0
    s2c_opcode_count: int = 0
    s2c_opcode_set: set = field(default_factory=set)
    keyrelay_connected: bool = False
    game_connected: bool = False
    # Wedding state
    wedding_target_sec: int = 0
    wedding_burst_task: Optional[asyncio.Task] = None
    wedding_burst_count: int = 0

    @property
    def tag(self) -> str:
        """Log prefix: [玩家名] or [S1@IP]"""
        if self.player_name:
            return f"[{self.player_name}]"
        return f"[{self.session_id}@{self.ip}]"

# ─── Session Registry ────────────────────────────────────────────────────────
# Each KeyRelay TCP connection = one independent session.
# Multiple sessions can share the same source IP (same-machine multi-instance).

sessions: Dict[str, ClientState] = {}       # key = session_id

# Pending game connection routes: KSRV registers here, game TCP connect pops.
# Key = (source_ip, game_port), Value = FIFO queue of ClientState.
# Ordering guarantee: DLL sends KSRV right before connect(), so KSRV always
# arrives before the corresponding game TCP connection.
pending_routes: Dict[Tuple[str, int], Deque[ClientState]] = {}

def create_session(ip: str) -> ClientState:
    """Create a new independent session for a KeyRelay connection."""
    global _next_session_id
    _next_session_id += 1
    sid = f"S{_next_session_id}"
    cs = ClientState(session_id=sid, ip=ip)
    sessions[sid] = cs
    log.info(f"[{sid}] New session from {ip} (total: {len(sessions)})")
    return cs

def remove_session(cs: ClientState):
    """Remove session if both keyrelay and game are disconnected."""
    if not cs.keyrelay_connected and not cs.game_connected:
        if cs.session_id in sessions:
            del sessions[cs.session_id]
        log.info(f"{cs.tag} Session removed (total: {len(sessions)})")

def find_session_for_game(source_ip: str, game_port: int) -> Optional[ClientState]:
    """Find the matching session for an incoming game TCP connection.

    Uses the pending_routes queue (populated by KSRV messages).
    Fallback: find any session from this IP that isn't in a game yet.
    """
    # Primary: KSRV-based route matching (precise, handles same-IP multi-instance)
    key = (source_ip, game_port)
    if key in pending_routes and pending_routes[key]:
        cs = pending_routes[key].popleft()
        if not pending_routes[key]:
            del pending_routes[key]
        log.info(f"{cs.tag} Matched game connection via KSRV route ({source_ip}:{game_port})")
        return cs

    # Fallback: find any session from this IP that has game_server_ip and no active game
    for cs in sessions.values():
        if cs.ip == source_ip and cs.game_server_ip and not cs.game_connected:
            log.info(f"{cs.tag} Matched game connection via IP fallback ({source_ip}:{game_port})")
            return cs

    return None

def get_estimated_game_time_for(cs: ClientState) -> int:
    """Estimate current game time for a specific client."""
    if cs.game_time <= 0:
        return 0
    elapsed_ms = int((time.monotonic() - cs.game_time_local) * 1000)
    return cs.game_time + elapsed_ms

# ─── KeyRelay Server (Persistent Connection Protocol) ────────────────────────
# Protocol:
#   "KREL" + 16-byte key = 20 bytes  (TEA key update)
#   "KNAM" + 1-byte len + N-byte name(GBK) = 5+N bytes (player name)
#   "KINF" + 2B X + 2B Y + 4B handle + 4B pad = 16 bytes (player info)
#   "KTIM" + 8-byte int64 LE = 12 bytes (gameTime sync)
#   "KSRV" + 4B IP(network order) + 2B port(LE) = 10 bytes (game server addr)
# Messages arrive on a persistent TCP stream, parse by 4-byte magic prefix.
# Each TCP connection = one independent session (supports same-IP multi-instance).

async def handle_keyrelay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Handle KeyRelay DLL persistent connection. Each connection = independent session."""
    peername = writer.get_extra_info("peername")
    client_ip = peername[0] if peername else "unknown"
    cs = create_session(client_ip)
    cs.keyrelay_connected = True
    log.info(f"{cs.tag} KeyRelay connected from {peername}")
    buf = bytearray()
    try:
        while True:
            data = await asyncio.wait_for(reader.read(4096), timeout=30.0)
            if not data:
                break
            buf.extend(data)

            # Parse messages from buffer
            while len(buf) >= 4:
                magic = bytes(buf[:4])

                if magic == b"KREL":
                    # Need 4 + 16 = 20 bytes
                    if len(buf) < 20:
                        break  # wait for more data
                    key_bytes = bytes(buf[4:20])
                    del buf[:20]
                    # Validate
                    if key_bytes == b'\x00' * 16 or key_bytes == b'\xFF' * 16:
                        log.warning(f"{cs.tag} KeyRelay: invalid key (zeros or FF)")
                        continue
                    if key_bytes != cs.tea_key:
                        cs.tea_key = key_bytes
                        log.info(f"{cs.tag} TEA key set: {key_bytes.hex()} (ASCII: {key_bytes.decode('ascii', errors='replace')})")

                elif magic == b"KNAM":
                    # Need at least 5 bytes: 4 magic + 1 len
                    if len(buf) < 5:
                        break
                    name_len = buf[4]
                    if name_len == 0 or name_len > 32:
                        log.warning(f"{cs.tag} KeyRelay: invalid KNAM len={name_len}")
                        del buf[:5]
                        continue
                    total = 5 + name_len
                    if len(buf) < total:
                        break  # wait for more data
                    name_bytes = bytes(buf[5:total])
                    del buf[:total]
                    try:
                        player_name = name_bytes.decode('gbk', errors='replace')
                    except Exception:
                        player_name = name_bytes.hex()
                    if player_name != cs.player_name:
                        old_name = cs.player_name
                        cs.player_name = player_name
                        log.info(f"{cs.tag} Player name: '{player_name}' (was '{old_name}')")

                elif magic == b"KINF":
                    # Fixed 16 bytes: 4 magic + 2 X + 2 Y + 4 handle + 4 pad
                    if len(buf) < 16:
                        break
                    px = struct.unpack_from("<H", buf, 4)[0]
                    py = struct.unpack_from("<H", buf, 6)[0]
                    handle = struct.unpack_from("<I", buf, 8)[0]
                    del buf[:16]
                    cs.player_x = px
                    cs.player_y = py
                    cs.player_handle = handle

                elif magic == b"KTIM":
                    # Need 4 + 8 = 12 bytes
                    if len(buf) < 12:
                        break  # wait for more data
                    game_time = struct.unpack_from("<q", buf, 4)[0]
                    del buf[:12]
                    old_time = cs.game_time
                    cs.game_time = game_time
                    cs.game_time_local = time.monotonic()
                    # Log first time sync and every 30 seconds
                    if old_time == 0:
                        log.info(f"{cs.tag} First gameTime sync: {game_time} ms ({game_time//1000}s)")
                    elif game_time // 30000 != old_time // 30000:
                        log.info(f"{cs.tag} gameTime: {game_time} ms ({game_time//1000}s)")

                elif magic == b"KSRV":
                    # Need 4 + 4 (IP) + 2 (port) = 10 bytes
                    if len(buf) < 10:
                        break  # wait for more data
                    ip_bytes = bytes(buf[4:8])
                    port = struct.unpack_from("<H", buf, 8)[0]
                    del buf[:10]
                    game_ip = f"{ip_bytes[0]}.{ip_bytes[1]}.{ip_bytes[2]}.{ip_bytes[3]}"
                    if game_ip != cs.game_server_ip:
                        old_ip = cs.game_server_ip or "(none)"
                        cs.game_server_ip = game_ip
                        log.info(f"{cs.tag} Game server updated: {game_ip}:{port} (was {old_ip})")

                    # Register pending route for game connection matching
                    # DLL sends KSRV right before connect(), so this entry will be
                    # consumed by the game TCP connection arriving shortly after.
                    route_key = (client_ip, port)
                    if route_key not in pending_routes:
                        pending_routes[route_key] = deque()
                    pending_routes[route_key].append(cs)
                    log.debug(f"{cs.tag} Pending route registered: {route_key}")

                else:
                    # Unknown magic — discard 1 byte and try to resync
                    log.warning(f"{cs.tag} KeyRelay: unknown magic {magic!r}, discarding byte")
                    del buf[:1]

    except asyncio.TimeoutError:
        log.warning(f"{cs.tag} KeyRelay: timeout (no data for 30s)")
    except (ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        log.error(f"{cs.tag} KeyRelay error: {e}")
    finally:
        try:
            writer.close()
        except Exception:
            pass
        cs.keyrelay_connected = False
        log.info(f"{cs.tag} KeyRelay disconnected")
        remove_session(cs)

# ─── Packet Injection ────────────────────────────────────────────────────────

def build_skill_packet_from_plaintext(cs: ClientState, plaintext_hex: str) -> bytes:
    """
    Build a skill packet from raw plaintext hex (34 bytes).
    Re-encrypts with the client's current TEA key.
    """
    plaintext = bytes.fromhex(plaintext_hex)
    if len(plaintext) != 34:
        log.warning(f"{cs.tag} Plaintext must be 34 bytes, got {len(plaintext)}")
        return b''

    if not cs.tea_key:
        log.warning(f"{cs.tag} Cannot encrypt skill packet: no TEA key")
        return b''

    encrypted = qq_tea_encrypt(plaintext, cs.tea_key)

    # Build 16-byte header (BIG-ENDIAN for wire format)
    header = bytearray(16)
    struct.pack_into(">H", header, 0, 0x0010)           # magic
    struct.pack_into(">H", header, 2, len(encrypted))    # payload_size
    struct.pack_into(">H", header, 4, SKILL_OPCODE)      # opcode

    log.info(f"{cs.tag} Built skill packet from plaintext: {plaintext_hex[:36]}... "
             f"payload={len(encrypted)}B encrypted")

    return bytes(header) + encrypted


def build_skill_packet(cs: ClientState, skill_id: int = 23, direction: int = 0) -> bytes:
    """
    Build a skill packet (opcode 0x44E = 1102) for a specific client.

    Payload structure (34 bytes) — verified from captured real packets:
      [0:2]   player X       (BE u16)
      [2:4]   player Y       (BE u16)
      [4:6]   skill ID       (BE u16) — e.g. 5=十荡十决, 23=挑畔四方
      [6:8]   constant 1     (BE u16)
      [8:12]  player handle   (BE u32)
      [12:14] constant 1     (BE u16)
      [14:18] player handle   (BE u32, repeated)
      [18:26] game time       (8 bytes, format TBD)
      [26:34] zeros           (8 bytes)
    """
    game_time = get_estimated_game_time_for(cs)
    if game_time <= 0:
        log.warning(f"{cs.tag} Cannot build skill packet: no gameTime available")
        return b''

    if cs.player_x == 0 and cs.player_y == 0:
        log.warning(f"{cs.tag} Cannot build skill packet: no player position")
        return b''

    if cs.player_handle == 0:
        log.warning(f"{cs.tag} Cannot build skill packet: no player handle")
        return b''

    # Build 34-byte payload (plaintext)
    payload = bytearray(34)
    struct.pack_into(">H", payload, 0, cs.player_x)
    struct.pack_into(">H", payload, 2, cs.player_y)
    struct.pack_into(">H", payload, 4, skill_id)
    struct.pack_into(">H", payload, 6, 1)
    struct.pack_into(">I", payload, 8, cs.player_handle)
    struct.pack_into(">H", payload, 12, 1)
    struct.pack_into(">I", payload, 14, cs.player_handle)
    # [18:26] game time — use estimated value as 2x LE u32
    # Based on captured data: [18:22] increases ~1 per second, [22:26] varies
    # For now use the raw game_time split
    time_sec = game_time // 1000
    time_ms  = game_time % 1000
    struct.pack_into("<I", payload, 18, time_sec & 0xFFFFFFFF)
    struct.pack_into("<I", payload, 22, time_ms & 0xFFFFFFFF)
    # [26:34] zeros
    payload = bytes(payload)

    # Encrypt
    if not cs.tea_key:
        log.warning(f"{cs.tag} Cannot encrypt skill packet: no TEA key")
        return b''

    encrypted = qq_tea_encrypt(payload, cs.tea_key)

    # Build 16-byte header (BIG-ENDIAN for wire format)
    header = bytearray(16)
    struct.pack_into(">H", header, 0, 0x0010)           # magic
    struct.pack_into(">H", header, 2, len(encrypted))    # payload_size
    struct.pack_into(">H", header, 4, SKILL_OPCODE)      # opcode

    log.info(f"{cs.tag} Built skill packet: X={cs.player_x} Y={cs.player_y} skill={skill_id} "
             f"handle=0x{cs.player_handle:08X} gameTime={game_time}, "
             f"payload={len(encrypted)}B encrypted, plaintext={payload.hex()}")

    return bytes(header) + encrypted

async def inject_packet(packet: bytes, cs: ClientState):
    """Inject a packet into the C->S stream for a specific client."""
    if not packet:
        return
    if cs.client_to_server and not cs.client_to_server.is_closing():
        cs.client_to_server.write(packet)
        await cs.client_to_server.drain()
        log.info(f"{cs.tag} INJECTED skill packet: {len(packet)} bytes -> game server")
    else:
        log.warning(f"{cs.tag} Cannot inject: no server connection")

# ─── Wedding Packet Building & Burst ────────────────────────────────────────

def build_wedding_packet(cs: ClientState) -> bytes:
    """Build a wedding snatch packet (opcode 4368, 1-byte payload: 0x00).
    Each call produces unique ciphertext due to random TEA padding."""
    if not cs.tea_key:
        return b''

    plaintext = b'\x00'  # 1 byte payload
    encrypted = qq_tea_encrypt(plaintext, cs.tea_key)

    # 16-byte header (BIG-ENDIAN, wire format)
    header = bytearray(16)
    struct.pack_into(">H", header, 0, 0x0010)                    # magic
    struct.pack_into(">H", header, 2, len(encrypted))             # payload_size
    struct.pack_into(">H", header, 4, WEDDING_SNATCH_OPCODE)      # opcode 4368

    return bytes(header) + encrypted


async def wedding_countdown_handler(cs: ClientState, target_sec: int):
    """Background coroutine: wait for countdown, then burst wedding snatch packets.

    Timeline:
      1. Sleep until ~200ms before trigger point
      2. Tight-loop poll remaining time every 1ms
      3. When remaining <= BURST_START_MS: send BURST_PER_MS packets, sleep 1ms
      4. Stop when remaining <= BURST_END_MS
    """
    target_ms = target_sec * 1000

    # Validate game time availability
    game_time = get_estimated_game_time_for(cs)
    if game_time <= 0:
        log.warning(f"{cs.tag} WEDDING: no game time available, cannot start countdown")
        return

    remaining_ms = target_ms - game_time
    log.info(f"{cs.tag} WEDDING countdown started: target_sec={target_sec} "
             f"remaining={remaining_ms}ms ({remaining_ms/1000:.1f}s)")

    # Ignore already-expired countdowns (> 2ms past deadline)
    if remaining_ms < -2:
        log.info(f"{cs.tag} WEDDING: ignoring expired countdown (remaining={remaining_ms}ms, threshold=-2ms)")
        return

    # Phase 1: Coarse sleep — wake up 200ms before burst trigger
    sleep_ms = remaining_ms - WEDDING_BURST_START_MS - 200
    if sleep_ms > 0:
        log.info(f"{cs.tag} WEDDING: sleeping {sleep_ms/1000:.1f}s before tight-loop")
        await asyncio.sleep(sleep_ms / 1000.0)

    # Phase 2: Tight-loop polling + burst (rate-limited: N packets per ms)
    log.info(f"{cs.tag} WEDDING: entering tight-loop phase")
    burst_count = 0
    burst_started = False
    burst_start_time = None

    while True:
        game_time = get_estimated_game_time_for(cs)
        remaining_ms = target_ms - game_time

        # Stop condition
        if remaining_ms <= WEDDING_BURST_END_MS:
            break

        # Check server connection
        if not cs.client_to_server or cs.client_to_server.is_closing():
            log.warning(f"{cs.tag} WEDDING: server connection lost, aborting")
            break

        if remaining_ms <= WEDDING_BURST_START_MS:
            if not burst_started:
                burst_started = True
                burst_start_time = time.monotonic()
                log.info(f"{cs.tag} >>> WEDDING BURST START! remaining={remaining_ms}ms")

            # Send BURST_PER_MS packets this tick
            for _ in range(WEDDING_BURST_PER_MS):
                pkt = build_wedding_packet(cs)
                if pkt:
                    cs.client_to_server.write(pkt)
                    burst_count += 1

            # Flush + sleep 1ms (rate limit)
            try:
                await cs.client_to_server.drain()
            except Exception as e:
                log.error(f"{cs.tag} WEDDING: drain error: {e}")
                break
            await asyncio.sleep(0.001)
        else:
            # Not yet — poll every 1ms
            await asyncio.sleep(0.001)

    # Final drain
    if cs.client_to_server and not cs.client_to_server.is_closing():
        try:
            await cs.client_to_server.drain()
        except Exception:
            pass

    elapsed = (time.monotonic() - burst_start_time) * 1000 if burst_start_time else 0
    cs.wedding_burst_count = burst_count
    cs.wedding_burst_task = None
    log.info(f"{cs.tag} WEDDING BURST COMPLETE: {burst_count} packets in {elapsed:.0f}ms "
             f"(rate: {WEDDING_BURST_PER_MS}/ms, window: +{WEDDING_BURST_START_MS}ms → {WEDDING_BURST_END_MS}ms)")

# ─── Packet Analysis ────────────────────────────────────────────────────────

def analyze_c2s_packet(raw: bytes, cs: ClientState):
    """Analyze C->S packet for a specific client."""
    magic, payload_size, opcode = parse_header(raw)
    if magic is None or magic != 0x0010:
        return
    # Log first C->S packet header
    if cs.last_c2s_header is None:
        header_hex = raw[:HEADER_SIZE].hex()
        log.info(f"{cs.tag} C→S first packet header: {header_hex} opcode={opcode}")
    cs.last_c2s_header = raw[:HEADER_SIZE]

    # Capture and decrypt skill packets (opcode 0x44E = 1102)
    if opcode == SKILL_OPCODE and cs.tea_key:
        cs.c2s_skill_count += 1
        payload = raw[HEADER_SIZE:HEADER_SIZE + payload_size]
        log.info(f"{cs.tag} C→S SKILL #{cs.c2s_skill_count}: opcode=0x{opcode:04X} cipher={payload.hex()} ({len(payload)}B)")
        content = qq_tea_decrypt(payload, cs.tea_key)
        if content:
            log.info(f"{cs.tag} C→S SKILL #{cs.c2s_skill_count}: decrypted={content.hex()} ({len(content)}B)")
            if len(content) >= 34:
                time_ms   = struct.unpack_from("<I", content, 18)[0]
                time_sec  = struct.unpack_from("<I", content, 22)[0]
                skill_tp  = struct.unpack_from("<I", content, 26)[0]
                direction = struct.unpack_from("<I", content, 30)[0]
                log.info(f"{cs.tag} C→S SKILL #{cs.c2s_skill_count}: timeSec={time_sec} timeMs={time_ms} skillType={skill_tp} dir={direction}")
                log.info(f"{cs.tag} C→S SKILL #{cs.c2s_skill_count}: prefix[0:18]={content[:18].hex()}")
        else:
            log.warning(f"{cs.tag} C→S SKILL #{cs.c2s_skill_count}: decrypt FAILED")

def analyze_server_packet(raw: bytes, cs: ClientState):
    """Analyze a server-to-client packet for a specific client. Detect spawn events (type=7)."""
    magic, payload_size, opcode = parse_header(raw)
    if magic is None:
        return

    cs.s2c_opcode_count += 1
    cs.s2c_opcode_set.add(opcode)
    # Log first 5 S→C packets with full header breakdown
    if cs.s2c_opcode_count <= 5:
        h = raw[:HEADER_SIZE]
        fields = [struct.unpack_from(">H", h, i)[0] for i in range(0, 16, 2)]
        log.info(f"{cs.tag} S→C pkt#{cs.s2c_opcode_count} header fields (BE u16): {['0x%04X'%f for f in fields]} hex={h.hex()}")
    # Log stats every 200 packets
    if cs.s2c_opcode_count % 200 == 1 and cs.s2c_opcode_count > 5:
        log.info(f"{cs.tag} S→C stats: {cs.s2c_opcode_count} packets, unique opcodes: {sorted(cs.s2c_opcode_set)}")

    if opcode == SPAWN_OPCODE:
        payload = raw[HEADER_SIZE:HEADER_SIZE + payload_size]

        if not cs.tea_key or len(payload) < 16:
            log.info(f"{cs.tag} SPAWN detected but no key or payload too short ({len(payload)}B)")
            return

        # QQ TEA decrypt — yields 10 bytes of content for opcode 2514
        # Content is in BE byte order: type(u16), X(u16), Y(u16), handle(u32)
        content = qq_tea_decrypt(payload, cs.tea_key)
        if content is None:
            log.warning(f"{cs.tag} SPAWN: QQ TEA decrypt failed! cipher={payload.hex()}")
            return

        if len(content) < 10:
            log.warning(f"{cs.tag} SPAWN: decrypted content too short ({len(content)}B): {content.hex()}")
            return

        # Parse fields — QQ TEA output is BIG-ENDIAN
        sp_type = struct.unpack_from(">H", content, 0)[0]
        sp_x    = struct.unpack_from(">H", content, 2)[0]
        sp_y    = struct.unpack_from(">H", content, 4)[0]
        sp_handle = struct.unpack_from(">I", content, 6)[0]

        log.info(f"{cs.tag} SPAWN type={sp_type} X={sp_x} Y={sp_y} handle=0x{sp_handle:08X}")

        # type 7 = SPAWN (怪物出生特效) — 检查坐标proximity后注入
        if sp_type == 7:
            dx = abs(sp_x - cs.player_x)
            dy = abs(sp_y - cs.player_y)
            if dx <= 300 and dy <= 1:
                log.info(f"{cs.tag} >>> SPAWN MATCH ({sp_x},{sp_y}) player=({cs.player_x},{cs.player_y}) dx={dx} dy={dy} — injecting!")
                pkt = build_skill_packet(cs, skill_id=23)
                if pkt:
                    asyncio.get_event_loop().create_task(inject_packet(pkt, cs))
            else:
                log.debug(f"{cs.tag} SPAWN skip ({sp_x},{sp_y}) player=({cs.player_x},{cs.player_y}) dx={dx} dy={dy}")

    # ─── Wedding opcode detection ─────────────────────────────────────────
    if opcode in WEDDING_ALL_OPCODES:
        payload = raw[HEADER_SIZE:HEADER_SIZE + payload_size]
        content = None
        if cs.tea_key and opcode not in EXEMPT_OPCODES and len(payload) >= 8:
            content = qq_tea_decrypt(payload, cs.tea_key)

        log.info(f"{cs.tag} WEDDING opcode={opcode} payload={len(payload)}B "
                 f"decrypted={content.hex() if content else 'N/A'} ({len(content)}B)" if content else
                 f"{cs.tag} WEDDING opcode={opcode} payload={len(payload)}B (no decrypt)")

        # Opcode 4374: countdown — extract target_sec and start burst handler
        if opcode == WEDDING_COUNTDOWN_OPCODE and content and len(content) >= 4:
            # Log both BE and LE interpretations for verification
            target_sec_be = struct.unpack_from(">I", content, 0)[0]
            target_sec_le = struct.unpack_from("<I", content, 0)[0]
            log.info(f"{cs.tag} WEDDING COUNTDOWN raw={content[:4].hex()} "
                     f"BE={target_sec_be} LE={target_sec_le}")

            # Use BE (consistent with opcode 2514 convention)
            target_sec = target_sec_be
            cs.wedding_target_sec = target_sec

            # Log estimated remaining time
            game_time = get_estimated_game_time_for(cs)
            if game_time > 0:
                remaining_ms = target_sec * 1000 - game_time
                log.info(f"{cs.tag} WEDDING COUNTDOWN: target={target_sec}s "
                         f"gameTime={game_time}ms remaining={remaining_ms}ms "
                         f"({remaining_ms/1000:.1f}s)")

            # Cancel existing burst task if running
            if cs.wedding_burst_task and not cs.wedding_burst_task.done():
                cs.wedding_burst_task.cancel()
                log.info(f"{cs.tag} WEDDING: cancelled previous countdown handler")

            # Spawn countdown handler
            if WEDDING_AUTO_SNATCH:
                cs.wedding_burst_task = asyncio.create_task(
                    wedding_countdown_handler(cs, target_sec))
                log.info(f"{cs.tag} WEDDING: countdown handler spawned (auto-snatch ON)")
            else:
                log.info(f"{cs.tag} WEDDING: auto-snatch disabled, not starting handler")

# ─── TCP Proxy Core ──────────────────────────────────────────────────────────

async def pipe(label: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
               analyzer=None):
    """Forward data from reader to writer, optionally analyzing packets."""
    try:
        buf = bytearray()
        while True:
            data = await reader.read(8192)
            if not data:
                break

            # Forward immediately (low latency is critical)
            writer.write(data)
            await writer.drain()

            # Analyze in background (non-blocking to forwarding)
            if analyzer:
                buf.extend(data)
                # Try to parse complete packets from buffer
                while len(buf) >= HEADER_SIZE:
                    magic, payload_size, opcode = parse_header(bytes(buf[:HEADER_SIZE]))
                    if magic != 0x0010:
                        # Log first bad magic for debugging
                        log.warning(f"Pipe {label}: bad magic 0x{magic:04X} at buf[0:4]={buf[:4].hex()}, clearing {len(buf)}B")
                        buf.clear()
                        break
                    total_size = HEADER_SIZE + payload_size
                    if len(buf) < total_size:
                        break  # Need more data
                    packet = bytes(buf[:total_size])
                    del buf[:total_size]
                    try:
                        analyzer(packet)
                    except Exception as e:
                        log.error(f"Analyzer error: {e}")
    except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
        pass
    except Exception as e:
        log.error(f"Pipe {label} error: {e}")
    finally:
        try:
            writer.close()
        except Exception:
            pass

async def handle_game_client(client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
    """Handle a game client connection — proxy to real game server.
    Matches to a KeyRelay session via pending_routes (KSRV-based)."""
    client_addr = client_writer.get_extra_info("peername")
    client_ip = client_addr[0] if client_addr else "unknown"
    # 获取客户端连接的本地端口 → 用同端口连游戏服务器
    local_addr = client_writer.get_extra_info("sockname")
    game_port = local_addr[1] if local_addr else PROXY_PORTS[0]

    # Find matching session from KSRV pending route
    cs = find_session_for_game(client_ip, game_port)
    if not cs:
        log.warning(f"[{client_ip}:{game_port}] No matching session found, "
                     f"creating anonymous session (default server)")
        cs = create_session(client_ip)

    cs.game_connected = True
    log.info(f"{cs.tag} Game client connected from {client_addr} on port {game_port}")

    if not cs.tea_key:
        log.warning(f"{cs.tag} No TEA key yet — KeyRelay may not have sent KREL")

    # Use DLL-reported game server IP, or fallback to default
    target_ip = cs.game_server_ip if cs.game_server_ip else GAME_SERVER_IP_DEFAULT
    if not cs.game_server_ip:
        log.warning(f"{cs.tag} No KSRV received yet, using default: {GAME_SERVER_IP_DEFAULT}")

    # Connect to real game server (same port)
    try:
        server_reader, server_writer = await asyncio.open_connection(target_ip, game_port)
        log.info(f"{cs.tag} Connected to game server {target_ip}:{game_port}")
    except Exception as e:
        log.error(f"{cs.tag} Cannot connect to game server {target_ip}:{game_port}: {e}")
        client_writer.close()
        cs.game_connected = False
        remove_session(cs)
        return

    # Store server writer for packet injection (per-client)
    cs.client_to_server = server_writer

    # Create per-client analyzer closures
    c2s_analyzer = lambda raw: analyze_c2s_packet(raw, cs)
    s2c_analyzer = lambda raw: analyze_server_packet(raw, cs)

    # Bidirectional pipe with analysis on both directions
    c2s = asyncio.create_task(pipe(f"{cs.tag} C→S", client_reader, server_writer, analyzer=c2s_analyzer))
    s2c = asyncio.create_task(pipe(f"{cs.tag} S→C", server_reader, client_writer, analyzer=s2c_analyzer))

    # Wait for either direction to close
    done, pending = await asyncio.wait([c2s, s2c], return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()

    cs.client_to_server = None
    cs.game_connected = False
    log.info(f"{cs.tag} Game client disconnected")
    remove_session(cs)

# ─── Injection Trigger (file-based) ──────────────────────────────────────────

INJECT_FILE = "/tmp/qqsg_inject"

async def injection_watcher():
    """Poll for /tmp/qqsg_inject file and trigger skill injection.

    File format (one line):
      hex:<34-byte-plaintext-hex>     — replay exact plaintext
      skill:<skill_id>                — build packet with skill ID using live data
    """
    while True:
        await asyncio.sleep(0.5)
        try:
            if not os.path.exists(INJECT_FILE):
                continue
            with open(INJECT_FILE, "r") as f:
                cmd = f.read().strip()
            os.remove(INJECT_FILE)
            if not cmd:
                continue

            log.info(f"Injection trigger: {cmd}")

            # Find first connected client with game connection
            target_cs = None
            for cs in sessions.values():
                if cs.client_to_server and not cs.client_to_server.is_closing() and cs.tea_key:
                    target_cs = cs
                    break

            if not target_cs:
                log.warning("Injection: no connected client with game session")
                continue

            if cmd == "wedding":
                # Send one wedding snatch packet
                pkt = build_wedding_packet(target_cs)
                if pkt:
                    target_cs.client_to_server.write(pkt)
                    await target_cs.client_to_server.drain()
                    log.info(f"{target_cs.tag} Injection: wedding snatch packet sent ({len(pkt)}B)")
                else:
                    log.warning(f"{target_cs.tag} Injection: wedding packet build failed (no key?)")
                continue

            pkt = b''
            if cmd.startswith("hex:"):
                # Replay exact plaintext
                pkt = build_skill_packet_from_plaintext(target_cs, cmd[4:])
            elif cmd.startswith("skill:"):
                # Build with skill ID
                skill_id = int(cmd[6:])
                pkt = build_skill_packet(target_cs, skill_id=skill_id)
            else:
                log.warning(f"Injection: unknown command format: {cmd}")
                continue

            if pkt:
                await inject_packet(pkt, target_cs)

        except Exception as e:
            log.error(f"Injection watcher error: {e}")

# ─── Main ────────────────────────────────────────────────────────────────────

async def main():
    log.info("=" * 60)
    log.info("QQSG MITM Proxy v4 — auto skill on SPAWN + wedding snatch")
    log.info(f"  KeyRelay port:  {KEYRELAY_PORT}")
    log.info(f"  Proxy ports:    {PROXY_PORTS}")
    log.info(f"  Game server:    (auto-detect from DLL, default={GAME_SERVER_IP_DEFAULT})")
    log.info(f"  Skill opcode:   0x{SKILL_OPCODE:04X} ({SKILL_OPCODE})")
    log.info(f"  Spawn opcode:   0x{SPAWN_OPCODE:04X} ({SPAWN_OPCODE})")
    log.info(f"  Wedding snatch: 0x{WEDDING_SNATCH_OPCODE:04X} ({WEDDING_SNATCH_OPCODE})")
    log.info(f"  Wedding countdown: 0x{WEDDING_COUNTDOWN_OPCODE:04X} ({WEDDING_COUNTDOWN_OPCODE})")
    log.info(f"  Wedding auto:   {WEDDING_AUTO_SNATCH} (burst +{WEDDING_BURST_START_MS}ms → {WEDDING_BURST_END_MS}ms)")
    log.info("=" * 60)

    # Start KeyRelay server
    kr_server = await asyncio.start_server(handle_keyrelay, "0.0.0.0", KEYRELAY_PORT)
    log.info(f"KeyRelay server listening on 0.0.0.0:{KEYRELAY_PORT}")

    # Start Game Proxy servers on multiple ports
    gp_servers = []
    for port in PROXY_PORTS:
        srv = await asyncio.start_server(handle_game_client, "0.0.0.0", port)
        gp_servers.append(srv)
        log.info(f"Game proxy listening on 0.0.0.0:{port}")

    log.info("Waiting for KeyRelay DLL connections (multi-client ready)...")

    # Start injection watcher
    asyncio.create_task(injection_watcher())
    log.info(f"Injection watcher active (trigger: {INJECT_FILE})")

    # Run forever
    serve_tasks = [kr_server.serve_forever()]
    for srv in gp_servers:
        serve_tasks.append(srv.serve_forever())
    await asyncio.gather(*serve_tasks)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Proxy stopped.")
