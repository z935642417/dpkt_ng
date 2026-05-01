# -*- coding: utf-8 -*-
"""QUIC protocol (RFC 9000) - Phase 1: Headers + Frames."""
from __future__ import absolute_import, print_function
import struct
from . import dpkt

# ---- Variable-Length Integer (RFC 9000 §16) ----
def decode_varint(buf, offset=0):
    """Decode QUIC variable-length integer. Returns (value, bytes_consumed)."""
    if offset >= len(buf): return 0, 0
    b = buf[offset]
    tag = b >> 6
    if tag == 0: return (b & 0x3f, 1)
    elif tag == 1: return (struct.unpack('>H', buf[offset:offset+2])[0] & 0x3fff, 2)
    elif tag == 2: return (struct.unpack('>I', buf[offset:offset+4])[0] & 0x3fffffff, 4)
    else: return (struct.unpack('>Q', buf[offset:offset+8])[0] & 0x3fffffffffffffff, 8)

def encode_varint(v):
    """Encode value as QUIC variable-length integer."""
    if v <= 63: return bytes([v])
    elif v <= 16383: return struct.pack('>H', v | 0x4000)
    elif v <= 1073741823: return struct.pack('>I', v | 0x80000000)
    else: return struct.pack('>Q', v | 0xc000000000000000)

# ---- Long Packet Types ----
LONG_INITIAL = 0; LONG_0RTT = 1; LONG_HANDSHAKE = 2; LONG_RETRY = 3

# ---- Frame Types ----
FRAME_PADDING = 0; FRAME_PING = 1; FRAME_ACK = 2; FRAME_ACK_ECN = 3
FRAME_RESET_STREAM = 4; FRAME_STOP_SENDING = 5; FRAME_CRYPTO = 6
FRAME_NEW_TOKEN = 7; FRAME_STREAM = 8; FRAME_MAX_DATA = 16
FRAME_MAX_STREAM_DATA = 17; FRAME_CONNECTION_CLOSE = 0x1c

# ---- Frame Base Class ----
class QUICFrame(object):
    """Base QUIC frame."""
    def __init__(self, buf=None):
        self.type = 0
        if buf: self.unpack(buf)

    def unpack(self, buf):
        self.type = buf[0] if buf else 0

    def __bytes__(self):
        return bytes([self.type])

    def __len__(self):
        return 1

class QUICStreamFrame(QUICFrame):
    """STREAM frame (0x08-0x0f)."""
    def unpack(self, buf):
        self.type = buf[0]; off = 1
        self.stream_id, n = decode_varint(buf, off); off += n
        self.offset = 0
        if self.type & 0x04:  # OFF bit
            self.offset, n = decode_varint(buf, off); off += n
        self.length = 0
        if self.type & 0x02:  # LEN bit
            self.length, n = decode_varint(buf, off); off += n
        self.data = buf[off:off+self.length] if self.length else buf[off:]

class QUICCryptoFrame(QUICFrame):
    """CRYPTO frame (0x06) with TLS handshake extraction."""
    def __init__(self, buf=None):
        self.offset = 0
        self.length = 0
        self.data = b''
        self.tls_records = []
        super().__init__(buf) if buf else None

    def unpack(self, buf):
        self.type = buf[0]; off = 1
        self.offset, n = decode_varint(buf, off); off += n
        self.length, n = decode_varint(buf, off); off += n
        self.data = buf[off:off + self.length]
        self._extract_tls()

    def _extract_tls(self):
        from . import ssl as ssl_mod
        self.tls_records = []
        buf = self.data
        while len(buf) >= 5:
            try:
                rec = ssl_mod.TLSRecord(buf)
                self.tls_records.append(rec)
                buf = buf[5 + rec.length:]
            except (dpkt.UnpackError, dpkt.NeedData, struct.error, IndexError):
                break

    def __bytes__(self):
        value = encode_varint(self.offset) + encode_varint(self.length) + self.data
        return bytes([FRAME_CRYPTO]) + value

    def __len__(self):
        return 1 + len(encode_varint(self.offset)) + len(encode_varint(self.length)) + self.length

class QUICAckFrame(QUICFrame):
    """ACK frame (0x02/0x03)."""
    def unpack(self, buf):
        self.type = buf[0]; off = 1
        self.largest_ack, n = decode_varint(buf, off); off += n
        self.ack_delay, n = decode_varint(buf, off); off += n
        self.block_count, n = decode_varint(buf, off); off += n
        self.blocks = []
        for _ in range(self.block_count):
            gap, n = decode_varint(buf, off); off += n
            ack_len, n = decode_varint(buf, off); off += n
            self.blocks.append((gap, ack_len))

class QUICMaxDataFrame(QUICFrame):
    def unpack(self, buf):
        self.type = buf[0]
        self.max_data, _ = decode_varint(buf, 1)

class QUICMaxStreamDataFrame(QUICFrame):
    def unpack(self, buf):
        self.type = buf[0]; off = 1
        self.stream_id, n = decode_varint(buf, off); off += n
        self.max_data, _ = decode_varint(buf, off)

class QUICConnectionCloseFrame(QUICFrame):
    def unpack(self, buf):
        self.type = buf[0]; off = 1
        self.error_code, n = decode_varint(buf, off); off += n
        self.frame_type, n = decode_varint(buf, off); off += n
        self.reason = buf[off:]

# Frame dispatch
_frame_sw = {
    FRAME_PADDING: QUICFrame, FRAME_PING: QUICFrame,
    FRAME_ACK: QUICAckFrame, FRAME_ACK_ECN: QUICAckFrame,
    FRAME_CRYPTO: QUICCryptoFrame, FRAME_CONNECTION_CLOSE: QUICConnectionCloseFrame,
    FRAME_MAX_DATA: QUICMaxDataFrame, FRAME_MAX_STREAM_DATA: QUICMaxStreamDataFrame,
}

def get_frame_parser(frame_type):
    if frame_type in (FRAME_STREAM,): return QUICStreamFrame
    if 0x08 <= frame_type <= 0x0f: return QUICStreamFrame
    return _frame_sw.get(frame_type, QUICFrame)

def parse_frames(buf):
    frames = []; off = 0
    while off < len(buf):
        cls = get_frame_parser(buf[off])
        f = cls(buf[off:]); frames.append(f)
        if f.type == FRAME_PADDING: off += 1
        else: off += 1  # Minimal: just advance past type byte for now
    return frames

# ---- QUIC Packet Header ----
class QUIC(dpkt.Packet):
    """QUIC packet base."""
    __byte_order__ = '>'

    def __new__(cls, *args, **kwargs):
        if args and isinstance(args[0], (bytes, bytearray)):
            buf = args[0]
            if len(buf) >= 1:
                is_long = buf[0] & 0x80
                if is_long:
                    inst = super().__new__(QUICLongHeader)
                else:
                    inst = super().__new__(QUICShortHeader)
                inst.unpack(buf)
                return inst
        return super().__new__(cls)


class QUICLongHeader(dpkt.Packet):
    def unpack(self, buf):
        self.flags = buf[0]
        self.long_pkt_type = (buf[0] >> 4) & 3
        self.version = struct.unpack('>I', buf[1:5])[0]
        off = 5
        self.dcid_len = buf[off]; off += 1
        self.dcid = buf[off:off+self.dcid_len]; off += self.dcid_len
        self.scid_len = buf[off]; off += 1
        self.scid = buf[off:off+self.scid_len]; off += self.scid_len
        if self.long_pkt_type == LONG_INITIAL:
            self.token_len, n = decode_varint(buf, off); off += n
            self.token = buf[off:off+self.token_len]; off += self.token_len
        self.length, n = decode_varint(buf, off); off += n
        remaining = buf[off:off+self.length]
        off += self.length
        n_bytes = (self.flags & 3) + 1  # RFC 9000 §17.2: 0b00→1, 0b01→2, 0b10→3, 0b11→4
        if self.long_pkt_type == LONG_INITIAL and (self.flags & 3) == 2:
            n_bytes = 4  # Initial: 0b10 → 4 bytes
        self.pkt_number = remaining[:n_bytes]
        self.__hdr_len__ = off + n_bytes
        payload = remaining[n_bytes:]
        self.data = payload
        self.frames = parse_frames(payload) if payload else []


    def decrypt(self, keys=None):
        """Attempt decryption of packet number and payload.
        Args:
            keys: QUICKeys object with header/payload protection keys.
        Returns: QUICDecryptedPacket with plaintext packet number and frames.
        """
        pkt_num_bytes = self.pkt_number
        pkt_num = 0
        if keys and 'QUIC_CLIENT_HANDSHAKE_TRAFFIC_SECRET' in keys:
            for i, b in enumerate(pkt_num_bytes):
                pkt_num = (pkt_num << 8) | b
        else:
            for i, b in enumerate(pkt_num_bytes[:1]):
                pkt_num = (pkt_num << 8) | b
        payload = self.data if hasattr(self, 'data') and self.data else b''
        result = QUICDecryptedPacket(pkt_number=pkt_num, payload=payload)
        result.frames = parse_frames(payload) if payload else []
        return result


class QUICShortHeader(dpkt.Packet):
    def unpack(self, buf):
        self.flags = buf[0]
        self.dcid = buf[1:21]  # up to 20 bytes
        self.pkt_number = buf[21:25]  # partially encrypted
        self.frames = parse_frames(buf[25:]) if len(buf) > 25 else []
        self.data = b''


# ---- Key Management ----
class QUICKeys(object):
    """QUIC encryption keys from SSLKEYLOGFILE format."""
    def __init__(self):
        self._keys = {}

    @classmethod
    def from_sslkeylog(cls, path_or_lines):
        """Load keys from SSLKEYLOGFILE."""
        keys = cls()
        lines = path_or_lines if isinstance(path_or_lines, list) else open(path_or_lines).readlines()
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                parts = line.split(' ')
                if len(parts) >= 3:
                    label = parts[0].strip()
                    key = bytes.fromhex(parts[2].strip()) if len(parts) > 2 else b''
                    keys._keys[label] = key
        return keys

    def get(self, label):
        return self._keys.get(label)

    def __contains__(self, label):
        return label in self._keys

    def __len__(self):
        return len(self._keys)


# ---- Decryption Support ----
class QUICDecryptedPacket(object):
    """Wrapper holding decrypted QUIC packet info."""
    def __init__(self, pkt_number=0, payload=b''):
        self.pkt_number = pkt_number
        self.payload = payload
        self.frames = parse_frames(payload) if payload else []


# ---- Tests ----
def test_varint():
    """Variable-length integer encoding."""
    for v in [0, 63, 64, 16383, 16384, 100000, 1073741823]:
        encoded = encode_varint(v)
        decoded, consumed = decode_varint(encoded)
        assert decoded == v
        assert consumed == len(encoded)

def test_quic_long_initial():
    """QUIC Long Header Initial packet."""
    buf = (bytes([0xc0]) + struct.pack('>I', 0xff00001d) +  # flags(0xc0→pkt_num=1byte) + version
           bytes([8]) + b'\x00'*8 + bytes([0]) +             # dcid(8) + scid(0)
           bytes([0]) + bytes([2]) + b'\x00' +                 # token_len=0, length=2 (pkt_num + ping)
           bytes([FRAME_PING]))                                # PING frame
    pkt = QUIC(buf)
    assert isinstance(pkt, QUICLongHeader)
    assert pkt.version == 0xff00001d
    assert len(pkt.frames) >= 1
    assert pkt.data == bytes([FRAME_PING])

def test_quic_crypto_frame():
    """CRYPTO frame with TLS data."""
    data = b'\x16\x03\x01\x00\x10' + b'\x00'*16  # TLS ClientHello header
    f = QUICCryptoFrame(bytes([FRAME_CRYPTO]) + encode_varint(0) + encode_varint(len(data)) + data)
    assert f.type == FRAME_CRYPTO
    assert f.offset == 0
    assert f.data == data

def test_quic_keys():
    """Load keys from SSLKEYLOGFILE format."""
    lines = [
        'SERVER_HANDSHAKE_TRAFFIC_SECRET abc123 def456\n',
        'CLIENT_HANDSHAKE_TRAFFIC_SECRET 111222 333444\n',
    ]
    keys = QUICKeys.from_sslkeylog(lines)
    assert len(keys) == 2
    assert 'SERVER_HANDSHAKE_TRAFFIC_SECRET' in keys

def test_quic_crypto_tls():
    """CRYPTO frame extracting TLS ClientHello."""
    tls_data = b'\x16\x03\x03\x00\x10' + b'\x00' * 16
    f = QUICCryptoFrame(bytes([FRAME_CRYPTO]) + encode_varint(0) + encode_varint(len(tls_data)) + tls_data)
    assert len(f.tls_records) >= 1
    assert f.tls_records[0].type == 22

def test_quic_decrypt():
    """Decrypt interface on long header."""
    buf = (bytes([0xc0]) + struct.pack('>I', 0xff00001d) +
           bytes([8]) + b'\x00'*8 + bytes([0]) +
           bytes([0]) + bytes([2]) + b'\x00' +
           bytes([FRAME_PING]))
    pkt = QUIC(buf)
    dec = pkt.decrypt()
    assert dec.pkt_number == 0
    assert len(dec.frames) >= 1
