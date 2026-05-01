# -*- coding: utf-8 -*-
"""HTTP/3 frame parsing (RFC 9114). Transport-independent."""
from __future__ import absolute_import, print_function
import struct
from . import dpkt

# Frame types
HTTP3_DATA = 0x00; HTTP3_HEADERS = 0x01; HTTP3_CANCEL_PUSH = 0x03
HTTP3_SETTINGS = 0x04; HTTP3_PUSH_PROMISE = 0x05; HTTP3_GOAWAY = 0x07
HTTP3_MAX_PUSH_ID = 0x0d

# ---- Variable-Length Integer (self-contained) ----
def _decode_varint(buf, offset=0):
    b = buf[offset]; tag = b >> 6
    if tag == 0: return (b & 0x3f, 1)
    elif tag == 1: return (struct.unpack('>H', buf[offset:offset+2])[0] & 0x3fff, 2)
    elif tag == 2: return (struct.unpack('>I', buf[offset:offset+4])[0] & 0x3fffffff, 4)
    else: return (struct.unpack('>Q', buf[offset:offset+8])[0] & 0x3fffffffffffffff, 8)

# ---- Frame Base ----
class Http3Frame(object):
    def __init__(self, buf=None):
        self.type = 0; self.length = 0
        if buf: self.unpack(buf)
    def unpack(self, buf):
        self.type, n = _decode_varint(buf, 0)
        self.length, m = _decode_varint(buf, n)
    def __bytes__(self):
        return b''


class Http3DataFrame(Http3Frame):
    def __init__(self, buf=None):
        self.payload = b''; super().__init__(buf) if buf else None
    def unpack(self, buf):
        self.type, n = _decode_varint(buf, 0)
        self.length, m = _decode_varint(buf, n)
        self.payload = buf[n+m:n+m+self.length]
    def __bytes__(self):
        import struct
        hdr = b''
        if self.type <= 63: hdr += bytes([self.type])
        else: hdr += struct.pack('>H', self.type | 0x4000)
        if len(self.payload) <= 63: hdr += bytes([len(self.payload)])
        else: hdr += struct.pack('>H', len(self.payload) | 0x4000)
        return hdr + self.payload


class Http3HeadersFrame(Http3Frame):
    def __init__(self, buf=None):
        self.encoded_headers = b''; super().__init__(buf) if buf else None
    def unpack(self, buf):
        self.type, n = _decode_varint(buf, 0)
        self.length, m = _decode_varint(buf, n)
        self.encoded_headers = buf[n+m:n+m+self.length]


class Http3SettingsFrame(Http3Frame):
    def __init__(self, buf=None):
        self.settings = []; super().__init__(buf) if buf else None
    def unpack(self, buf):
        self.type, n = _decode_varint(buf, 0)
        self.length, m = _decode_varint(buf, n)
        off = n + m
        end = off + self.length
        while off + 2 <= end:
            sid, sn = _decode_varint(buf, off); off += sn
            sval, sv = _decode_varint(buf, off); off += sv
            self.settings.append((sid, sval))


class Http3GoawayFrame(Http3Frame):
    def unpack(self, buf):
        self.type, n = _decode_varint(buf, 0)
        self.length, m = _decode_varint(buf, n)
        self.last_stream_id, _ = _decode_varint(buf, n+m)


class Http3PushPromiseFrame(Http3Frame):
    def __init__(self, buf=None):
        self.push_id = 0; self.encoded_headers = b''; super().__init__(buf) if buf else None
    def unpack(self, buf):
        self.type, n = _decode_varint(buf, 0)
        self.length, m = _decode_varint(buf, n)
        self.push_id, p = _decode_varint(buf, n+m)
        self.encoded_headers = buf[n+m+p:n+m+p+self.length-p]


class Http3CancelPushFrame(Http3Frame):
    def unpack(self, buf):
        self.type, n = _decode_varint(buf, 0)
        self.length, m = _decode_varint(buf, n)
        self.push_id, _ = _decode_varint(buf, n+m)


class Http3MaxPushIdFrame(Http3Frame):
    def unpack(self, buf):
        self.type, n = _decode_varint(buf, 0)
        self.length, m = _decode_varint(buf, n)
        self.max_push_id, _ = _decode_varint(buf, n+m)


# Frame dispatch
_http3_sw = {
    HTTP3_DATA: Http3DataFrame, HTTP3_HEADERS: Http3HeadersFrame,
    HTTP3_SETTINGS: Http3SettingsFrame, HTTP3_GOAWAY: Http3GoawayFrame,
    HTTP3_PUSH_PROMISE: Http3PushPromiseFrame, HTTP3_CANCEL_PUSH: Http3CancelPushFrame,
    HTTP3_MAX_PUSH_ID: Http3MaxPushIdFrame,
}

def parse_http3_frames(buf):
    frames = []; off = 0
    while off < len(buf):
        ftype, n = _decode_varint(buf, off)
        flen, m = _decode_varint(buf, off+n)
        total = n + m + flen
        cls = _http3_sw.get(ftype, Http3Frame)
        frames.append(cls(buf[off:off+total]))
        off += total
    return frames


# ---- Tests ----
def test_http3_data():
    f = Http3DataFrame(bytes([HTTP3_DATA]) + bytes([5]) + b'HELLO')
    assert f.type == HTTP3_DATA
    assert f.payload == b'HELLO'

def test_http3_settings():
    buf = bytes([HTTP3_SETTINGS]) + bytes([5])  # type + len (5 bytes of settings)
    buf += bytes([1]) + bytes([0x40, 0x40])     # QPACK_MAX_TABLE_CAPACITY=1, value=64
    buf += bytes([8]) + bytes([0])              # SETTINGS_ENABLE_CONNECT_PROTOCOL=8, val=0
    f = Http3SettingsFrame(buf)
    assert len(f.settings) == 2
    assert f.settings[0] == (1, 64)  # SETTINGS_QPACK_MAX_TABLE_CAPACITY=1

def test_http3_headers():
    f = Http3HeadersFrame(bytes([HTTP3_HEADERS]) + bytes([4]) + b'ABCD')
    assert f.type == HTTP3_HEADERS
    assert f.encoded_headers == b'ABCD'

def test_http3_multi_frame():
    """Parse multiple frames from buffer."""
    f1 = bytes([HTTP3_DATA]) + bytes([3]) + b'GET'
    f2 = bytes([HTTP3_HEADERS]) + bytes([2]) + b'AB'
    frames = parse_http3_frames(f1 + f2)
    assert len(frames) == 2
    assert isinstance(frames[0], Http3DataFrame)
    assert isinstance(frames[1], Http3HeadersFrame)
