# -*- coding: utf-8 -*-
"""QPACK header compression (RFC 9204)."""
from __future__ import absolute_import, print_function
import struct

# Instruction prefixes
QPACK_SECTION_ACK = 0x80       # decoder stream
QPACK_STREAM_CANCEL = 0x40     # decoder stream
QPACK_INSERT_NAME_REF = 0x80   # encoder stream
QPACK_INSERT_NO_REF = 0x40     # encoder stream
QPACK_DUPLICATE = 0x00         # encoder stream
QPACK_DYNAMIC_CAPACITY = 0x20  # encoder stream
QPACK_INDEXED = 0x80           # request stream
QPACK_LITERAL_NAME_REF = 0x40  # request stream
QPACK_LITERAL_LITERAL = 0x20   # request stream
QPACK_POST_BASE = 0x10         # request stream


def _decode_int(buf, prefix_bits):
    """Decode QPACK integer with prefix."""
    mask = (1 << prefix_bits) - 1
    value = buf[0] & mask
    if value < mask:
        return value, 1
    # Multi-byte integer
    value = mask
    m = 0
    off = 1
    while off < len(buf):
        b = buf[off]; off += 1
        value += (b & 0x7f) << m
        m += 7
        if not (b & 0x80):
            break
    return value, off


class QPACKInstruction(object):
    """Base QPACK instruction."""
    def __init__(self, buf=None):
        self.prefix = 0
        if buf: self.unpack(buf)
    def unpack(self, buf):
        self.prefix = buf[0] & 0xc0
    def __repr__(self):
        return '%s()' % self.__class__.__name__


class QPACKIndexedField(QPACKInstruction):
    """Indexed Header Field (0x80). Static or dynamic table reference."""
    def unpack(self, buf):
        self.prefix = 0x80
        self.index, self._consumed = _decode_int(buf, 6)

class QPACKLiteralNameRef(QPACKInstruction):
    """Literal Header Field With Name Reference (0x40/0x00)."""
    def unpack(self, buf):
        self.prefix = 0x40
        self.static = bool(buf[0] & 0x10)
        self.name_index, n = _decode_int(buf, 4)
        self.value_len, m = _decode_int(buf[n:], 7)
        self.value = buf[n+m:n+m+self.value_len]

class QPACKLiteralLiteral(QPACKInstruction):
    """Literal Header Field With Literal Name (0x20/0x00)."""
    def unpack(self, buf):
        self.prefix = 0x20
        self.name_len, n = _decode_int(buf, 3)
        self.name = buf[n:n+self.name_len]
        off = n + self.name_len
        self.value_len, m = _decode_int(buf[off:], 7)
        self.value = buf[off+m:off+m+self.value_len]

class QPACKPostBase(QPACKInstruction):
    """Post-Base Indexed Header Field (0x10)."""
    def unpack(self, buf):
        self.prefix = 0x10
        self.index, self._consumed = _decode_int(buf, 4)

class QPACKEncoderInsertRef(QPACKInstruction):
    """Encoder: Insert With Name Reference."""
    def unpack(self, buf):
        self.prefix = 0x80
        self.static = bool(buf[0] & 0x40)
        self.name_index, n = _decode_int(buf, 6)
        self.value_len, m = _decode_int(buf[n:], 7)
        self.value = buf[n+m:n+m+self.value_len]

class QPACKEncoderInsertNoRef(QPACKInstruction):
    """Encoder: Insert Without Name Reference."""
    def unpack(self, buf):
        self.prefix = 0x40
        self.name_len, n = _decode_int(buf, 5)
        self.name = buf[n:n+self.name_len]
        off = n + self.name_len
        self.value_len, m = _decode_int(buf[off:], 7)
        self.value = buf[off+m:off+m+self.value_len]

class QPACKDuplicate(QPACKInstruction):
    """Encoder: Duplicate."""
    def unpack(self, buf):
        self.prefix = 0x00
        self.index, self._consumed = _decode_int(buf, 5)

class QPACKDynamicCapacity(QPACKInstruction):
    """Encoder: Set Dynamic Table Capacity."""
    def unpack(self, buf):
        self.prefix = 0x20
        self.capacity, self._consumed = _decode_int(buf, 5)

class QPACKSectionAck(QPACKInstruction):
    """Decoder: Section Acknowledgment."""
    def unpack(self, buf):
        self.prefix = 0x80
        self.stream_id, self._consumed = _decode_int(buf, 7)

class QPACKStreamCancel(QPACKInstruction):
    """Decoder: Stream Cancellation."""
    def unpack(self, buf):
        self.prefix = 0x40
        self.stream_id, self._consumed = _decode_int(buf, 6)


def parse_qpack_encoder(buf):
    """Parse QPACK encoder stream instructions."""
    insts = []; off = 0
    while off < len(buf):
        prefix = buf[off] & 0xe0
        if prefix == 0x20: cls = QPACKDynamicCapacity
        elif prefix == 0x00: cls = QPACKDuplicate
        elif buf[off] & 0x80: cls = QPACKEncoderInsertRef
        elif buf[off] & 0x40: cls = QPACKEncoderInsertNoRef
        else: break
        insts.append(cls(buf[off:]))
        off += 1  # minimum advance
    return insts

def parse_qpack_request(buf):
    """Parse QPACK request stream header block."""
    insts = []; off = 0
    while off < len(buf):
        b = buf[off]
        if b & 0x80: cls = QPACKIndexedField
        elif b & 0x40: cls = QPACKLiteralNameRef
        elif b & 0x20: cls = QPACKLiteralLiteral
        elif b & 0x10: cls = QPACKPostBase
        else: break
        insts.append(cls(buf[off:]))
        off += 1
    return insts


# ---- Tests ----
def test_qpack_indexed():
    """Indexed Header Field: :authority."""
    inst = QPACKIndexedField(bytes([0x80 | 1]))  # index=1 = :authority
    assert isinstance(inst, QPACKIndexedField)
    assert inst.index == 1

def test_qpack_literal():
    """Literal Header Field With Literal Name."""
    buf = bytes([0x20 | 7]) + bytes([0x00]) + b'customk' + bytes([5]) + b'value'
    inst = QPACKLiteralLiteral(buf)
    assert inst.name == b'customk'
    assert inst.value == b'value'

def test_qpack_encoder_insert():
    """Encoder: Insert With Name Reference."""
    buf = bytes([0x80 | 3]) + bytes([5]) + b'value'
    inst = QPACKEncoderInsertRef(buf)
    assert inst.name_index == 3
    assert inst.value == b'value'

def test_qpack_request_multi():
    """Parse multiple header fields from request stream."""
    f1 = bytes([0x80 | 1])  # Indexed :authority
    f2 = bytes([0x40 | 7]) + bytes([3]) + b'val'
    insts = parse_qpack_request(f1 + f2)
    assert len(insts) >= 2
    assert isinstance(insts[0], QPACKIndexedField)
