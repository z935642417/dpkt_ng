# -*- coding: utf-8 -*-
"""Enhanced Interior Gateway Routing Protocol."""
from __future__ import absolute_import
from __future__ import print_function

import struct

from . import dpkt

# Opcodes
EIGRP_OP_UPDATE = 1
EIGRP_OP_QUERY = 3
EIGRP_OP_REPLY = 4
EIGRP_OP_HELLO = 5
EIGRP_OP_SIAQUERY = 10
EIGRP_OP_SIAREPLY = 11

# Flags
EIGRP_FLAG_INIT = 0x01
EIGRP_FLAG_CONDITIONAL_RECEIVE = 0x02
EIGRP_FLAG_RESTART = 0x04
EIGRP_FLAG_ENDOFTABLE = 0x08

# TLV types
EIGRP_TLV_PARAM = 0x0001
EIGRP_TLV_AUTH = 0x0002
EIGRP_TLV_INTERNAL_ROUTE = 0x0102
EIGRP_TLV_EXTERNAL_ROUTE = 0x0103

# Wide Metrics sub-TLV types
EIGRP_METRIC_SCALED = 0x0601
EIGRP_METRIC_EXTENDED = 0x0602

# Address Family Identifiers
AFI_IPV4 = 1
AFI_IPV6 = 16384


class EIGRPTLV(object):
    """Base TLV: type(2B) + length(2B) + value(variable)."""
    def __init__(self, buf=None):
        self.type = 0
        self.length = 4
        self.value = b''
        if buf:
            self.unpack(buf)

    def unpack(self, buf):
        self.type, self.length = struct.unpack('>HH', buf[:4])
        self.value = buf[4:self.length]

    def __bytes__(self):
        return struct.pack('>HH', self.type, self.length) + self.value

    def __len__(self):
        return self.length


class EIGRPGenericTLV(EIGRPTLV):
    """Fallback TLV for unknown types."""
    pass


class EIGRP(dpkt.Packet):
    """EIGRP Protocol Packet."""
    __byte_order__ = '>'
    __hdr__ = (
        ('v', 'B', 2),
        ('opcode', 'B', 0),
        ('sum', 'H', 0),
        ('flags', 'I', 0),
        ('seq', 'I', 0),
        ('ack', 'I', 0),
        ('asn', 'I', 0),
    )
    _tlv_sw = {}
    _opcode_sw = {}

    def __bytes__(self):
        if not self.sum:
            self.sum = dpkt.in_cksum(dpkt.Packet.__bytes__(self))
        return dpkt.Packet.__bytes__(self)

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        cls = self._opcode_sw.get(self.opcode)
        if cls:
            self.data = cls(self.data)
            setattr(self, self.data.__class__.__name__.lower(), self.data)


def test_eigrp_header():
    """Parse EIGRP header fields."""
    buf = struct.pack('>BBHIIII', 2, EIGRP_OP_HELLO, 0, 0, 1, 0, 100)
    pkt = EIGRP(buf)
    assert pkt.v == 2
    assert pkt.opcode == EIGRP_OP_HELLO
    assert pkt.asn == 100
    assert len(bytes(pkt)) == 20
